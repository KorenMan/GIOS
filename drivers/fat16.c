#include "fat16.h"
#include "ata-driver.h"
#include "vga-driver.h"
#include "../lib/memory.h"
#include "../lib/string.h"

// Global filesystem information
static u8_t temp_sector[SECTOR_SIZE];
static fat16_info_t fat16_info;

// Static global to track current directory
static u16_t current_dir_cluster = 0; // 0 means root directory
static char current_path[256] = "/";

static u16_t _create_fat_date();
static u16_t _create_fat_time();
static void _filename_to_fat83(const char *filename, u8_t *name, u8_t *ext);
static bool _filename_matches(const char *filename, const dir_entry_t *entry);
static u16_t _find_free_cluster();
static void _update_fat_entry(u16_t cluster, u16_t value);
static u16_t _get_next_cluster(u16_t cluster);
static u32_t _cluster_to_sector(u16_t cluster);
static bool _find_file(const char *filename, dir_entry_t *entry, u32_t *dir_sector, u32_t *dir_offset);
static bool _find_free_dir_entry(u32_t *dir_sector, u32_t *dir_offset); 
static bool _parse_path(const char *path, char *components[], int *num_components);
static bool _find_dir_entry(u16_t dir_cluster, const char *name, dir_entry_t *entry, u32_t *dir_sector, u32_t *dir_offset);
static bool _find_dir_by_path(const char *path, u16_t *dir_cluster);
static bool _find_free_dir_entry_in_cluster(u16_t dir_cluster, u32_t *dir_sector, u32_t *dir_offset);
static bool _find_free_dir_entry_in_root(u32_t *dir_sector, u32_t *dir_offset);

/* =============================== Public Functions =============================== */

bool fat16_init() {
    // Set default values for the boot record
    fat16_info.boot_record.bytes_per_sector = 512;      // Standard sector size
    fat16_info.boot_record.sectors_per_cluster = 1;     // Default cluster size
    fat16_info.boot_record.reserved_sectors = 1;        // Boot sector only
    fat16_info.boot_record.num_fats = 2;                // Two FATs for redundancy
    fat16_info.boot_record.root_dir_entries = 512;      // Standard for FAT16
    fat16_info.boot_record.fat_size_sectors = 64;       // Typical value for ~16MB volume
    fat16_info.boot_record.jump_code[0] = 0xeb;         // Valid signature
    
    // Calculate filesystem parameters based on default values
    fat16_info.fat_start_sector = fat16_info.boot_record.reserved_sectors;
    fat16_info.root_dir_start_sector = fat16_info.fat_start_sector +
                              (fat16_info.boot_record.num_fats * fat16_info.boot_record.fat_size_sectors);
   
    u32_t root_dir_sectors = ((fat16_info.boot_record.root_dir_entries * DIR_ENTRY_SIZE) +
                            (fat16_info.boot_record.bytes_per_sector - 1)) /
                            fat16_info.boot_record.bytes_per_sector;
   
    fat16_info.data_start_sector = fat16_info.root_dir_start_sector + root_dir_sectors;
    fat16_info.cluster_size_bytes = fat16_info.boot_record.sectors_per_cluster * SECTOR_SIZE;
   
    return true;
}

// Format the disk with a FAT16 filesystem
bool fat16_format() {
    // Initialize the boot record
    mem_set(&fat16_info.boot_record, 0, sizeof(fat_boot_record_t));
    
    // Set up basic boot record parameters
    fat16_info.boot_record.jump_code[0] = 0xeb;         // Jump instruction
    fat16_info.boot_record.jump_code[1] = 0x3c;
    fat16_info.boot_record.jump_code[2] = 0x90;
    
    mem_cpy(fat16_info.boot_record.oem_name, "FATOS ", 8);
    
    fat16_info.boot_record.bytes_per_sector = SECTOR_SIZE;
    fat16_info.boot_record.sectors_per_cluster = 1;     // Default cluster size
    fat16_info.boot_record.reserved_sectors = 1;        // Boot record only
    fat16_info.boot_record.num_fats = 2;                // Two FATs for redundancy
    fat16_info.boot_record.root_dir_entries = 512;      // 512 directory entries
    
    // Compute reasonable values for a small disk
    u32_t disk_sectors = 16384;  // 8MB disk size
    
    // Fill in the sector counts
    if (disk_sectors < 0x10000) {
        fat16_info.boot_record.total_sectors_16 = disk_sectors;
    } else {
        fat16_info.boot_record.total_sectors_32 = disk_sectors;
    }
    
    fat16_info.boot_record.media_descriptor = 0xf8;     // Fixed disk
    
    // Calculate FAT size
    u32_t root_dir_sectors = ((fat16_info.boot_record.root_dir_entries * DIR_ENTRY_SIZE) + 
                            (SECTOR_SIZE - 1)) / SECTOR_SIZE;
    
    u32_t data_sectors = disk_sectors - fat16_info.boot_record.reserved_sectors - root_dir_sectors;
    u32_t cluster_count = data_sectors / fat16_info.boot_record.sectors_per_cluster;
    
    // Each FAT entry is 2 bytes for FAT16
    u32_t fat_size = (cluster_count * 2 + SECTOR_SIZE - 1) / SECTOR_SIZE;
    fat16_info.boot_record.fat_size_sectors = fat_size;
    
    // Extended boot record
    fat16_info.boot_record.drive_number = 0x80;         // Hard disk
    fat16_info.boot_record.boot_signature = 0x29;       // Extended boot signature
    fat16_info.boot_record.volume_id = 0x12345678;      // Volume ID
    
    mem_cpy(fat16_info.boot_record.volume_label, "VOLUME   ", 11);
    mem_cpy(fat16_info.boot_record.fat16_type, "FAT16   ", 8);
    
    // Calculate important sector positions
    fat16_info.fat_start_sector = fat16_info.boot_record.reserved_sectors;
    fat16_info.root_dir_start_sector = fat16_info.fat_start_sector + 
                              (fat16_info.boot_record.num_fats * fat_size);
    fat16_info.data_start_sector = fat16_info.root_dir_start_sector + root_dir_sectors;
    fat16_info.cluster_size_bytes = fat16_info.boot_record.sectors_per_cluster * SECTOR_SIZE;
    
    // Write boot sector
    if (ata_write_sectors(0, 1, &fat16_info.boot_record) != 1) {
        return false;
    }
    
    // Initialize the FATs
    mem_set(temp_sector, 0, SECTOR_SIZE);
    u16_t *fat = (u16_t *)temp_sector;
    
    // First two FAT entries are reserved
    fat[0] = 0xfff8;  // Media descriptor
    fat[1] = 0xffff;  // End of chain marker
    
    // Write first sector of each FAT
    if (ata_write_sectors(fat16_info.fat_start_sector, 1, temp_sector) != 1) {
        return false;
    }
    
    if (ata_write_sectors(fat16_info.fat_start_sector + fat_size, 1, temp_sector) != 1) {
        return false;
    }
    
    // Clear the rest of the FATs
    mem_set(temp_sector, 0, SECTOR_SIZE);
    
    for (u32_t i = 1; i < fat_size; i++) {
        if (ata_write_sectors(fat16_info.fat_start_sector + i, 1, temp_sector) != 1) {
            return false;
        }
        
        if (ata_write_sectors(fat16_info.fat_start_sector + fat_size + i, 1, temp_sector) != 1) {
            return false;
        }
    }
    
    // Clear root directory
    for (u32_t i = 0; i < root_dir_sectors; i++) {
        if (ata_write_sectors(fat16_info.root_dir_start_sector + i, 1, temp_sector) != 1) {
            return false;
        }
    }
    
    return true;
}

// Open a file
file_t fat16_open(const char *filename) {
    file_t file;
    mem_set(&file, 0, sizeof(file_t));
   
    // Try to find the file
    if (!_find_file(filename, &file.entry, &file.dir_sector, &file.dir_offset)) {
        return file; // File not found
    }
   
    file.current_cluster = file.entry.first_cluster_low;
    file.position = 0;
    file.is_open = true;
   
    return file;
}

// Create a new file
file_t fat16_create(const char *filename) {
    // Parse the path and filename
    char path[256];
    char name[13];

    file_t file;
    mem_set(&file, 0, sizeof(file_t));
    
    // Find the last slash to separate path and filename
    const char *last_slash = NULL;
    {
        const char *temp = filename;
        while(*temp) {
            if (*temp == '/') {
                last_slash = temp;
            }
            temp++;
        }
    }

    if (last_slash) {
        // Extract path and name
        u32_t path_len = last_slash - filename;
        mem_cpy(path, filename, path_len);
        path[path_len] = '\0';
        
        mem_cpy(name, last_slash + 1, str_len(last_slash + 1));
        name[str_len(last_slash + 1)] = '\0';
    } else {
        // No path specified, use current directory
        mem_cpy(path, ".", 2);
        mem_cpy(name, filename, str_len(filename));
        name[str_len(filename) + 1] = '\0';
    }

    // Find the directory
    u16_t dir_cluster;
    if (!_find_dir_by_path(path, &dir_cluster)) {
        return file; // Directory not found
    }
    
    // Now find a free entry in this directory
    u32_t dir_sector, dir_offset;
    if (dir_cluster == 0) { // If parent is root
        // Call the function that ONLY searches root
        if (!_find_free_dir_entry_in_root(&dir_sector, &dir_offset)) {
             return file; // No space in root directory
         }
    } else { // If parent is subdir
        // Call the function that searches a specific cluster chain
        if (!_find_free_dir_entry_in_cluster(dir_cluster, &dir_sector, &dir_offset)) {
             return file; // No space in subdirectory (or extension failed)
        }
    }
    
    // Find a free cluster for the file
    u16_t cluster = _find_free_cluster();
    if (cluster == 0) {
        return file;
    }
    
    // Create directory entry
    dir_entry_t new_entry;
    mem_set(&new_entry, 0, sizeof(dir_entry_t));

    // Set up filename
    _filename_to_fat83(name, new_entry.filename, new_entry.extension);
    
    // Set attributes and timestamps
    new_entry.attributes = ATTR_ARCHIVE;
    new_entry.creation_date = _create_fat_date();
    new_entry.creation_time = _create_fat_time();
    new_entry.last_access_date = new_entry.creation_date;
    new_entry.last_modification_date = new_entry.creation_date;
    new_entry.last_modification_time = new_entry.creation_time;
    new_entry.first_cluster_low = cluster;
    new_entry.file_size = 0;
    
    // Write the directory entry
    u8_t buffer[SECTOR_SIZE];
    ata_read_sectors(dir_sector, 1, buffer);
    mem_cpy(&buffer[dir_offset], &new_entry, sizeof(dir_entry_t));
    ata_write_sectors(dir_sector, 1, buffer);
    
    // Set up the file handle
    file.entry = new_entry;
    file.dir_sector = dir_sector;
    file.dir_offset = dir_offset;
    file.position = 0;
    file.current_cluster = 0;
    file.is_open = true;

    return file;
}

// Close a file
void fat16_close(file_t *file) {
    // Check if file is valid and open
    if (!file || !file->is_open) {
        return;
    }
   
    // Update directory entry with any changes
    ata_read_sectors(file->dir_sector, 1, temp_sector);
    mem_cpy(temp_sector + file->dir_offset, &file->entry, sizeof(dir_entry_t));
    ata_write_sectors(file->dir_sector, 1, temp_sector);
   
    // Mark file as closed
    file->is_open = false;
    
    // Reset file handle fields
    file->position = 0;
    file->current_cluster = 0;
}

// Read from a file
u32_t fat16_read(file_t *file, void *buffer, u32_t size, int position) {
    // Check parameters.
    if (!file->is_open || !buffer || size == 0) {
        return 0;  // Invalid parameters
    }
    if (position >= 0) {
        file->position = position;
    }
    // Do not read past the end of the file.
    if (file->position >= file->entry.file_size) {
        return 0;
    }
    if (file->position + size > file->entry.file_size) {
        size = file->entry.file_size - file->position;
    }

    // If no cluster has been allocated (empty file), nothing to read.
    if (file->entry.first_cluster_low == 0) {
        return 0;
    }
    
    u32_t bytes_read = 0;
    u8_t *dest = (u8_t *)buffer;
    u16_t cluster;
    u32_t pos_in_file = 0;
    u32_t cluster_start_pos = 0;

    // Always start from the first cluster and track position accurately
    cluster = file->entry.first_cluster_low;
    pos_in_file = 0;
    
    // If we're not starting from position 0, find the correct cluster
    if (file->position > 0) {
        // Calculate how many complete clusters to skip
        u32_t clusters_to_skip = file->position / fat16_info.cluster_size_bytes;
        
        // Skip complete clusters
        for (u32_t i = 0; i < clusters_to_skip && cluster < FAT16_EOC; i++) {
            cluster = _get_next_cluster(cluster);
            if (cluster >= FAT16_EOC) {
                return 0;  // Unexpected end of chain
            }
            pos_in_file += fat16_info.cluster_size_bytes;
        }
        
        // Now pos_in_file points to the start of the cluster containing our position
        cluster_start_pos = pos_in_file;
    }
    
    // Store the current cluster
    file->current_cluster = cluster;
    
    // Calculate the offset into the current cluster.
    u32_t cluster_offset = file->position - cluster_start_pos;
    
    // Read data until we've reached the requested size or hit EOF.
    while (bytes_read < size) {
        // Calculate the starting sector for the current cluster.
        u32_t first_cluster_sector = _cluster_to_sector(cluster);
        u32_t bytes_available = fat16_info.cluster_size_bytes - cluster_offset;
        u32_t bytes_to_read = (size - bytes_read > bytes_available) ? 
                              bytes_available : (size - bytes_read);

        // Now, read sector by sector inside the current cluster.
        u32_t sectors_per_cluster = fat16_info.cluster_size_bytes / SECTOR_SIZE;
        u32_t sector_index = cluster_offset / SECTOR_SIZE;
        u32_t offset_in_sector = cluster_offset % SECTOR_SIZE;
        u32_t remaining_in_cluster = bytes_to_read;

        for (u32_t i = sector_index; (i < sectors_per_cluster) && (remaining_in_cluster > 0); i++) {
            // in case read sector fail
            mem_set(temp_sector, 0, SECTOR_SIZE);
            
            // Read the current sector into our local buffer.
            ata_read_sectors(first_cluster_sector + i, 1, temp_sector);
            // Determine how many bytes we can read from this sector.
            u32_t available_in_sector = SECTOR_SIZE - offset_in_sector;
            u32_t copy_bytes = (remaining_in_cluster > available_in_sector) ? available_in_sector : remaining_in_cluster;
            
            // Copy the data to the destination buffer.
            mem_cpy(dest, temp_sector + offset_in_sector, copy_bytes);
            dest += copy_bytes;
            bytes_read += copy_bytes;
            remaining_in_cluster -= copy_bytes;
            
            // For subsequent sectors, always start at offset 0.
            offset_in_sector = 0;
        }
        
        // After reading this cluster, update file position.
        file->position += bytes_to_read;
        
        // If we haven't read all requested bytes, try the next cluster.
        if (bytes_read < size) {
            u16_t next_cluster = _get_next_cluster(cluster);
            if (next_cluster >= FAT16_EOC) {
                break;  // End-of-chain reached.
            }
            cluster = next_cluster;
            file->current_cluster = cluster;
            // Reset offset for the new cluster.
            cluster_offset = 0;
            // Update the position in file for accurate tracking
            cluster_start_pos += fat16_info.cluster_size_bytes;
        }
    }
    
    return bytes_read;
}

// Write to a file
u32_t fat16_write(file_t *file, const void *buffer, u32_t size, int position) {
    if (!file->is_open) {
        return 0;  // File not open
    }

    if (position >= 0) {
        file->position = position;
    }
    
    // If position is beyond file size, we need to fill the gap with zeros
    if (file->position > file->entry.file_size) {
        // Calculate how many bytes we need to fill
        u32_t bytes_to_fill = file->position - file->entry.file_size;
        
        // Save current position
        u32_t original_position = file->position;
        
        // Set position to end of file
        file->position = file->entry.file_size;
        
        // Create a zero-filled buffer
        u8_t zero_buffer[SECTOR_SIZE];
        mem_set(zero_buffer, 0, SECTOR_SIZE);
        
        // Fill with zeros in sector-sized chunks
        while (bytes_to_fill > 0) {
            u32_t chunk_size = (bytes_to_fill > SECTOR_SIZE) ? SECTOR_SIZE : bytes_to_fill;
            u32_t written = fat16_write(file, zero_buffer, chunk_size, -1);
            
            if (written == 0) break; // Error occurred
            bytes_to_fill -= written;
        }
        
        // Restore original position
        file->position = original_position;
    }
    
    u32_t bytes_written = 0;
    const u8_t *src = (const u8_t *)buffer;
    
    // Allocate first cluster if needed
    if (file->entry.first_cluster_low == 0 && size > 0) {
        u16_t cluster = _find_free_cluster();
        if (cluster == 0) return 0;  // No free clusters
        
        file->entry.first_cluster_low = cluster;
        file->current_cluster = cluster;
    }
    
    // Find the right cluster for the current file position
    u16_t cluster = file->entry.first_cluster_low;
    u32_t pos_in_file = 0;
    
    while (pos_in_file + fat16_info.cluster_size_bytes <= file->position && cluster > 0) {
        u16_t next_cluster = _get_next_cluster(cluster);
        
        // If end of chain is reached but we need more space, allocate a new cluster.
        if (next_cluster >= FAT16_EOC) {
            u16_t new_cluster = _find_free_cluster();
            if (new_cluster == 0) return 0;  // No free clusters available

            // Link the new cluster into the chain
            _update_fat_entry(cluster, new_cluster);
            cluster = new_cluster;
        } else {
            cluster = next_cluster;
        }
        
        pos_in_file += fat16_info.cluster_size_bytes;
    }
    
    // If we couldn't find a suitable cluster (might happen with large seeks), return error
    if (cluster == 0) return 0;
    
    // Position within the current cluster where writing will begin
    u32_t cluster_offset = file->position - pos_in_file;
    
    // Write the data
    while (bytes_written < size) {
        u32_t bytes_left_in_cluster = fat16_info.cluster_size_bytes - cluster_offset;
        u32_t bytes_to_write = size - bytes_written;
        if (bytes_to_write > bytes_left_in_cluster) {
            bytes_to_write = bytes_left_in_cluster;
        }
        
        u32_t sector = _cluster_to_sector(cluster);
        u32_t sector_offset = cluster_offset % SECTOR_SIZE;
        u32_t sector_index = cluster_offset / SECTOR_SIZE;

        while (bytes_to_write > 0) {
            // For partial sector writes, read the current sector first
            if (sector_offset > 0 || bytes_to_write < SECTOR_SIZE) {
                ata_read_sectors(sector + sector_index, 1, temp_sector);
            } else {
                // For full sector writes, we can just fill the buffer without reading
                mem_set(temp_sector, 0, SECTOR_SIZE); // Ensure clean buffer
            }
            
            u32_t bytes_to_sector = SECTOR_SIZE - sector_offset;
            if (bytes_to_sector > bytes_to_write) {
                bytes_to_sector = bytes_to_write;
            }
            
            // Copy data into the temporary buffer
            mem_cpy(temp_sector + sector_offset, src, bytes_to_sector);
            // Write the modified sector back to disk
            ata_write_sectors(sector + sector_index, 1, temp_sector);
            
            src += bytes_to_sector;
            bytes_written += bytes_to_sector;
            bytes_to_write -= bytes_to_sector;
            
            // Move to the next sector
            sector_index++;
            sector_offset = 0;
        }
        
        // If data remains, move to a new cluster
        if (bytes_written < size) {
            u16_t next_cluster = _get_next_cluster(cluster);
            if (next_cluster >= FAT16_EOC) {
                u16_t new_cluster = _find_free_cluster();
                if (new_cluster == 0) break;  // No free clusters available

                _update_fat_entry(cluster, new_cluster);
                cluster = new_cluster;
            } else {
                cluster = next_cluster;
            }
            cluster_offset = 0;
        }
    }
    
    // Update the file's metadata
    file->position += bytes_written;
    if (file->position > file->entry.file_size) {
        file->entry.file_size = file->position;
    }
    
    file->current_cluster = cluster;
    
    // Update the directory entry on disk with the new file size/cluster info
    ata_read_sectors(file->dir_sector, 1, temp_sector);
    mem_cpy(temp_sector + file->dir_offset, &file->entry, sizeof(dir_entry_t));
    ata_write_sectors(file->dir_sector, 1, temp_sector);
    
    return bytes_written;
}

bool fat16_delete(const char *filename) {
    dir_entry_t entry;
    u32_t dir_sector, dir_offset;
   
    // Find the file using the new _find_file function
    if (!_find_file(filename, &entry, &dir_sector, &dir_offset)) {
        return false; // File not found
    }
   
    // Mark directory entry as deleted
    ata_read_sectors(dir_sector, 1, temp_sector);
    temp_sector[dir_offset] = 0xe5; // Mark as deleted
    ata_write_sectors(dir_sector, 1, temp_sector);
   
    // Free clusters and zero them out for security
    u16_t cluster = entry.first_cluster_low;
    while ((cluster >= 2) && (cluster < FAT16_EOC)) {
        u16_t next_cluster = _get_next_cluster(cluster);
        // Mark cluster as free in FAT
        _update_fat_entry(cluster, FAT_ENTRY_FREE);
       
        cluster = next_cluster;
    }
   
    return true;
}

// Rename a file
bool fat16_rename(const char *old_name, const char *new_name) {
    dir_entry_t entry;
    u32_t dir_sector, dir_offset;
    
    // Check if the new name already exists
    if (_find_file(new_name, NULL, NULL, NULL)) {
        return false;  // New name already exists
    }
    
    // Find the old file
    if (!_find_file(old_name, &entry, &dir_sector, &dir_offset)) {
        return false;  // Old file not found
    }
    
    // Convert new name to FAT 8.3 format
    u8_t new_name_fat[8];
    u8_t new_ext_fat[3];
    _filename_to_fat83(new_name, new_name_fat, new_ext_fat);
    
    // Update entry with new name
    ata_read_sectors(dir_sector, 1, temp_sector);
    dir_entry_t *dir_entry = (dir_entry_t *)(temp_sector + dir_offset);
    
    // Copy new name and extension
    mem_cpy(dir_entry->filename, new_name_fat, 8);
    mem_cpy(dir_entry->extension, new_ext_fat, 3);
    
    // Update last modification time
    dir_entry->last_modification_time = _create_fat_time();
    dir_entry->last_modification_date = _create_fat_date();
    
    // Write back the updated entry
    ata_write_sectors(dir_sector, 1, temp_sector);
    
    return true;
}

// List all files and directories in the root directory
void fat16_list_files() {
    u32_t root_sectors = ((fat16_info.boot_record.root_dir_entries * DIR_ENTRY_SIZE) + 
                        (fat16_info.boot_record.bytes_per_sector - 1)) / 
                        fat16_info.boot_record.bytes_per_sector;
    
    u32_t file_count = 0;
    u32_t dir_count = 0;
    u32_t total_bytes = 0;
    char filename_buffer[13]; // 8 + '.' + 3 + null terminator
    char size_str[16];
    
    vga_print("Name           Size      Attributes     Date      Time\n");
    vga_print("------------------------------------------------------------\n");
    
    // Determine which directory we're listing based on current_dir_cluster
    u32_t start_sector;
    u32_t sector_count;
    u16_t directory_cluster = current_dir_cluster;
    
    if (directory_cluster == 0) {
        // Root directory
        start_sector = fat16_info.root_dir_start_sector;
        sector_count = root_sectors;
    } else {
        // Subdirectory
        start_sector = _cluster_to_sector(directory_cluster);
        sector_count = fat16_info.boot_record.sectors_per_cluster;
    }
    
    u32_t sector_index = 0;
    u32_t next_sector = start_sector;
    u16_t current_cluster = directory_cluster;
    
    // Loop through all sectors in the current directory only
    while (sector_index < sector_count) {
        if (ata_read_sectors(next_sector, 1, temp_sector) < 0) {
            vga_print("Error reading directory sector\n");
            return;
        }
        
        dir_entry_t *entries = (dir_entry_t *)temp_sector;
        for (u32_t j = 0; j < ENTRIES_PER_SECTOR; j++) {
            // Check for end of directory marker
            if (entries[j].filename[0] == 0) {
                // We've reached the end of the directory - exit both loops
                sector_index = sector_count;
                break;
            }
            
            // Skip deleted entries
            if (entries[j].filename[0] == 0xe5) {
                continue;
            }
            
            // Additional validation to ensure this is a valid directory entry
            // Check for invalid characters in filename (control chars, specific symbols)
            bool valid_entry = true;
            for (int k = 0; k < 8; k++) {
                char c = entries[j].filename[k];
                if (c != ' ' && c != 0 && (c < 0x20 || c > 0x7e || 
                    c == '"' || c == '*' || c == '/' || c == ':' || 
                    c == '<' || c == '>' || c == '?' || c == '\\' || c == '|')) {
                    valid_entry = false;
                    break;
                }
            }

            // Skip entries that fail validation
            if (!valid_entry) {
                continue;
            }
            
            // Skip volume ID entries
            if (entries[j].attributes & ATTR_VOLUME_ID) {
                continue;
            }
            
            // // Skip "." and ".." directory entries in subdirectories
            // // but keep them visible if explicitly enabled
            // if (entries[j].attributes & ATTR_DIRECTORY && 
            //     (entries[j].filename[0] == '.' && 
            //     (entries[j].filename[1] == ' ' || 
            //      (entries[j].filename[1] == '.' && entries[j].filename[2] == '.')))) {
            //     continue;
            // }
            
            // Validate that first cluster is within valid range
            if (entries[j].first_cluster_low < 2 && 
                entries[j].first_cluster_low != 0 && 
                !(entries[j].attributes & ATTR_DIRECTORY)) {
                continue;
            }

            // Check for valid attributes
            if ((entries[j].attributes & 0x80) || 
                (entries[j].attributes & ATTR_VOLUME_ID && entries[j].attributes != ATTR_VOLUME_ID) || 
                (!entries[j].attributes)) {
                continue; // Skip entries with invalid attributes
            }
            
            // Convert the FAT filename (8.3 format) to a standard filename
            mem_set(filename_buffer, 0, 13);
            
            // Copy the filename, removing trailing spaces
            u32_t name_len = 0;
            for (u32_t k = 0; k < 8; k++) {
                if (entries[j].filename[k] != ' ') {
                    filename_buffer[name_len++] = entries[j].filename[k];
                }
            }
            
            // Add extension if it exists and it's not a directory
            if (!(entries[j].attributes & ATTR_DIRECTORY) && entries[j].extension[0] != ' ') {
                filename_buffer[name_len++] = '.';
                for (u32_t k = 0; k < 3; k++) {
                    if (entries[j].extension[k] != ' ') {
                        filename_buffer[name_len++] = entries[j].extension[k];
                    }
                }
            }
            
            // Add null terminator
            filename_buffer[name_len] = '\0';
            
            // For directories, add a slash to visually indicate it's a directory
            if (entries[j].attributes & ATTR_DIRECTORY) {
                filename_buffer[name_len++] = '/';
                filename_buffer[name_len] = '\0';
            }
            
            // Print filename with padding
            vga_print(filename_buffer);
            for (u32_t padding = name_len; padding < 13; padding++) {
                vga_print(" ");
            }
            
            // Print file size or <DIR> for directories
            if (entries[j].attributes & ATTR_DIRECTORY) {
                vga_print("<DIR>");
                for (u32_t padding = 5; padding < 14; padding++) {
                    vga_print(" ");
                }
                dir_count++;
            } else {
                str_int_to_dec(entries[j].file_size, size_str, 10);
                vga_print(size_str);
                for (u32_t padding = str_len(size_str); padding < 14; padding++) {
                    vga_print(" ");
                }
                total_bytes += entries[j].file_size;
                file_count++;
            }
            
            // Print attributes
            vga_print((entries[j].attributes & ATTR_READ_ONLY) ? "R" : "-");
            vga_print((entries[j].attributes & ATTR_HIDDEN) ? "H" : "-");
            vga_print((entries[j].attributes & ATTR_SYSTEM) ? "S" : "-");
            vga_print((entries[j].attributes & ATTR_DIRECTORY) ? "D" : "-");
            vga_print((entries[j].attributes & ATTR_ARCHIVE) ? "A" : "-");
            vga_print("     ");
            
            // Print date (DD/MM/YYYY format)
            u16_t date = entries[j].last_modification_date;
            u8_t day = date & 0x1f;
            u8_t month = (date >> 5) & 0xf;
            u16_t year = 1980 + (date >> 9);
            
            if (day < 10) vga_print("0");
            str_int_to_dec(day, size_str, 2);
            vga_print(size_str);
            vga_print("/");
            
            if (month < 10) vga_print("0");
            str_int_to_dec(month, size_str, 2);
            vga_print(size_str);
            vga_print("/");
            
            str_int_to_dec(year, size_str, 5);
            vga_print(size_str);
            vga_print(" ");
            vga_print(" ");
            vga_print(" ");
            
            // Print time (HH:MM format)
            u16_t time = entries[j].last_modification_time;
            u8_t hour = time >> 11;
            u8_t minute = (time >> 5) & 0x3f;
            
            if (hour < 10) vga_print("0");
            str_int_to_dec(hour, size_str, 2);
            vga_print(size_str);
            vga_print(":");
            
            if (minute < 10) vga_print("0");
            str_int_to_dec(minute, size_str, 2);
            vga_print(size_str);
            
            vga_print("\n");
        }
        
        sector_index++;
        next_sector++;
        
        // If we're in a subdirectory and we've reached the end of the current cluster,
        // follow the FAT chain to the next cluster of the *same* directory
        if (directory_cluster != 0 && 
            sector_index % fat16_info.boot_record.sectors_per_cluster == 0) {
            u16_t next_cluster = _get_next_cluster(current_cluster);
            if (next_cluster >= FAT16_EOC) {
                break; // End of directory
            }
            current_cluster = next_cluster;
            next_sector = _cluster_to_sector(current_cluster);
            sector_count += fat16_info.boot_record.sectors_per_cluster;
        }
    }
    
    // Print summary and current path
    vga_print("\nCurrent path: ");
    vga_print(current_path);
    vga_print("\n");
    
    vga_print("Total: ");
    str_int_to_dec(file_count, size_str, 6);
    vga_print(size_str);
    vga_print(" files, ");
    
    str_int_to_dec(dir_count, size_str, 6);
    vga_print(size_str);
    vga_print(" directories, ");
    
    str_int_to_dec(total_bytes, size_str, 16);
    vga_print(size_str);
    vga_print(" bytes\n");
}

bool fat16_create_directory(const char *dirname) {
    // Parse the path to separate directory name from path
    char path[256];
    char name[13]; // 8.3 format + null terminator
    
    // Simple parsing: find last '/'
    const char *last_slash = str_chr(dirname, '/');
    if (last_slash) {
        // Copy path part
        u32_t path_len = last_slash - dirname;
        mem_cpy(path, dirname, path_len);
        path[path_len] = '\0';
        
        // Copy name part (skip the '/')
        mem_cpy(name, last_slash + 1, 12);
        name[12] = '\0';
    } else {
        // No path, just name
        mem_cpy(path, ".", 2);  // Current directory
        mem_cpy(name, dirname, 12);
        name[12] = '\0';
    }
    
    // Find the parent directory
    u16_t parent_cluster;
    if (!_find_dir_by_path(path, &parent_cluster)) {
        return false;  // Parent directory not found
    }
    
    // Create directory entry
    dir_entry_t new_dir;
    mem_set(&new_dir, 0, sizeof(dir_entry_t));
    
    // Set up filename
    _filename_to_fat83(name, new_dir.filename, NULL);
    
    // Set attributes and timestamps
    new_dir.attributes = ATTR_DIRECTORY;
    new_dir.creation_date = _create_fat_date();
    new_dir.creation_time = _create_fat_time();
    new_dir.last_access_date = new_dir.creation_date;
    new_dir.last_modification_date = new_dir.creation_date;
    new_dir.last_modification_time = new_dir.creation_time;
    
    // Allocate first cluster
    u16_t first_cluster = _find_free_cluster();
    if (first_cluster == 0) {
        return false;  // No free clusters
    }
    
    new_dir.first_cluster_low = first_cluster;
    new_dir.file_size = 0;
    
    // Mark the end of chain in FAT
    _update_fat_entry(first_cluster, FAT16_EOC);
    
    // Find free directory entry in parent directory
    u32_t dir_sector, dir_offset;
    if (!_find_free_dir_entry(&dir_sector, &dir_offset)) {
        // Revert FAT allocation
        _update_fat_entry(first_cluster, FAT_ENTRY_FREE);
        return false;
    }
    
    // Write directory entry
    u8_t buffer[SECTOR_SIZE];
    if (ata_read_sectors(dir_sector, 1, buffer) < 0) {
        _update_fat_entry(first_cluster, FAT_ENTRY_FREE);
        return false;
    }
    
    mem_cpy(&buffer[dir_offset], &new_dir, sizeof(dir_entry_t));
    
    if (ata_write_sectors(dir_sector, 1, buffer) < 0) {
        _update_fat_entry(first_cluster, FAT_ENTRY_FREE);
        return false;
    }
    
    // Initialize directory contents (. and .. entries)
    mem_set(buffer, 0, SECTOR_SIZE);
    
    // Create "." entry (points to itself)
    dir_entry_t *dot_entry = (dir_entry_t *)buffer;
    dot_entry->filename[0] = '.';
    for (int i = 1; i < 8; i++) {
        dot_entry->filename[i] = ' ';
    }
    for (int i = 0; i < 3; i++) {
        dot_entry->extension[i] = ' ';
    }

    dot_entry->attributes = ATTR_DIRECTORY;
    dot_entry->creation_date = new_dir.creation_date;
    dot_entry->creation_time = new_dir.creation_time;
    dot_entry->last_access_date = new_dir.last_access_date;
    dot_entry->last_modification_date = new_dir.last_modification_date;
    dot_entry->last_modification_time = new_dir.last_modification_time;
    dot_entry->first_cluster_low = first_cluster;
    
    // Create ".." entry (points to parent)
    dir_entry_t *dotdot_entry = (dir_entry_t *)(buffer + DIR_ENTRY_SIZE);
    dotdot_entry->filename[0] = '.';
    dotdot_entry->filename[1] = '.';
    for (int i = 2; i < 8; i++) {
        dotdot_entry->filename[i] = ' ';
    }
    for (int i = 0; i < 3; i++) {
        dotdot_entry->extension[i] = ' ';
    }

    dotdot_entry->attributes = ATTR_DIRECTORY;
    dotdot_entry->creation_date = new_dir.creation_date;
    dotdot_entry->creation_time = new_dir.creation_time;
    dotdot_entry->last_access_date = new_dir.last_access_date;
    dotdot_entry->last_modification_date = new_dir.last_modification_date;
    dotdot_entry->last_modification_time = new_dir.last_modification_time;
    dotdot_entry->first_cluster_low = parent_cluster;
    
    // Write the directory contents
    u32_t dir_first_sector = _cluster_to_sector(first_cluster);
    if (ata_write_sectors(dir_first_sector, 1, buffer) < 0) {
        _update_fat_entry(first_cluster, FAT_ENTRY_FREE);
        return false;
    }

    return true;
}

bool fat16_change_directory(const char *path) {
    u16_t new_dir_cluster;
    
    // Handle special cases first
    if (str_cmp(path, ".")) {
        // "." means current directory, no change needed
        return true;
    }
    
    if (str_cmp(path, "..")) {
        // ".." means parent directory
        // Special case for root directory
        if (str_cmp(current_path, "/")) {
            // Already at root, nothing to do
            return true;
        }
        
        // Find the last '/' in the current path
        int i = str_len(current_path) - 1;
        while (i > 0 && current_path[i] != '/') {
            i--;
        }
        
        // Truncate the path at the last '/'
        if (i == 0) {
            // We're directly under root, just set to "/"
            current_path[0] = '/';
            current_path[1] = '\0';
            
            current_dir_cluster = 0; // Special value for root directory
        } else {
            // Get the parent path
            char parent_path[256];
            mem_cpy(parent_path, current_path, i);
            parent_path[i] = '\0';
            
            // Find the parent directory's cluster
            if (!_find_dir_by_path(parent_path, &new_dir_cluster)) {
                return false;
            }
            
            // Update current directory information
            current_dir_cluster = new_dir_cluster;
            
            // Update the path
            current_path[i] = '\0';
            if (i == 0) {
                // Make sure we have at least "/"
                current_path[0] = '/';
                current_path[1] = '\0';
            }
        }
        
        return true;
    }
    
    // Regular directory change
    if (!_find_dir_by_path(path, &new_dir_cluster)) {
        return false;  // Directory not found
    }
    
    // Update current directory
    current_dir_cluster = new_dir_cluster;
    
    // Update current path
    if (path[0] == '/') {
        // Absolute path
        mem_cpy(current_path, path, 255);
        current_path[255] = '\0';
    } else {
        // Relative path
        char temp_path[256];
        if (str_cmp(current_path, "/") ) {
            // Create string like "/path"
            temp_path[0] = '/';
            mem_cpy(&temp_path[1], path, 254);
            temp_path[255] = '\0';
        } else {
            u32_t current_len = str_len(current_path);
            mem_cpy(temp_path, current_path, current_len);
            temp_path[current_len] = '/';
            mem_cpy(&temp_path[current_len + 1], path, 254 - current_len);
            temp_path[255] = '\0';
        }
        mem_cpy(current_path, temp_path, 256);
    }
    
    return true;
}

const char *fat16_get_path() {
    return current_path;
}

bool fat16_delete_directory(const char *dir_name) {
    dir_entry_t entry;
    u32_t dir_sector, dir_offset;

    // Locate the directory by name and obtain its directory entry and position.
    if (!_find_file(dir_name, &entry, &dir_sector, &dir_offset)) {
        return false; // Directory not found
    }
    
    // Verify the entry is a directory.
    if (!(entry.attributes & ATTR_DIRECTORY)) {
        return false; // Not a directory
    }
    
    // Get the starting cluster of the directory.
    u16_t dir_cluster = entry.first_cluster_low;
    // Prevent deletion of the root directory.
    if (dir_cluster == 0) {
        return false;
    }
    
    // Check that the directory is empty.
    u8_t buffer[SECTOR_SIZE];
    u32_t sector = fat16_info.data_start_sector + 
                   ((dir_cluster - 2) * fat16_info.boot_record.sectors_per_cluster);
    
    // Read the first sector of the directory.
    if (ata_read_sectors(sector, 1, buffer) < 0) {
        return false;
    }
    
    dir_entry_t *entries = (dir_entry_t*)buffer;
    for (int i = 0; i < ENTRIES_PER_SECTOR; i++) {
        // Skip the special entries '.' and '..'
        if (i < 2) continue;
        // If any valid entry exists, the directory isn’t empty.
        if (entries[i].filename[0] != 0 && entries[i].filename[0] != 0xe5) {
            return false;
        }
    }
    
    // If the directory spans multiple clusters, check each cluster for additional entries.
    u16_t next_cluster = dir_cluster;
    u16_t fat_entry;
    while (next_cluster < FAT16_EOC) {
        u32_t fat_offset = next_cluster * 2;
        u32_t fat_sector = fat16_info.fat_start_sector + (fat_offset / SECTOR_SIZE);
        u32_t ent_offset = fat_offset % SECTOR_SIZE;
        
        if (ata_read_sectors(fat_sector, 1, buffer) < 0) {
            return false;
        }
        
        fat_entry = *(u16_t*)&buffer[ent_offset];
        if (fat_entry >= 0xfff8) {
            break;  // End of cluster chain reached
        }
        
        // Move to the next cluster in the chain and check its first sector.
        next_cluster = fat_entry;
        sector = fat16_info.data_start_sector + 
                 ((next_cluster - 2) * fat16_info.boot_record.sectors_per_cluster);
                 
        if (ata_read_sectors(sector, 1, buffer) < 0) {
            return false;
        }
        
        entries = (dir_entry_t*)buffer;
        for (int i = 0; i < ENTRIES_PER_SECTOR; i++) {
            if (entries[i].filename[0] != 0 && entries[i].filename[0] != 0xe5) {
                return false; // Found an entry, so the directory isn’t empty.
            }
        }
    }
    
    // Mark the directory entry in its parent as deleted.
    u8_t entry_buffer[SECTOR_SIZE];
    if (ata_read_sectors(dir_sector, 1, entry_buffer) < 0) {
        return false;
    }
    
    // The first byte of the entry is set to 0xe5 to indicate deletion.
    entry_buffer[dir_offset] = 0xe5;
    
    if (ata_write_sectors(dir_sector, 1, entry_buffer) < 0) {
        return false;
    }
    
    // Free all clusters used by the directory in the FAT chain.
    next_cluster = dir_cluster;
    while (next_cluster < FAT16_EOC) {
        u32_t fat_offset = next_cluster * 2;
        u32_t fat_sector = fat16_info.fat_start_sector + (fat_offset / SECTOR_SIZE);
        u32_t ent_offset = fat_offset % SECTOR_SIZE;
        
        if (ata_read_sectors(fat_sector, 1, buffer) < 0) {
            return false;
        }
        
        fat_entry = *(u16_t *)&buffer[ent_offset];
        // Mark this cluster as free.
        *(u16_t *)&buffer[ent_offset] = 0x0000;
        
        if (ata_write_sectors(fat_sector, 1, buffer) < 0) {
            return false;
        }
        
        if (fat_entry >= 0xfff8) {
            break;  // Last cluster in the chain
        }
        
        next_cluster = fat_entry;
    }
    
    return true;
}

/* =============================== Private Functions =============================== */

// Initialize date/time values
static u16_t _create_fat_date() {
    // Just a default value: 1980-01-01
    return (0 << 9) | (1 << 5) | 1;  // Year(0-127) + 1980, Month(1-12), Day(1-31)
}

static u16_t _create_fat_time() {
    // Default time: 0:00:00
    return (0 << 11) | (0 << 5) | 0;  // Hour(0-23), Minute(0-59), Second/2(0-29)
}

// Convert 8.3 filename to FAT format (space padded)
static void _filename_to_fat83(const char *filename, u8_t *name, u8_t *ext) {
    // Initialize the 8-byte name with spaces.
    for (int i = 0; i < 8; i++) {
        name[i] = ' ';
    }
    
    // If an extension buffer is provided, initialize the 3-byte extension with spaces.
    if (ext) {
        for (int i = 0; i < 3; i++) {
            ext[i] = ' ';
        }
    }
    
    // Process the name part (up to 8 characters or until a dot is found)
    int name_indx = 0;
    for (int i = 0; i < 8 && filename[i] && filename[i] != '.'; i++) {
        char c = str_to_upper(filename[i]);
        // Skip invalid FAT characters
        if (c < 0x20 || c > 0x7e || 
            c == '"' || c == '*' || c == '+' || c == ',' || c == '.' || 
            c == '/' || c == ':' || c == ';' || c == '<' || c == '=' || 
            c == '>' || c == '?' || c == '[' || c == '\\' || c == ']' || c == '|') {
            continue;
        }
        name[name_indx++] = c;
    }
    
    // Process the extension if provided.
    if (ext) {
        // Locate the extension starting at the '.' character
        const char *extension = str_chr(filename, '.');
        if (extension) {
            extension++;  // Skip the dot
            int ext_indx = 0;
            for (int i = 0; i < 3 && extension[i]; i++) {
                char c = str_to_upper(extension[i]);
                // Skip any invalid character from the extension.
                if (c < 0x20 || c > 0x7e || 
                    c == '"' || c == '*' || c == '+' || c == ',' ||  c == '.' || 
                    c == '/' || c == ':' || c == ';' || c == '<' || c == '=' || 
                    c == '>' || c == '?' || c == '[' || c == '\\' || c == ']' || c == '|') {
                    continue;
                }
                ext[ext_indx++] = c;
            }
        }
    }
}


// Compare a filename with a directory entry
static bool _filename_matches(const char *filename, const dir_entry_t *entry) {
    char fat_name[8+1];
    char fat_ext[3+1];
    char entry_name[8+1];
    char entry_ext[3+1];
    
    // Extract entry name and extension
    mem_cpy(entry_name, entry->filename, 8);
    entry_name[8] = '\0';
    mem_cpy(entry_ext, entry->extension, 3);
    entry_ext[3] = '\0';
    
    // Remove trailing spaces
    for (int i = 7; i >= 0 && entry_name[i] == ' '; i--) entry_name[i] = '\0';
    for (int i = 2; i >= 0 && entry_ext[i] == ' '; i--) entry_ext[i] = '\0';
    
    // Convert filename to FAT 8.3 format for comparison
    mem_set(fat_name, 0, 9);
    mem_set(fat_ext, 0, 4);
    _filename_to_fat83(filename, (u8_t *)fat_name, (u8_t *)fat_ext);
    
    // Remove trailing spaces
    for (int i = 7; i >= 0 && fat_name[i] == ' '; i--) fat_name[i] = '\0';
    for (int i = 2; i >= 0 && fat_ext[i] == ' '; i--) fat_ext[i] = '\0';
    
    // Compare
    return (str_cmp(fat_name, entry_name) && str_cmp(fat_ext, entry_ext));
}

// Find a free cluster in the FAT and mark it as used
static u16_t _find_free_cluster() {
    u8_t temp_sector[SECTOR_SIZE];
    u16_t fat_sector = fat16_info.fat_start_sector;
   
    for (u32_t i = 0; i < fat16_info.boot_record.fat_size_sectors; i++) {
        ata_read_sectors(fat_sector + i, 1, temp_sector);
        u16_t *fat_entries = (u16_t *)temp_sector;
       
        for (u32_t j = 0; j < SECTOR_SIZE / 2; j++) {
            u16_t cluster = i * (SECTOR_SIZE / 2) + j;
            // Skip reserved clusters and look for a free one
            if (cluster >= 2 && fat_entries[j] == FAT_ENTRY_FREE) {
                // Mark this cluster as the end-of-chain
                fat_entries[j] = FAT16_EOC;
                
                // Write the updated FAT sector back to disk
                ata_write_sectors(fat_sector + i, 1, temp_sector);
                
                // If a second FAT is in use, update that as well
                if (fat16_info.boot_record.num_fats > 1) {
                    u32_t fat2_sector = fat_sector + i + fat16_info.boot_record.fat_size_sectors;
                    ata_write_sectors(fat2_sector, 1, temp_sector);
                }
                
                return cluster;
            }
        }
    }
   
    return 0; // No free clusters found.
}

// Update FAT entry for a cluster
static void _update_fat_entry(u16_t cluster, u16_t value) {
    u32_t fat_offset = cluster * 2; // Each FAT entry is 2 bytes.
    u32_t fat_sector = fat16_info.fat_start_sector + (fat_offset / SECTOR_SIZE);
    u32_t entry_offset = fat_offset % SECTOR_SIZE;
    
    // Read the FAT sector into a local buffer.
    ata_read_sectors(fat_sector, 1, temp_sector);
    *((u16_t *)(temp_sector + entry_offset)) = value;
    
    // Write the updated sector back to disk.
    ata_write_sectors(fat_sector, 1, temp_sector);

    // If a second FAT is in use, update that as well.
    if (fat16_info.boot_record.num_fats > 1) {
        u32_t fat2_sector = fat_sector + fat16_info.boot_record.fat_size_sectors;
        ata_write_sectors(fat2_sector, 1, temp_sector);
    }
}

// Get the next cluster in a chain
static u16_t _get_next_cluster(u16_t cluster) {
    u32_t fat_offset = cluster * 2;
    u32_t fat_sector = fat16_info.fat_start_sector + (fat_offset / SECTOR_SIZE);
    u32_t entry_offset = fat_offset % SECTOR_SIZE;
    
    ata_read_sectors(fat_sector, 1, temp_sector);
    return *((u16_t *)(temp_sector + entry_offset));
}

// Convert cluster number to sector number
static u32_t _cluster_to_sector(u16_t cluster) {
    return fat16_info.data_start_sector + ((cluster - 2) * fat16_info.boot_record.sectors_per_cluster);
}

// Find a file by its path
static bool _find_file(const char *filename, dir_entry_t *entry, u32_t *dir_sector, u32_t *dir_offset) {
    // Buffers for the filename (8.3 filename plus null terminator)
    char name[13]; // 8.3 format (8 + 3) + null terminator
    
    // Copy the filename, ensuring it doesn't exceed buffer capacity
    {
        u32_t name_len = str_len(filename);
        if (name_len > 12) name_len = 12;
        mem_cpy(name, filename, name_len);
        name[name_len] = '\0';
    }
    // Check if current path is the root directory
    if (str_cmp(current_path, "/")) {
        // Calculate the number of sectors occupied by the root directory
        u32_t root_sectors = ((fat16_info.boot_record.root_dir_entries * DIR_ENTRY_SIZE) +
                              (fat16_info.boot_record.bytes_per_sector - 1)) /
                             fat16_info.boot_record.bytes_per_sector;
        
        // Iterate over each sector in the root directory
        for (u32_t i = 0; i < root_sectors; i++) {
            // Read one sector from the root directory
            ata_read_sectors(fat16_info.root_dir_start_sector + i, 1, temp_sector);
           
            // Cast the sector buffer to an array of dir_entry_t structures
            dir_entry_t *entries = (dir_entry_t *)temp_sector;
            for (u32_t j = 0; j < ENTRIES_PER_SECTOR; j++) {
                // Skip unused entries (first byte is 0 or marked as deleted (0xe5))
                if (entries[j].filename[0] == 0 || entries[j].filename[0] == 0xe5) {
                    continue;
                }
               
                // Skip directory entries and volume labels
                if (entries[j].attributes & (ATTR_DIRECTORY | ATTR_VOLUME_ID)) {
                    continue;
                }
               
                // Check if this entry's filename matches the requested filename
                if (_filename_matches(name, &entries[j])) {
                    if (entry) {
                        *entry = entries[j];
                    }
                    if (dir_sector) {
                        *dir_sector = fat16_info.root_dir_start_sector + i;
                    }
                    if (dir_offset) {
                        *dir_offset = j * DIR_ENTRY_SIZE;
                    }
                    vga_print(current_path);
                    return true;
                }
            }
        }
       
        // File not found in root directory
        return false;
    } else {
        // For current directory that is not root, first find the directory cluster
        u16_t dir_cluster;
        if (!_find_dir_by_path(current_path, &dir_cluster)) {
            return false;  // Directory not found
        }
        
        // Delegate to find_dir_entry which will search the directory specified by dir_cluster
        return _find_dir_entry(dir_cluster, name, entry, dir_sector, dir_offset);
    }
}

// Find a free directory entry
static bool _find_free_dir_entry(u32_t *dir_sector, u32_t *dir_offset) {
    // If we're in the root directory
    if (current_dir_cluster == 0) {
        u32_t root_sectors = ((fat16_info.boot_record.root_dir_entries * DIR_ENTRY_SIZE) + 
                            (fat16_info.boot_record.bytes_per_sector - 1)) / 
                            fat16_info.boot_record.bytes_per_sector;
        
        for (u32_t i = 0; i < root_sectors; i++) {
            ata_read_sectors(fat16_info.root_dir_start_sector + i, 1, temp_sector);
            
            dir_entry_t *entries = (dir_entry_t *)temp_sector;
            for (u32_t j = 0; j < ENTRIES_PER_SECTOR; j++) {
                // Check for unused entry
                if (entries[j].filename[0] == 0 || entries[j].filename[0] == 0xe5) {
                    *dir_sector = fat16_info.root_dir_start_sector + i;
                    *dir_offset = j * DIR_ENTRY_SIZE;
                    
                    // Clear the entire entry to make sure we're starting fresh
                    mem_set(&entries[j], 0, sizeof(dir_entry_t));
                    // Mark it as the last entry if it was the end marker
                    if (entries[j].filename[0] == 0) {
                        // Make sure the next entry is also properly marked as end
                        if (j+1 < ENTRIES_PER_SECTOR) {
                            entries[j+1].filename[0] = 0;
                        }
                    }
                    
                    // Write the cleared entry back
                    ata_write_sectors(fat16_info.root_dir_start_sector + i, 1, temp_sector);
                    return true;
                }
            }
        }
    } else {
        // We're in a subdirectory, use the cluster-based search
        return _find_free_dir_entry_in_cluster(current_dir_cluster, dir_sector, dir_offset);
    }
    
    return false;
}

// Parse a path to split it into components
static bool _parse_path(const char *path, char *components[], int *num_components) {
    char path_copy[256];
    mem_cpy(path_copy, path, 255);
    path_copy[255] = '\0';
    
    *num_components = 0;
    
    // Handle absolute vs relative path
    char *token;
    if (path_copy[0] == '/') {
        token = str_tok(path_copy + 1, "/");  // Skip the first '/'
    } else {
        token = str_tok(path_copy, "/");
    }
    
    while (token != NULL && *num_components < 32) {  // Limit to 32 components
        components[*num_components] = token;
        (*num_components)++;
        token = str_tok(NULL, "/");
    }
    
    return true;
}

// Find a directory entry in the specified directory cluster
static bool _find_dir_entry(u16_t dir_cluster, const char *name, dir_entry_t *entry, u32_t *dir_sector, u32_t *dir_offset) {
    // Special case for root directory
    u32_t sector;
    u32_t max_sectors;
    
    if (dir_cluster == 0) {
        // Root directory handling
        sector = fat16_info.root_dir_start_sector;
        max_sectors = fat16_info.root_dir_start_sector + 
                    (fat16_info.boot_record.root_dir_entries * DIR_ENTRY_SIZE) / SECTOR_SIZE;
    } else {
        // Subdirectory handling
        sector = _cluster_to_sector(dir_cluster);
        max_sectors = sector + fat16_info.boot_record.sectors_per_cluster;
    }
    
    u8_t buffer[SECTOR_SIZE];
    dir_entry_t *dir_entry;
    
    while (sector < max_sectors) {
        if (ata_read_sectors(sector, 1, buffer) < 0) {
            return false;
        }
        
        for (u32_t i = 0; i < ENTRIES_PER_SECTOR; i++) {
            dir_entry = (dir_entry_t *)&buffer[i * DIR_ENTRY_SIZE];
            
            // Skip empty entries
            if (dir_entry->filename[0] == 0x00) {
                break;  // End of directory
            }
            
            if (dir_entry->filename[0] == 0xe5) {
                continue;  // Deleted entry
            }
            
            // Check if the name matches
            if (_filename_matches(name, dir_entry)) {
                *entry = *dir_entry;
                *dir_sector = sector;
                *dir_offset = i * DIR_ENTRY_SIZE;
                return true;
            }
        }
        
        sector++;
        
        // If we're in a subdirectory, we need to follow the cluster chain
        if (dir_cluster != 0 && sector >= max_sectors) {
            u16_t next_cluster = _get_next_cluster(dir_cluster);
            if (next_cluster >= FAT16_EOC) {
                break;  // End of directory
            }
            dir_cluster = next_cluster;
            sector = _cluster_to_sector(dir_cluster);
            max_sectors = sector + fat16_info.boot_record.sectors_per_cluster;
        }
    }
    
    return false;  // Not found
}

// Find a directory by path
static bool _find_dir_by_path(const char *path, u16_t *dir_cluster) {
    // Handle root directory case
    if (str_cmp(path, "/")) {
        *dir_cluster = 0;  // 0 represents root directory
        return true;
    }
   
    // Handle current directory
    if (str_cmp(path, ".")) {
        *dir_cluster = current_dir_cluster;
        return true;
    }
   
    // Handle parent directory
    if (str_cmp(path, "..")) {
        // If already at root, stay at root
        if (current_dir_cluster == 0) {
            *dir_cluster = 0;
            return true;
        }
       
        // Need to find the parent by reading the ".." entry
        u8_t buffer[SECTOR_SIZE];
        u32_t sector = _cluster_to_sector(current_dir_cluster);
       
        if (ata_read_sectors(sector, 1, buffer) < 0) {
            return false;
        }
       
        // The ".." entry is the second entry in a directory
        dir_entry_t *dotdot = (dir_entry_t *)&buffer[DIR_ENTRY_SIZE];
        if (dotdot->filename[0] != '.' || dotdot->filename[1] != '.') {
            return false; // Invalid directory structure
        }
       
        *dir_cluster = dotdot->first_cluster_low;
        if (*dir_cluster == 0) {
            *dir_cluster = 0; // Ensure it's 0 for root
        }
        return true;
    }
   
    // Parse the path components
    char *components[32];  // Maximum 32 path components
    int num_components;
   
    if (!_parse_path(path, components, &num_components)) {
        return false;
    }
   
    // Start from root or current directory
    u16_t current_cluster;
    if (path[0] == '/') {
        current_cluster = 0;  // Start from root
    } else {
        current_cluster = current_dir_cluster;  // Start from current directory
    }
   
    // Return the final directory cluster
    *dir_cluster = current_cluster;
    return true;
}

static bool _find_free_dir_entry_in_cluster(u16_t dir_cluster, u32_t *dir_sector, u32_t *dir_offset) {
   // Start with the first sector of the directory
   u32_t sector = _cluster_to_sector(dir_cluster);
   u32_t sectors_per_cluster = fat16_info.boot_record.sectors_per_cluster;
   u16_t current_search_cluster = dir_cluster;

   while (current_search_cluster >= 2 && current_search_cluster < FAT16_EOC) {
       sector = _cluster_to_sector(current_search_cluster);
       // For each sector in the current cluster of the directory
       for (u32_t i = 0; i < sectors_per_cluster; i++) {
           // Read the sector
           if (ata_read_sectors(sector + i, 1, temp_sector) < 0) {
                return false;
           }

           // Check each directory entry in the sector
           for (u32_t offset = 0; offset < SECTOR_SIZE; offset += sizeof(dir_entry_t)) {
               // Get the entry
               dir_entry_t *entry = (dir_entry_t *)(temp_sector + offset);

               // Check if entry is free (first byte is 0xe5 or 0x00)
               if (entry->filename[0] == 0xe5 || entry->filename[0] == 0x00) {
                   *dir_sector = sector + i;
                   *dir_offset = offset;

                   return true;
               }
           }
       }
       // If no free entry in this cluster, move to the next one in the chain
       current_search_cluster = _get_next_cluster(current_search_cluster);
   }

   // No free entry found in this directory cluster chain
   return false;
}

static bool _find_free_dir_entry_in_root(u32_t *dir_sector, u32_t *dir_offset) {
    u32_t root_sectors = ((fat16_info.boot_record.root_dir_entries * DIR_ENTRY_SIZE) +
                        (fat16_info.boot_record.bytes_per_sector - 1)) /
                        fat16_info.boot_record.bytes_per_sector;

    for (u32_t i = 0; i < root_sectors; i++) {
        // Read one sector from the root directory.
        if (ata_read_sectors(fat16_info.root_dir_start_sector + i, 1, temp_sector) < 0) {
             return false;
        }

        dir_entry_t *entries = (dir_entry_t *)temp_sector;
        for (u32_t j = 0; j < ENTRIES_PER_SECTOR; j++) {
            // Check for unused entry (0x00: never used, 0xe5: deleted)
            if (entries[j].filename[0] == 0 || entries[j].filename[0] == 0xe5) {
                *dir_sector = fat16_info.root_dir_start_sector + i;
                *dir_offset = j * DIR_ENTRY_SIZE;

                return true; // Found a free entry
            }
        }
    }

    return false; // No free entry found in the root directory
}