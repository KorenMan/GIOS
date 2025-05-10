#include "fat16.h"
#include "ata-driver.h"
#include "vga-driver.h"
#include "../lib/memory.h"
#include "../lib/string.h"

// Filesystem information
static u8_t temp_sector[SECTOR_SIZE];
static fat16_info_t fat16_info;

// Track current directory
static u16_t current_cluster = 0;
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
    
    mem_cpy(fat16_info.boot_record.oem_name, "FAT16 ", 8);
    
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
    mem_cpy(fat16_info.boot_record.fat16_type, "FAT16 ", 8);
    
    // Calculate important sector positions
    fat16_info.fat_start_sector = fat16_info.boot_record.reserved_sectors;
    fat16_info.root_dir_start_sector = fat16_info.fat_start_sector + 
                              (fat16_info.boot_record.num_fats * fat_size);
    fat16_info.data_start_sector = fat16_info.root_dir_start_sector + root_dir_sectors;
    fat16_info.cluster_size_bytes = fat16_info.boot_record.sectors_per_cluster * SECTOR_SIZE;
    
    // Write boot sector
    if (ata_write_sectors(0, 1, &fat16_info.boot_record)) {
        return false;
    }
    
    // Initialize the FATs
    mem_set(temp_sector, 0, SECTOR_SIZE);
    u16_t *fat = (u16_t *)temp_sector;
    
    // First two FAT entries are reserved
    fat[0] = 0xfff8;  // Media descriptor
    fat[1] = 0xffff;  // End of chain marker
    
    // Write first sector of each FAT
    if (ata_write_sectors(fat16_info.fat_start_sector, 1, temp_sector)) {
        return false;
    }
    
    if (ata_write_sectors(fat16_info.fat_start_sector + fat_size, 1, temp_sector)) {
        return false;
    }
    
    // Clear the rest of the FATs
    mem_set(temp_sector, 0, SECTOR_SIZE);
    
    for (u32_t i = 1; i < fat_size; i++) {
        if (ata_write_sectors(fat16_info.fat_start_sector + i, 1, temp_sector)) {
            return false;
        }
        
        if (ata_write_sectors(fat16_info.fat_start_sector + fat_size + i, 1, temp_sector)) {
            return false;
        }
    }
    
    // Clear root directory
    for (u32_t i = 0; i < root_dir_sectors; i++) {
        if (ata_write_sectors(fat16_info.root_dir_start_sector + i, 1, temp_sector)) {
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
    file_t file;
    mem_set(&file, 0, sizeof(file_t));
    
    // Check if file already exists
    if (_find_file(filename, NULL, NULL, NULL)) {
        return file; // File already exists
    }
    
    // Find a free directory entry
    u32_t dir_sector, dir_offset;
    if (!_find_free_dir_entry(&dir_sector, &dir_offset)) {
        return file; // No free directory entries
    }
    
    // Read the sector to modify the entry
    ata_read_sectors(dir_sector, 1, temp_sector);
    
    // Get pointer to the directory entry
    dir_entry_t *dir_entry = (dir_entry_t *)(temp_sector + dir_offset);
    
    // Clear the entry first
    mem_set(dir_entry, 0, sizeof(dir_entry_t));
    
    // Set filename
    _filename_to_fat83(filename, dir_entry->filename, dir_entry->extension);
    
    // Set attributes and times
    dir_entry->attributes = ATTR_ARCHIVE;
    dir_entry->creation_time = _create_fat_time();
    dir_entry->creation_date = _create_fat_date();
    dir_entry->last_access_date = dir_entry->creation_date;
    dir_entry->last_modification_time = dir_entry->creation_time;
    dir_entry->last_modification_date = dir_entry->creation_date;
    
    // File initially has no clusters
    dir_entry->first_cluster_low = 0;
    dir_entry->file_size = 0;
    
    // Write the directory entry
    ata_write_sectors(dir_sector, 1, temp_sector);
    
    // Set up the file handle
    file.entry = *dir_entry;
    file.dir_sector = dir_sector;
    file.dir_offset = dir_offset;
    file.position = 0;
    file.current_cluster = 0;
    file.is_open = true;
    
    return file;
}

// Close a file
void fat16_close(file_t *file) {
    if (!file->is_open) return;
    
    // Update directory entry if needed
    ata_read_sectors(file->dir_sector, 1, temp_sector);
    mem_cpy(temp_sector + file->dir_offset, &file->entry, sizeof(dir_entry_t));
    ata_write_sectors(file->dir_sector, 1, temp_sector);
    
    file->is_open = false;
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
    file->entry.file_size = file->position;
    
    file->current_cluster = cluster;
    
    // Update the directory entry on disk with the new file size/cluster info
    ata_read_sectors(file->dir_sector, 1, temp_sector);
    mem_cpy(temp_sector + file->dir_offset, &file->entry, sizeof(dir_entry_t));
    ata_write_sectors(file->dir_sector, 1, temp_sector);
    
    return bytes_written;
}

// Delete a file
bool fat16_delete(const char *filename) {
    dir_entry_t entry;
    u32_t dir_sector, dir_offset;
    
    // Find the file
    if (!_find_file(filename, &entry, &dir_sector, &dir_offset)) {
        return false;  // File not found
    }
    
    // Mark directory entry as deleted
    ata_read_sectors(dir_sector, 1, temp_sector);
    temp_sector[dir_offset] = 0xe5;  // Mark as deleted
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

// List all files in the current directory
void fat16_list_files() {
    u32_t file_count = 0;
    u32_t total_bytes = 0;
    char filename_buffer[13]; // 8 + '.' + 3 + null terminator
    char size_str[16];
    dir_entry_t *entries;

    vga_print("Path: ");
    vga_print(fat16_get_path()); // Assuming fat16_get_path() returns the current path string
    vga_print("\n");
    vga_print("Name           Size      Attributes     Date      Time\n");
    vga_print("------------------------------------------------------------\n");

    if (current_cluster == 0) { // Root directory 
        u32_t root_dir_sectors = ((fat16_info.boot_record.root_dir_entries * DIR_ENTRY_SIZE) +
                                (fat16_info.boot_record.bytes_per_sector - 1)) /
                                fat16_info.boot_record.bytes_per_sector;
        u32_t entries_processed_in_root = 0;

        for (u32_t i = 0; i < root_dir_sectors; i++) {
            if (ata_read_sectors(fat16_info.root_dir_start_sector + i, 1, temp_sector)) {
                vga_print("Error reading root directory sector.\n");
                return;
            }
            entries = (dir_entry_t *)temp_sector;

            for (u32_t j = 0; j < ENTRIES_PER_SECTOR; j++) {
                if (entries_processed_in_root >= fat16_info.boot_record.root_dir_entries) {
                    goto end_listing; // All root directory entries processed
                }
                if (entries[j].filename[0] == 0x00) { // End of directory
                    goto end_listing;
                }
                if (entries[j].filename[0] == 0xe5) { // Deleted entry
                    entries_processed_in_root++;
                    continue;
                }

                // Process and print entry
                mem_set(filename_buffer, 0, sizeof(filename_buffer));
                u32_t name_len = 0;
                for (u32_t k = 0; k < 8; k++) {
                    if (entries[j].filename[k] == ' ') break;
                    filename_buffer[name_len++] = entries[j].filename[k];
                }
                if (entries[j].extension[0] != ' ') {
                    filename_buffer[name_len++] = '.';
                    for (u32_t k = 0; k < 3; k++) {
                        if (entries[j].extension[k] == ' ') break;
                        filename_buffer[name_len++] = entries[j].extension[k];
                    }
                }

                vga_print(filename_buffer);
                for (u32_t padding = name_len; padding < 13; padding++) vga_print(" ");

                if (entries[j].attributes & ATTR_DIRECTORY) {
                    vga_print("<DIR>        ");
                } else {
                    str_int_to_dec(entries[j].file_size, size_str, 10);
                    vga_print(size_str);
                    for (u32_t padding = str_len(size_str); padding < 14; padding++) vga_print(" ");
                }

                vga_print((entries[j].attributes & ATTR_READ_ONLY) ? "R" : "-");
                vga_print((entries[j].attributes & ATTR_HIDDEN) ? "H" : "-");
                vga_print((entries[j].attributes & ATTR_SYSTEM) ? "S" : "-");
                vga_print((entries[j].attributes & ATTR_ARCHIVE) ? "A" : "-");
                vga_print("     "); // Space before date

                u16_t date = entries[j].last_modification_date;
                u8_t day = date & 0x1f;
                u8_t month = (date >> 5) & 0xf;
                u16_t year = 1980 + (date >> 9);
                if (day < 10) vga_print("0"); str_int_to_dec(day, size_str, 2); vga_print(size_str); vga_print("/");
                if (month < 10) vga_print("0"); str_int_to_dec(month, size_str, 2); vga_print(size_str); vga_print("/");
                str_int_to_dec(year, size_str, 4); vga_print(size_str); vga_print("  ");

                u16_t time = entries[j].last_modification_time;
                u8_t hour = time >> 11;
                u8_t minute = (time >> 5) & 0x3f;
                if (hour < 10) vga_print("0"); str_int_to_dec(hour, size_str, 2); vga_print(size_str); vga_print(":");
                if (minute < 10) vga_print("0"); str_int_to_dec(minute, size_str, 2); vga_print(size_str);
                vga_print("\n");
                // (Duplicated processing block end)

                file_count++;
                if (!(entries[j].attributes & ATTR_DIRECTORY)) {
                    total_bytes += entries[j].file_size;
                }
                entries_processed_in_root++;
            }
        }
    } else if (current_cluster >= 2) { // Subdirectory
        u16_t cluster_to_list = current_cluster;
        while (cluster_to_list >= 2 && cluster_to_list < FAT16_EOC) {
            u32_t first_sector_of_cluster = _cluster_to_sector(cluster_to_list);

            for (u32_t sec_offset = 0; sec_offset < fat16_info.boot_record.sectors_per_cluster; ++sec_offset) {
                if (ata_read_sectors(first_sector_of_cluster + sec_offset, 1, temp_sector)) {
                    vga_print("Error reading directory sector.\n");
                    return;
                }
                entries = (dir_entry_t *)temp_sector;

                for (u32_t j = 0; j < ENTRIES_PER_SECTOR; ++j) {
                    if (entries[j].filename[0] == 0x00) { // End of directory
                        goto end_listing;
                    }
                    if (entries[j].filename[0] == 0xe5) { // Deleted entry
                        continue;
                    }

                    // Process and print entry
                    mem_set(filename_buffer, 0, sizeof(filename_buffer));
                    u32_t name_len = 0;
                    for (u32_t k = 0; k < 8; k++) {
                        if (entries[j].filename[k] == ' ') break;
                        filename_buffer[name_len++] = entries[j].filename[k];
                    }
                    if (entries[j].extension[0] != ' ') {
                        filename_buffer[name_len++] = '.';
                        for (u32_t k = 0; k < 3; k++) {
                            if (entries[j].extension[k] == ' ') break;
                            filename_buffer[name_len++] = entries[j].extension[k];
                        }
                    }

                    vga_print(filename_buffer);
                    for (u32_t padding = name_len; padding < 13; padding++) vga_print(" ");

                    if (entries[j].attributes & ATTR_DIRECTORY) {
                        vga_print("<DIR>        "); // 13 characters for size field + 1 space
                    } else {
                        str_int_to_dec(entries[j].file_size, size_str, 10);
                        vga_print(size_str);
                        for (u32_t padding = str_len(size_str); padding < 14; padding++) vga_print(" ");
                    }

                    vga_print((entries[j].attributes & ATTR_READ_ONLY) ? "R" : "-");
                    vga_print((entries[j].attributes & ATTR_HIDDEN) ? "H" : "-");
                    vga_print((entries[j].attributes & ATTR_SYSTEM) ? "S" : "-");
                    vga_print((entries[j].attributes & ATTR_ARCHIVE) ? "A" : "-");
                    vga_print("     "); // Space before date

                    u16_t date = entries[j].last_modification_date;
                    u8_t day = date & 0x1f;
                    u8_t month = (date >> 5) & 0xf;
                    u16_t year = 1980 + (date >> 9);
                    if (day < 10) vga_print("0"); str_int_to_dec(day, size_str, 2); vga_print(size_str); vga_print("/");
                    if (month < 10) vga_print("0"); str_int_to_dec(month, size_str, 2); vga_print(size_str); vga_print("/");
                    str_int_to_dec(year, size_str, 4); vga_print(size_str); vga_print("  ");

                    u16_t time = entries[j].last_modification_time;
                    u8_t hour = time >> 11;
                    u8_t minute = (time >> 5) & 0x3f;
                    if (hour < 10) vga_print("0"); str_int_to_dec(hour, size_str, 2); vga_print(size_str); vga_print(":");
                    if (minute < 10) vga_print("0"); str_int_to_dec(minute, size_str, 2); vga_print(size_str);
                    vga_print("\n");

                    file_count++;
                     if (!(entries[j].attributes & ATTR_DIRECTORY)) {
                        total_bytes += entries[j].file_size;
                    }
                }
            }
            cluster_to_list = _get_next_cluster(cluster_to_list);
        }
    } else {
        vga_print("Invalid current cluster for listing.\n");
        return;
    }

end_listing:
    vga_print("\nTotal files: ");
    str_int_to_dec(file_count, size_str, 6);
    vga_print(size_str);

    vga_print(", Total size: ");
    str_int_to_dec(total_bytes, size_str, 16);
    vga_print(size_str);
    vga_print(" bytes\n");
}

// Create a sub directory
bool fat16_create_directory(const char *dir_name) {
    // Check if dir already exists
    if (_find_file(dir_name, NULL, NULL, NULL)) {
        return false; // Dir already exists
    }
    
    // Find a free directory entry
    u32_t dir_sector, dir_offset;
    if (!_find_free_dir_entry(&dir_sector, &dir_offset)) {
        return false; // No free directory entries
    }
    
    // Read the sector to modify the entry
    ata_read_sectors(dir_sector, 1, temp_sector);
    
    // Get pointer to the directory entry
    dir_entry_t *dir_entry = (dir_entry_t *)(temp_sector + dir_offset);
    
    // Clear the entry first
    mem_set(dir_entry, 0, sizeof(dir_entry_t));
    
    // Set attributes and times
    mem_cpy(dir_entry->filename, dir_name, str_len(dir_name) + 1);
    dir_entry->extension[0] = '\0';
    dir_entry->attributes = ATTR_DIRECTORY;
    dir_entry->creation_time = _create_fat_time();
    dir_entry->creation_date = _create_fat_date();
    dir_entry->last_access_date = dir_entry->creation_date;
    dir_entry->last_modification_time = dir_entry->creation_time;
    dir_entry->last_modification_date = dir_entry->creation_date;
    
    // File initially has no clusters
    dir_entry->file_size = 0;
    dir_entry->first_cluster_low = _find_free_cluster();
    if (dir_entry->first_cluster_low == 0) {
        return false;
    }
    
    // Write the directory entry
    ata_write_sectors(dir_sector, 1, temp_sector);
    
    u16_t temp = current_cluster;
    current_cluster = dir_entry->first_cluster_low;
        
    // DOT dir
    
    // Find a free directory entry
    if (!_find_free_dir_entry(&dir_sector, &dir_offset)) {
        return false; // No free directory entries
    }
    
    // Read the sector to modify the entry
    ata_read_sectors(dir_sector, 1, temp_sector);
    
    // Get pointer to the directory entry
    dir_entry = (dir_entry_t *)(temp_sector + dir_offset);
    
    // Clear the entry first
    mem_set(dir_entry, 0, sizeof(dir_entry_t));
    
    // Set attributes and times
    mem_cpy(dir_entry->filename, ".", 2);
    dir_entry->extension[0] = '\0';
    dir_entry->attributes = ATTR_DIRECTORY;
    dir_entry->creation_time = _create_fat_time();
    dir_entry->creation_date = _create_fat_date();
    dir_entry->last_access_date = dir_entry->creation_date;
    dir_entry->last_modification_time = dir_entry->creation_time;
    dir_entry->last_modification_date = dir_entry->creation_date;
    
    // File initially has no clusters
    dir_entry->file_size = 0;
    dir_entry->first_cluster_low = current_cluster;
    
    // Write the directory entry
    ata_write_sectors(dir_sector, 1, temp_sector);
    
    // DOTDOT dir

    // Find a free directory entry
    if (!_find_free_dir_entry(&dir_sector, &dir_offset)) {
        return false; // No free directory entries
    }
    
    // Read the sector to modify the entry
    ata_read_sectors(dir_sector, 1, temp_sector);
    
    // Get pointer to the directory entry
    dir_entry = (dir_entry_t *)(temp_sector + dir_offset);
    
    // Clear the entry first
    mem_set(dir_entry, 0, sizeof(dir_entry_t));
    
    // Set attributes and times
    mem_cpy(dir_entry->filename, "..", 3);
    dir_entry->extension[0] = '\0';
    dir_entry->attributes = ATTR_DIRECTORY;
    dir_entry->creation_time = _create_fat_time();
    dir_entry->creation_date = _create_fat_date();
    dir_entry->last_access_date = dir_entry->creation_date;
    dir_entry->last_modification_time = dir_entry->creation_time;
    dir_entry->last_modification_date = dir_entry->creation_date;
   
    // File initially has no clusters
    dir_entry->file_size = 0;
    dir_entry->first_cluster_low = temp;
    
    // Write the directory entry
    ata_write_sectors(dir_sector, 1, temp_sector);
    current_cluster = temp;
    return true;
}

// Change the path relativly
bool fat16_change_directory(const char *path) {
    dir_entry_t entry;
    if (!_find_file(path, &entry, NULL, NULL)) {
        return false;
    }

    if (entry.attributes != ATTR_DIRECTORY) {
        return false;
    }
    
    current_cluster = entry.first_cluster_low;

    if (str_cmp(path, ".")) {
        return true;
    } 
    if (str_cmp(path, "..")) {
        str_replace_last_char(current_path, '/', '\0');
        if (current_path[0] == '\0') {
            str_cat(current_path, "/");
        }
        return true;
    }
    if (str_len(path) + str_len(current_path) < 255) {
        if (!str_cmp(current_path, "/")) {
            str_cat(current_path, "/");
        }
        str_cat(current_path, path);
        return true;
    }
    return false;
}

// Returns the current path
char *fat16_get_path() {
    return current_path;
}

// Delete an empty directory
bool fat16_delete_directory(const char *dir_name) {
    dir_entry_t entry;
    u32_t dir_sector, dir_offset;
    u16_t original_parent_cluster = current_cluster;

    if (!_find_file(dir_name, &entry, &dir_sector, &dir_offset)) {
        return false; // Directory not found in current_cluster
    }

    if (!(entry.attributes & ATTR_DIRECTORY)) {
        return false; // Not a directory
    }

    // Should prevent deletion of "." or ".."
    if (str_cmp(dir_name, ".") || str_cmp(dir_name, "..")) {
        return false; 
    }
    
    // Temporarily change current_cluster to the directory being inspected
    u16_t target_dir_cluster = entry.first_cluster_low;
    current_cluster = target_dir_cluster;

    bool is_empty = true;
    u16_t cluster_to_scan = target_dir_cluster;
    dir_entry_t *sub_entries;

    // A directory is empty if it only contains "." and ".."
    while (cluster_to_scan >= 2 && cluster_to_scan < FAT16_EOC) {
        u32_t current_data_sector = _cluster_to_sector(cluster_to_scan);

        for (u32_t sec_offset = 0; sec_offset < fat16_info.boot_record.sectors_per_cluster; ++sec_offset) {
            if (ata_read_sectors(current_data_sector + sec_offset, 1, temp_sector)) {
                current_cluster = original_parent_cluster; // Restore
                return false; // Read error
            }

            sub_entries = (dir_entry_t *)temp_sector;
            for (u32_t i = 0; i < ENTRIES_PER_SECTOR; ++i) {
                if (sub_entries[i].filename[0] == 0x00) { // End of directory
                    goto end_emptiness_check;
                }
                if (sub_entries[i].filename[0] == 0xe5) { // Deleted entry
                    continue;
                }

                // Check if the entry is "." or ".."
                bool is_dot_or_dotdot = false;
                if (sub_entries[i].filename[0] == '.' && sub_entries[i].filename[1] == ' ') {
                    is_dot_or_dotdot = true; // Matches "."
                     for(int k=2; k<8; ++k) if(sub_entries[i].filename[k] != ' ') is_dot_or_dotdot = false;
                     for(int k=0; k<3; ++k) if(sub_entries[i].extension[k] != ' ') is_dot_or_dotdot = false;
                }
                if (!is_dot_or_dotdot && sub_entries[i].filename[0] == '.' && sub_entries[i].filename[1] == '.' && sub_entries[i].filename[2] == ' ') {
                    is_dot_or_dotdot = true; // Matches ".."
                    for(int k=3; k<8; ++k) if(sub_entries[i].filename[k] != ' ') is_dot_or_dotdot = false;
                    for(int k=0; k<3; ++k) if(sub_entries[i].extension[k] != ' ') is_dot_or_dotdot = false;
                }

                if (!is_dot_or_dotdot) {
                    is_empty = false;
                    goto end_emptiness_check;
                }
            }
        }
        cluster_to_scan = _get_next_cluster(cluster_to_scan);
    }

end_emptiness_check:
    current_cluster = original_parent_cluster; // Restore current_cluster

    if (!is_empty) {
        return false; // Directory not empty
    }

    // Mark directory entry as deleted in its parent directory
    if (ata_read_sectors(dir_sector, 1, temp_sector)) {
        return false; // Read error
    }
    temp_sector[dir_offset] = 0xe5; // Mark as deleted (first byte of filename)
    if (ata_write_sectors(dir_sector, 1, temp_sector)) {
        return false; // Write error
    }

    // Free clusters allocated to this directory
    u16_t cluster_to_free = entry.first_cluster_low;
    while (cluster_to_free >= 2 && cluster_to_free < FAT16_EOC) {
        u16_t next_cluster = _get_next_cluster(cluster_to_free);
        _update_fat_entry(cluster_to_free, FAT_ENTRY_FREE);
        cluster_to_free = next_cluster;
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

// Convert 8.3 filename to FAT format 
static void _filename_to_fat83(const char *filename, u8_t *name, u8_t *ext) {
    // Initialize with spaces
    for (int i = 0; i < 8; i++) name[i] = ' ';
    for (int i = 0; i < 3; i++) ext[i] = ' ';
    
    // Filter invalid characters and convert to uppercase
    int name_idx = 0;
    for (int i = 0; i < 8 && filename[i] && filename[i] != '.'; i++) {
        char c = str_to_upper(filename[i]);
        // Skip invalid FAT characters
        if (c < 0x20 || c > 0x7e || 
            c == '"' || c == '*' || c == '+' || c == ',' || c == '.' || 
            c == '/' || c == ':' || c == ';' || c == '<' || c == '=' || 
            c == '>' || c == '?' || c == '[' || c == '\\' || c == ']' || c == '|') {
            continue;
        }
        name[name_idx++] = c;
    }
    
    // Find extension
    const char *extension = str_chr(filename, '.');
    if (extension) {
        extension++; // Skip the '.'
        // Copy extension part
        int ext_idx = 0;
        for (int i = 0; i < 3 && extension[i]; i++) {
            char c = str_to_upper(extension[i]);
            // Skip invalid FAT characters
            if (c < 0x20 || c > 0x7e || 
                c == '"' || c == '*' || c == '+' || c == ',' || c == '.' || 
                c == '/' || c == ':' || c == ';' || c == '<' || c == '=' || 
                c == '>' || c == '?' || c == '[' || c == '\\' || c == ']' || c == '|') {
                continue;
            }
            ext[ext_idx++] = c;
        }
    }
}

// Compare a filename with a directory entry
static bool _filename_matches(const char *filename, const dir_entry_t *entry) {
    if (entry->attributes == ATTR_ARCHIVE) {
        u8_t name[8], ext[3];
        _filename_to_fat83(filename, name, ext);
    
        // Compare name and extension
        for (int i = 0; i < 8; i++)
            if (name[i] != entry->filename[i]) return false;
        for (int i = 0; i < 3; i++)
            if (ext[i] != entry->extension[i]) return false;
    } else {
        if (!str_cmp(filename, entry->filename)) {
            return false;
        }
    }
    
    return true;
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

static bool _find_file(const char *filename, dir_entry_t *entry, u32_t *dir_sector, u32_t *dir_offset) {
    dir_entry_t *entries;
    if (current_cluster == 0) { // Root directory
        u32_t root_dir_total_entries = fat16_info.boot_record.root_dir_entries;
        u32_t entries_processed = 0;

        for (u32_t i = 0; i < fat16_info.root_dir_start_sector + (root_dir_total_entries * DIR_ENTRY_SIZE / SECTOR_SIZE) - fat16_info.root_dir_start_sector ; i++) { // Iterate sectors of root dir
            u32_t current_sector_abs = fat16_info.root_dir_start_sector + i;
            if (ata_read_sectors(current_sector_abs, 1, temp_sector)) return false; // Read error

            entries = (dir_entry_t *)temp_sector;
            for (u32_t j = 0; j < ENTRIES_PER_SECTOR; j++) {
                if (entries_processed >= root_dir_total_entries) return false; // Exceeded max root entries

                if (entries[j].filename[0] == 0x00) return false; // End of directory
                if (entries[j].filename[0] == 0xe5) {entries_processed++; continue;}    // Deleted entry

                if (_filename_matches(filename, &entries[j])) {
                    if (entry) *entry = entries[j];
                    if (dir_sector) *dir_sector = current_sector_abs;
                    if (dir_offset) *dir_offset = j * DIR_ENTRY_SIZE;
                    return true;
                }
                entries_processed++;
            }
        }
    } else { // Subdirectory (current_cluster >= 2)
        u16_t cluster_to_scan = current_cluster;
        while (cluster_to_scan >= 2 && cluster_to_scan < FAT16_EOC) {
            u32_t current_dir_sector_start = _cluster_to_sector(cluster_to_scan);
            for (u32_t sec_offset = 0; sec_offset < fat16_info.boot_record.sectors_per_cluster; sec_offset++) {
                u32_t actual_sector = current_dir_sector_start + sec_offset;
                if (ata_read_sectors(actual_sector, 1, temp_sector)) return false; // Read error
                
                entries = (dir_entry_t *)temp_sector;
                for (u32_t j = 0; j < ENTRIES_PER_SECTOR; j++) {
                    if (entries[j].filename[0] == 0x00) return false; // End of directory
                    if (entries[j].filename[0] == 0xe5) continue;

                    if (_filename_matches(filename, &entries[j])) {
                        if (entry) *entry = entries[j];
                        if (dir_sector) *dir_sector = actual_sector;
                        if (dir_offset) *dir_offset = j * DIR_ENTRY_SIZE;
                        return true;
                    }
                }
            }
            cluster_to_scan = _get_next_cluster(cluster_to_scan);
        }
    }
    return false;
}

// Find a free directory entry
static bool _find_free_dir_entry(u32_t *dir_sector, u32_t *dir_offset) {
    dir_entry_t *entries;
    dir_entry_t *entry_ptr;
    if (current_cluster == 0) { // Root directory
        u32_t root_dir_total_entries = fat16_info.boot_record.root_dir_entries;
        u32_t entries_processed = 0;
        u32_t root_dir_num_sectors = (root_dir_total_entries * DIR_ENTRY_SIZE + SECTOR_SIZE -1) / SECTOR_SIZE;


        for (u32_t i = 0; i < root_dir_num_sectors; i++) {
            u32_t current_sector_abs = fat16_info.root_dir_start_sector + i;
            if (ata_read_sectors(current_sector_abs, 1, temp_sector)) return false; // Read error

            entries = (dir_entry_t *)temp_sector;
            for (u32_t j = 0; j < ENTRIES_PER_SECTOR; j++) {
                 if (entries_processed >= root_dir_total_entries && entries[j].filename[0] != 0x00 && entries[j].filename[0] != 0xe5) {
                    // This case implies root dir is full and we are past its allocated entries,
                    return false; 
                }
                if (entries[j].filename[0] == 0x00 || entries[j].filename[0] == 0xe5) {
                    *dir_sector = current_sector_abs;
                    *dir_offset = j * DIR_ENTRY_SIZE;
                    
                    entry_ptr = &entries[j]; // Pointer within temp_sector
                    u8_t original_first_byte = entry_ptr->filename[0];
                    mem_set(entry_ptr, 0, sizeof(dir_entry_t));
                    if (original_first_byte == 0x00) { // If it was a true end-of-dir marker
                        if ((j + 1) < ENTRIES_PER_SECTOR) {
                            (entry_ptr + 1)->filename[0] = 0x00; 
                        } // Else, if end of sector, next sector should start with 00 or be handled by caller
                    }
                    ata_write_sectors(*dir_sector, 1, temp_sector); // Write modified sector
                    
                    return true;
                }
                entries_processed++;
            }
        }
    } else { // Subdirectory (current_cluster >= 2)
        u16_t cluster_to_scan = current_cluster;
        u16_t prev_cluster_in_chain = 0; 

        while (cluster_to_scan >= 2 && cluster_to_scan < FAT16_EOC) {
            u32_t current_dir_sector_start = _cluster_to_sector(cluster_to_scan);
            for (u32_t sec_offset = 0; sec_offset < fat16_info.boot_record.sectors_per_cluster; ++sec_offset) {
                u32_t actual_sector = current_dir_sector_start + sec_offset;
                if (ata_read_sectors(actual_sector, 1, temp_sector)) return false; // Read error
                
                entries = (dir_entry_t *)temp_sector;
                for (u32_t j = 0; j < ENTRIES_PER_SECTOR; j++) {
                    if (entries[j].filename[0] == 0x00 || entries[j].filename[0] == 0xE5) {
                        *dir_sector = actual_sector;
                        *dir_offset = j * DIR_ENTRY_SIZE;
                        return true;
                    }
                }
            }
            prev_cluster_in_chain = cluster_to_scan;
            cluster_to_scan = _get_next_cluster(cluster_to_scan);
        }

        // If here, all existing clusters in the subdirectory are full. Try to extend.
        if (prev_cluster_in_chain != 0) { // Check if there was a valid chain to extend
            u16_t new_cluster = _find_free_cluster(); // This marks new_cluster as EOC in FAT
            if (new_cluster != 0) { // Found a free cluster
                _update_fat_entry(prev_cluster_in_chain, new_cluster); // Link previous to new

                // Zero out the new cluster for the directory
                u32_t new_cluster_sector_start = _cluster_to_sector(new_cluster);
                mem_set(temp_sector, 0, SECTOR_SIZE); 
                for (u32_t s_off = 0; s_off < fat16_info.boot_record.sectors_per_cluster; ++s_off) {
                    ata_write_sectors(new_cluster_sector_start + s_off, 1, temp_sector);
                }

                // The first entry of this new cluster is now free and zeroed.
                *dir_sector = new_cluster_sector_start; 
                *dir_offset = 0; 
                return true;
            }
        }
    }
    return false; // No free entry found / could not extend
}
