#include "fat16.h"
#include "ata-driver.h"
#include "vga-driver.h"
#include "../lib/memory.h"
#include "../lib/string.h"

// Global filesystem information
static fat16_info_t fat16_info;
static u8_t temp_sector[SECTOR_SIZE];

static u16_t _create_fat_date();
static u16_t _create_fat_time();
static void _filename_to_fat83(const char *filename, u8_t *name, u8_t *ext);
static bool _filename_matches(const char *filename, const dir_entry_t *entry);
static u16_t _find_free_cluster();
static void _update_fat_entry(u16_t cluster, u16_t value);
static u16_t _get_next_cluster(u16_t cluster);
static void _update_fat_entry(u16_t cluster, u16_t value);
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
    
    mem_cpy(fat16_info.boot_record.oem_name, "MYFATOS ", 8);
    
    fat16_info.boot_record.bytes_per_sector = SECTOR_SIZE;
    fat16_info.boot_record.sectors_per_cluster = 4;     // 4 sectors per cluster (2KB)
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
    
    mem_cpy(fat16_info.boot_record.volume_label, "MYVOLUME   ", 11);
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
    
    // Prepare directory entry
    mem_set(&file.entry, 0, sizeof(dir_entry_t));
    
    // Set filename
    _filename_to_fat83(filename, file.entry.filename, file.entry.extension);
    
    // Set attributes and times
    file.entry.attributes = ATTR_ARCHIVE;
    file.entry.creation_time = _create_fat_time();
    file.entry.creation_date = _create_fat_date();
    file.entry.last_access_date = file.entry.creation_date;
    file.entry.last_modification_time = file.entry.creation_time;
    file.entry.last_modification_date = file.entry.creation_date;
    
    // File initially has no clusters
    file.entry.first_cluster_low = 0;
    file.entry.file_size = 0;
    
    // Save directory information
    file.dir_sector = dir_sector;
    file.dir_offset = dir_offset;
    file.position = 0;
    file.is_open = true;
    
    // Write the directory entry
    ata_read_sectors(dir_sector, 1, temp_sector);
    mem_cpy(temp_sector + dir_offset, &file.entry, sizeof(dir_entry_t));
    ata_write_sectors(dir_sector, 1, temp_sector);
    
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
u32_t fat16_read(file_t *file, void *buffer, u32_t size) {
    if (!file->is_open || file->position >= file->entry.file_size) {
        return 0;  // File not open or at end of file
    }
    
    // Don't read past the end of the file
    if (file->position + size > file->entry.file_size) {
        size = file->entry.file_size - file->position;
    }
    
    u32_t bytes_read = 0;
    u8_t *dest = (u8_t *)buffer;
    
    // If no clusters allocated, nothing to read
    if (file->entry.first_cluster_low == 0) {
        return 0;
    }
    
    // Find the right cluster
    u16_t cluster = file->entry.first_cluster_low;
    u32_t pos_in_file = 0;
    
    while (pos_in_file + fat16_info.cluster_size_bytes <= file->position) {
        cluster = _get_next_cluster(cluster);
        if (cluster >= FAT16_EOC) return 0;  // Unexpected end of chain
        pos_in_file += fat16_info.cluster_size_bytes;
    }
    
    // Position within the current cluster
    u32_t cluster_offset = file->position - pos_in_file;
    
    // Read data
    while (bytes_read < size) {
        // Read current cluster
        u32_t sector = _cluster_to_sector(cluster);
        
        // Calculate how much to read from this cluster
        u32_t bytes_left_in_cluster = fat16_info.cluster_size_bytes - cluster_offset;
        u32_t bytes_to_read = size - bytes_read;
        if (bytes_to_read > bytes_left_in_cluster) {
            bytes_to_read = bytes_left_in_cluster;
        }
        
        // Calculate sector and offset
        u32_t sector_offset = cluster_offset % SECTOR_SIZE;
        u32_t sector_index = cluster_offset / SECTOR_SIZE;
        
        // Read data sector by sector
        while (bytes_to_read > 0) {
            // Read the sector
            ata_read_sectors(sector + sector_index, 1, temp_sector);
            
            // Calculate how much to read from this sector
            u32_t bytes_from_sector = SECTOR_SIZE - sector_offset;
            if (bytes_from_sector > bytes_to_read) {
                bytes_from_sector = bytes_to_read;
            }
            
            // Copy data
            mem_cpy(dest, temp_sector + sector_offset, bytes_from_sector);
            
            // Update pointers
            dest += bytes_from_sector;
            bytes_read += bytes_from_sector;
            bytes_to_read -= bytes_from_sector;
            
            // Move to next sector
            sector_index++;
            sector_offset = 0;
        }
        
        // Move to next cluster if needed
        if (bytes_read < size) {
            cluster = _get_next_cluster(cluster);
            if (cluster >= FAT16_EOC) break;  // End of chain
            cluster_offset = 0;
        }
    }
    
    // Update file position
    file->position += bytes_read;
    file->current_cluster = cluster;
    
    return bytes_read;
}

// Write to a file
u32_t fat16_write(file_t *file, const void *buffer, u32_t size) {
    if (!file->is_open) {
        return 0;  // File not open
    }
    
    u32_t bytes_written = 0;
    const u8_t *src = (const u8_t *)buffer;
    
    // Allocate first cluster if needed
    if (file->entry.first_cluster_low == 0 && size > 0) {
        u16_t cluster = _find_free_cluster();
        if (cluster == 0) return 0;  // No free clusters
        
        file->entry.first_cluster_low = cluster;
        file->current_cluster = cluster;
        
        // Mark cluster as end of chain
        _update_fat_entry(cluster, FAT16_EOC);
    }
    
    // Find the right cluster
    u16_t cluster = file->entry.first_cluster_low;
    u32_t pos_in_file = 0;
    
    while (pos_in_file + fat16_info.cluster_size_bytes <= file->position) {
        u16_t next_cluster = _get_next_cluster(cluster);
        
        // If we reach the end of chain but need more clusters
        if (next_cluster >= FAT16_EOC) {
            // Allocate a new cluster
            u16_t new_cluster = _find_free_cluster();
            if (new_cluster == 0) return 0;  // No free clusters
            
            // Link it to the chain
            _update_fat_entry(cluster, new_cluster);
            _update_fat_entry(new_cluster, FAT16_EOC);
            
            cluster = new_cluster;
        } else {
            cluster = next_cluster;
        }
        
        pos_in_file += fat16_info.cluster_size_bytes;
    }
    
    // Position within the current cluster
    u32_t cluster_offset = file->position - pos_in_file;
    
    // Write data
    while (bytes_written < size) {
        // Calculate how much to write to this cluster
        u32_t bytes_left_in_cluster = fat16_info.cluster_size_bytes - cluster_offset;
        u32_t bytes_to_write = size - bytes_written;
        if (bytes_to_write > bytes_left_in_cluster) {
            bytes_to_write = bytes_left_in_cluster;
        }
        
        // Calculate sector and offset
        u32_t sector = _cluster_to_sector(cluster);
        u32_t sector_offset = cluster_offset % SECTOR_SIZE;
        u32_t sector_index = cluster_offset / SECTOR_SIZE;
        
        // Write data sector by sector
        while (bytes_to_write > 0) {
            // If writing a partial sector, read it first
            if (sector_offset > 0 || bytes_to_write < SECTOR_SIZE) {
                ata_read_sectors(sector + sector_index, 1, temp_sector);
            }
            
            // Calculate how much to write to this sector
            u32_t bytes_to_sector = SECTOR_SIZE - sector_offset;
            if (bytes_to_sector > bytes_to_write) {
                bytes_to_sector = bytes_to_write;
            }
            
            // Copy data
            mem_cpy(temp_sector + sector_offset, src, bytes_to_sector);
            
            // Write the sector
            ata_write_sectors(sector + sector_index, 1, temp_sector);
            
            // Update pointers
            src += bytes_to_sector;
            bytes_written += bytes_to_sector;
            bytes_to_write -= bytes_to_sector;
            
            // Move to next sector
            sector_index++;
            sector_offset = 0;
        }
        
        // If we need another cluster
        if (bytes_written < size) {
            u16_t next_cluster = _get_next_cluster(cluster);
            
            // If end of chain, allocate a new cluster
            if (next_cluster >= FAT16_EOC) {
                u16_t new_cluster = _find_free_cluster();
                if (new_cluster == 0) break;  // No free clusters
                
                // Link it to the chain
                _update_fat_entry(cluster, new_cluster);
                _update_fat_entry(new_cluster, FAT16_EOC);
                
                cluster = new_cluster;
            } else {
                cluster = next_cluster;
            }
            
            cluster_offset = 0;
        }
    }
    
    // Update file position and size
    file->position += bytes_written;
    if (file->position > file->entry.file_size) {
        file->entry.file_size = file->position;
    }
    
    file->current_cluster = cluster;
    
    // Update directory entry
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
    
    // Free clusters
    u16_t cluster = entry.first_cluster_low;
    while (cluster >= 2 && cluster < FAT16_EOC) {
        u16_t next_cluster = _get_next_cluster(cluster);
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

/* =============================== Private Functions =============================== */

// Initialize date/time values
static u16_t _create_fat_date() {
    // Just a default value: 2023-01-01
    return (43 << 9) | (1 << 5) | 1;  // Year(0-127) + 1980, Month(1-12), Day(1-31)
}

static u16_t _create_fat_time() {
    // Default time: 12:00:00
    return (12 << 11) | (0 << 5) | 0;  // Hour(0-23), Minute(0-59), Second/2(0-29)
}

// Convert 8.3 filename to FAT format (space padded)
static void _filename_to_fat83(const char *filename, u8_t *name, u8_t *ext) {  
    // Initialize with spaces
    for (int i = 0; i < 8; i++) name[i] = ' ';
    for (int i = 0; i < 3; i++) ext[i] = ' ';
    
    // Copy name part
    for (int i = 0; i < 8 && filename[i] && filename[i] != '.'; i++) {
        name[i] = str_to_upper(filename[i]);
    }
    
    // Find extension
    const char *extension = str_chr(filename, '.');
    if (extension) {
        extension++; // Skip the '.'
        // Copy extension part
        for (int i = 0; i < 3 && extension[i]; i++) {
            ext[i] = str_to_upper(extension[i]);
        }
    }
}

// Compare a filename with a directory entry
static bool _filename_matches(const char *filename, const dir_entry_t *entry) {
    u8_t name[8], ext[3];
    _filename_to_fat83(filename, name, ext);
    
    // Compare name and extension
    for (int i = 0; i < 8; i++) {
        if (name[i] != entry->filename[i]) return false;
    }
    for (int i = 0; i < 3; i++) {
        if (ext[i] != entry->extension[i]) return false;
    }
    
    return true;
}

// Find a free cluster in the FAT
static u16_t _find_free_cluster() {
    u16_t fat_sector = fat16_info.fat_start_sector;
    u16_t cluster;
    u16_t *fat_entries;
    
    // Search through the FAT for a free cluster
    for (u32_t i = 0; i < fat16_info.boot_record.fat_size_sectors; i++) {
        ata_read_sectors(fat_sector + i, 1, temp_sector);
        fat_entries = (u16_t *)temp_sector;
        
        for (u32_t j = 0; j < SECTOR_SIZE / 2; j++) {
            cluster = i * (SECTOR_SIZE / 2) + j;
            // Skip first two reserved entries and don't go beyond valid clusters
            if (cluster >= 2 && fat_entries[j] == FAT_ENTRY_FREE) {
                return cluster;
            }
        }
    }
    
    return 0; // No free clusters
}

// Update FAT entry for a cluster
static void _update_fat_entry(u16_t cluster, u16_t value) {
    u32_t fat_offset = cluster * 2; // Each FAT entry is 2 bytes
    u32_t fat_sector = fat16_info.fat_start_sector + (fat_offset / SECTOR_SIZE);
    u32_t entry_offset = fat_offset % SECTOR_SIZE;
    
    // Read the sector containing the FAT entry
    ata_read_sectors(fat_sector, 1, temp_sector);
    
    // Update the FAT entry
   *((u16_t *)(temp_sector + entry_offset)) = value;
    
    // Write the updated sector back
    ata_write_sectors(fat_sector, 1, temp_sector);
    
    // Also update the second FAT if it exists
    if (fat16_info.boot_record.num_fats > 1) {
        u32_t fat2_sector = fat_sector + fat16_info.boot_record.fat_size_sectors;
        ata_write_sectors(fat2_sector, 1, temp_sector);
    }
}

// Get the next cluster in a chain
static u16_t _get_next_cluster(u16_t cluster) {
    u32_t fat_offset = cluster * 2; // Each FAT entry is 2 bytes
    u32_t fat_sector = fat16_info.fat_start_sector + (fat_offset / SECTOR_SIZE);
    u32_t entry_offset = fat_offset % SECTOR_SIZE;
    
    // Read the sector containing the FAT entry
    ata_read_sectors(fat_sector, 1, temp_sector);
    
    // Return the FAT entry
    return *((u16_t *)(temp_sector + entry_offset));
}

// Convert cluster number to sector number
static u32_t _cluster_to_sector(u16_t cluster) {
    return fat16_info.data_start_sector + ((cluster - 2) * fat16_info.boot_record.sectors_per_cluster);
}

// Find a file in the root directory
static bool _find_file(const char *filename, dir_entry_t *entry, u32_t *dir_sector, u32_t *dir_offset) {
    u32_t root_sectors = ((fat16_info.boot_record.root_dir_entries * DIR_ENTRY_SIZE) + 
                        (fat16_info.boot_record.bytes_per_sector - 1)) / 
                        fat16_info.boot_record.bytes_per_sector;
    
    for (u32_t i = 0; i < root_sectors; i++) {
        ata_read_sectors(fat16_info.root_dir_start_sector + i, 1, temp_sector);
        
        dir_entry_t *entries = (dir_entry_t *)temp_sector;
        for (u32_t j = 0; j < ENTRIES_PER_SECTOR; j++) {
            // Skip unused entries
            if (entries[j].filename[0] == 0 || entries[j].filename[0] == 0xe5) {
                continue;
            }
            
            // Skip directory and volume label entries
            if (entries[j].attributes & (ATTR_DIRECTORY | ATTR_VOLUME_ID)) {
                continue;
            }
            
            // Check if filename matches
            if (_filename_matches(filename, &entries[j])) {
                if (entry) *entry = entries[j];
                if (dir_sector) *dir_sector = fat16_info.root_dir_start_sector + i;
                if (dir_offset) *dir_offset = j * DIR_ENTRY_SIZE;
                return true;
            }
        }
    }
    
    return false;
}

// Find a free directory entry
static bool _find_free_dir_entry(u32_t *dir_sector, u32_t *dir_offset) {
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
                return true;
            }
        }
    }
    
    return false;
}
