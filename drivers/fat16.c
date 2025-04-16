#include "fat16.h"
#include "../lib/string.h"
#include "../lib/types.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define SECTOR_SIZE 512  // Standard sector size

// Error codes
#define FAT16_ERROR_INVALID_FILESYSTEM    -1
#define FAT16_ERROR_NOT_FOUND             -2
#define FAT16_ERROR_IO                    -3
#define FAT16_ERROR_NO_MEMORY             -4
#define FAT16_ERROR_INVALID_PARAMETER     -5

// Default values for date/time fields (January 1, 1980, 00:00:00)
#define DEFAULT_FAT_DATE 0x0021  // 01:01:1980 in FAT format
#define DEFAULT_FAT_TIME 0x0000  // 00:00:00 in FAT format

static u8_t sector_buffer[SECTOR_SIZE];

static u32_t _fat16_fat_offset(u16_t cluster);
static int _read_sector(fat16_filesystem_t *fs, u32_t sector);
static int _write_sector(fat16_filesystem_t *fs, u32_t sector);
static int _find_file_in_dir(fat16_filesystem_t *fs, const char *filename, fat16_dir_entry_t *dir_entry, u32_t first_dir_sector, u32_t dir_sectors);
static int _fat16_set_fat_entry(fat16_filesystem_t *fs, u16_t cluster, u16_t value);
static u16_t _fat16_find_free_cluster(fat16_filesystem_t *fs);
static u16_t _fat16_allocate_cluster(fat16_filesystem_t *fs, u16_t prev_cluster);
static int _fat16_update_dir_entry(fat16_filesystem_t *fs, const char *filename, fat16_dir_entry_t *new_entry);

/* =============================== Public Functions =============================== */

// Initialize the FAT16 filesystem
int fat16_init(fat16_filesystem_t *fs, void *device_data,
                int (*read_sector)(void *device_data, u32_t sector, u8_t *buffer, u32_t sector_size),
                int (*write_sector)(void *device_data, u32_t sector, const u8_t *buffer, u32_t sector_size)) {
    
    if (!fs || !read_sector) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Initialize function pointers and device data
    fs->device_data = device_data;
    fs->read_sector = read_sector;
    fs->write_sector = write_sector;
    
    // Read the boot sector
    if (read_sector(device_data, 0, (u8_t*)&fs->bpb, SECTOR_SIZE) < 0) {
        return FAT16_ERROR_IO;
    }
    
    // Verify this is a FAT16 volume
    if (fs->bpb.bytes_per_sector == 0 || 
        (fs->bpb.bytes_per_sector != 512 && fs->bpb.bytes_per_sector != 1024 && 
         fs->bpb.bytes_per_sector != 2048 && fs->bpb.bytes_per_sector != 4096)) {
        return FAT16_ERROR_INVALID_FILESYSTEM;
    }
    
    // Calculate important filesystem parameters
    fs->sectors_per_fat = fs->bpb.sectors_per_fat;
    fs->first_fat_sector = fs->bpb.reserved_sectors;
    fs->root_dir_entries = fs->bpb.root_entries;
    
    // The root directory follows the FATs
    fs->root_dir_sector = fs->first_fat_sector + (fs->bpb.num_fats * fs->sectors_per_fat);
    
    // Calculate the size of the root directory in sectors
    u32_t root_dir_sectors = ((fs->root_dir_entries * 32) + (fs->bpb.bytes_per_sector - 1)) / fs->bpb.bytes_per_sector;
    
    // First data sector (cluster 2) follows the root directory
    fs->first_data_sector = fs->root_dir_sector + root_dir_sectors;
    
    // Calculate the total number of data sectors
    u32_t total_sectors = fs->bpb.total_sectors_16;
    if (total_sectors == 0) {
        total_sectors = fs->bpb.total_sectors_32;
    }
    
    fs->data_sectors = total_sectors - fs->first_data_sector;
    
    // Calculate the total number of clusters
    fs->total_clusters = fs->data_sectors / fs->bpb.sectors_per_cluster;
    
    // Verify this is indeed a FAT16 volume (not FAT12 or FAT32)
    if (fs->total_clusters < 4085) {
        // This is actually a FAT12 volume
        return FAT16_ERROR_INVALID_FILESYSTEM;
    } else if (fs->total_clusters >= 65525) {
        // This is actually a FAT32 volume
        return FAT16_ERROR_INVALID_FILESYSTEM;
    }
    
    // Allocate memory for FAT cache (optional, could be done on demand)
    fs->fat_table = NULL;  // Not caching entire FAT for now
    
    return 0;
}

// Get the next cluster in a cluster chain
u16_t fat16_get_next_cluster(fat16_filesystem_t *fs, u16_t cluster) {
    // Calculate FAT parameters
    u32_t fat_offset = _fat16_fat_offset(cluster);
    u32_t fat_sector = fs->first_fat_sector + (fat_offset / fs->bpb.bytes_per_sector);
    u32_t ent_offset = fat_offset % fs->bpb.bytes_per_sector;
    
    // Read the FAT sector
    if (read_sector(fs, fat_sector) < 0) {
        return FAT16_ERROR_IO;
    }
    
    // Extract the FAT entry value
    u16_t next_cluster = *(u16_t*)&sector_buffer[ent_offset];
    
    return next_cluster;
}

// Convert a cluster number to a sector number
u32_t fat16_cluster_to_sector(fat16_filesystem_t *fs, u16_t cluster) {
    // Cluster numbers start at 2
    if (cluster < 2) {
        return 0;
    }
    
    return ((cluster - 2) * fs->bpb.sectors_per_cluster) + fs->first_data_sector;
}

// Parse a FAT16 date field
void fat16_parse_date(u16_t fat_date, u16_t *year, u8_t *month, u8_t *day) {
    if (year) *year = 1980 + ((fat_date >> 9) & 0x7F);
    if (month) *month = (fat_date >> 5) & 0x0F;
    if (day) *day = fat_date & 0x1F;
}

// Parse a FAT16 time field
void fat16_parse_time(u16_t fat_time, u8_t *hour, u8_t *minute, u8_t *second) {
    if (hour) *hour = (fat_time >> 11) & 0x1F;
    if (minute) *minute = (fat_time >> 5) & 0x3F;
    if (second) *second = (fat_time & 0x1F) * 2;
}

// Open a file by name
int fat16_open_file(fat16_filesystem_t *fs, const char *filename, fat16_file_t *file) {
    if (!fs || !filename || !file) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Initialize file structure
    mem_set(file, 0, sizeof(fat16_file_t));
    file->fs = fs;
    
    // Calculate the size of the root directory in sectors
    u32_t root_dir_sectors = ((fs->root_dir_entries * 32) + (fs->bpb.bytes_per_sector - 1)) / fs->bpb.bytes_per_sector;
    
    // Find the file in the root directory
    fat16_dir_entry_t dir_entry;
    int result = _find_file_in_dir(fs, filename, &dir_entry, fs->root_dir_sector, root_dir_sectors);
    
    if (result < 0) {
        return result;
    }
    
    // Set up file properties
    file->first_cluster = dir_entry.first_cluster;
    file->current_cluster = dir_entry.first_cluster;
    file->current_position = 0;
    file->file_size = dir_entry.file_size;
    file->attributes = dir_entry.attributes;
    file->is_open = true;
    
    // Save the filename
    if (fat16_to_short_filename(filename, file->filename) < 0) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    return 0;
}

// Read data from a file
int fat16_read_file(fat16_file_t *file, void *buffer, u32_t size) {
    if (!file || !buffer || !file->is_open) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    fat16_filesystem_t *fs = file->fs;
    u8_t *dest = (u8_t *)buffer;
    u32_t bytes_read = 0;
    u32_t bytes_left = size;
    u32_t bytes_per_cluster = fs->bpb.bytes_per_sector * fs->bpb.sectors_per_cluster;
    
    // Don't read past the end of the file
    if (file->current_position + size > file->file_size) {
        bytes_left = file->file_size - file->current_position;
    }
    
    // While we have bytes to read and we haven't hit EOF
    while (bytes_left > 0 && file->current_cluster >= 2 && file->current_cluster < FAT16_EOF) {
        // Calculate position within cluster and sector
        u32_t cluster_offset = file->current_position % bytes_per_cluster;
        u32_t start_sector = fat16_cluster_to_sector(fs, file->current_cluster);
        u32_t sector_index = cluster_offset / fs->bpb.bytes_per_sector;
        u32_t sector_offset = cluster_offset % fs->bpb.bytes_per_sector;
        
        // Read the sector
        if (read_sector(fs, start_sector + sector_index) < 0) {
            return FAT16_ERROR_IO;
        }
        
        // Calculate how many bytes we can read from this sector
        u32_t bytes_this_sector = fs->bpb.bytes_per_sector - sector_offset;
        if (bytes_this_sector > bytes_left) {
            bytes_this_sector = bytes_left;
        }
        
        // Copy the data
        mem_cpy(dest + bytes_read, sector_buffer + sector_offset, bytes_this_sector);
        bytes_read += bytes_this_sector;
        bytes_left -= bytes_this_sector;
        file->current_position += bytes_this_sector;
        
        // If we've reached the end of a cluster, move to the next one
        if ((file->current_position % bytes_per_cluster) == 0) {
            file->current_cluster = fat16_get_next_cluster(fs, file->current_cluster);
            
            // Check for end of chain or error
            if (file->current_cluster >= FAT16_EOF || file->current_cluster < 2) {
                break;
            }
        }
    }
    
    return bytes_read;
}

int fat16_write_file(fat16_file_t *file, const void *buffer, u32_t size) {
    if (!file || !buffer || !file->is_open) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // If size is 0, nothing to write
    if (size == 0) {
        return 0;
    }
    
    fat16_filesystem_t *fs = file->fs;
    u32_t bytes_per_cluster = fs->bpb.sectors_per_cluster * fs->bpb.bytes_per_sector;
    u32_t bytes_written = 0;
    u32_t remaining = size;
    const u8_t *data = (const u8_t *)buffer;
    
    // Get current cluster position
    u16_t current_cluster = file->current_cluster;
    u32_t current_position_in_cluster = file->current_position % bytes_per_cluster;
    
    // If this is a new file or we're at the beginning
    if (current_cluster == 0) {
        if (file->first_cluster == 0) {
            // Allocate first cluster for a new file
            current_cluster = fat16_allocate_cluster(fs, 0);
            if (current_cluster == 0) {
                return FAT16_ERROR_NO_MEMORY;
            }
            
            // Update file with first cluster
            file->first_cluster = current_cluster;
        } else {
            // Start from the beginning of existing file
            current_cluster = file->first_cluster;
        }
        
        file->current_cluster = current_cluster;
    }
    
    // Write data in cluster-sized chunks
    while (remaining > 0) {
        // Calculate how much we can write in this cluster
        u32_t cluster_remaining = bytes_per_cluster - current_position_in_cluster;
        u32_t write_size = (remaining < cluster_remaining) ? remaining : cluster_remaining;
        
        // Calculate the sector for the current cluster
        u32_t cluster_sector = fat16_cluster_to_sector(fs, current_cluster);
        
        // Process each sector in the cluster that needs modification
        for (u32_t i = 0; i < fs->bpb.sectors_per_cluster; i++) {
            u32_t sector_offset = i * fs->bpb.bytes_per_sector;
            
            // Check if this sector needs to be modified
            if (current_position_in_cluster < (i + 1) * fs->bpb.bytes_per_sector &&
                current_position_in_cluster + write_size > i * fs->bpb.bytes_per_sector) {
                
                // Calculate offset within this sector
                u32_t sector_pos = 0;
                if (current_position_in_cluster > i * fs->bpb.bytes_per_sector) {
                    sector_pos = current_position_in_cluster - (i * fs->bpb.bytes_per_sector);
                }
                
                // Calculate how much to write to this sector
                u32_t sector_write = fs->bpb.bytes_per_sector - sector_pos;
                if (sector_write > remaining) sector_write = remaining;
                
                // For partial sector writes, read the sector first
                if (sector_pos > 0 || sector_write < fs->bpb.bytes_per_sector) {
                    if (read_sector(fs, cluster_sector + i) != 0) {
                        return FAT16_ERROR_IO;
                    }
                    
                    // Use the read buffer directly (assumed to be stored in fs)
                    memcpy((u8_t*)fs + sector_pos, data, sector_write);
                } else {
                    // For full sector writes, copy directly to the buffer
                    memcpy((u8_t*)fs, data, sector_write);
                }
                
                // Write the sector back
                if (write_sector(fs, cluster_sector + i) != 0) {
                    return FAT16_ERROR_IO;
                }
                
                // Update pointers
                data += sector_write;
                bytes_written += sector_write;
                remaining -= sector_write;
                file->current_position += sector_write;
                
                if (remaining == 0) break;
            }
        }
        
        current_position_in_cluster = 0; // Reset for next cluster
        
        // If we've written all data, we're done
        if (remaining == 0) {
            break;
        }
        
        // Get next cluster or allocate a new one
        u16_t next_cluster = fat16_get_next_cluster(fs, current_cluster);
        if (next_cluster >= FAT16_EOF) { // End of chain marker in FAT16
            // Allocate new cluster and link to current
            next_cluster = fat16_allocate_cluster(fs, current_cluster);
            if (next_cluster == 0) {
                // Couldn't allocate more clusters, return what we've written so far
                if (file->current_position > file->file_size) {
                    file->file_size = file->current_position;
                    
                    // Create a directory entry to update
                    fat16_dir_entry_t dir_entry;
                    memset(&dir_entry, 0, sizeof(fat16_dir_entry_t));
                    
                    // Copy basic info from file
                    dir_entry.first_cluster = file->first_cluster;
                    dir_entry.file_size = file->file_size;
                    
                    // Update the directory entry
                    fat16_update_dir_entry(fs, file->filename, &dir_entry);
                }
                return bytes_written;
            }
        }
        
        current_cluster = next_cluster;
        file->current_cluster = current_cluster;
    }
    
    // Update file size in directory entry if needed
    if (file->current_position > file->file_size) {
        file->file_size = file->current_position;
        
        // Create a directory entry to update
        fat16_dir_entry_t dir_entry;
        memset(&dir_entry, 0, sizeof(fat16_dir_entry_t));
        
        // Copy basic info from file
        dir_entry.first_cluster = file->first_cluster;
        dir_entry.file_size = file->file_size;
        
        // Update the directory entry
        fat16_update_dir_entry(fs, file->filename, &dir_entry);
    }
    
    return bytes_written;
}

// Close a file
int fat16_close_file(fat16_file_t *file) {
    if (!file || !file->is_open) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    file->is_open = false;
    return 0;
}

// Open a directory
int fat16_open_dir(fat16_filesystem_t *fs, const char *path, fat16_dir_t *dir) {
    if (!fs || !dir) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Initialize directory structure
    mem_set(dir, 0, sizeof(fat16_dir_t));
    dir->fs = fs;
    
    // Check if this is the root directory
    if (!path || path[0] == '/' || path[0] == '\0') {
        dir->is_root = true;
        dir->first_cluster = 0; // Root directory doesn't use clusters in FAT16
    } else {
        // Non-root directories would need to be found in the parent directory
        // This would require parsing paths - not implemented for now
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    return 0;
}

// Read the next directory entry
int fat16_read_dir(fat16_dir_t *dir, fat16_dir_entry_t *entry) {
    if (!dir || !entry || !dir->fs) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    fat16_filesystem_t *fs = dir->fs;
    
    if (dir->is_root) {
        // Calculate the size of the root directory in sectors
        u32_t root_dir_sectors = ((fs->root_dir_entries * 32) + (fs->bpb.bytes_per_sector - 1)) / fs->bpb.bytes_per_sector;
        
        // Calculate sector and offset
        u32_t entries_per_sector = fs->bpb.bytes_per_sector / sizeof(fat16_dir_entry_t);
        u32_t sector_index = dir->current_entry / entries_per_sector;
        u32_t entry_offset = dir->current_entry % entries_per_sector;
        
        // Check if we're past the end of the root directory
        if (sector_index >= root_dir_sectors) {
            return 0; // End of directory
        }
        
        // Read the sector
        if (read_sector(fs, fs->root_dir_sector + sector_index) < 0) {
            return FAT16_ERROR_IO;
        }
        
        // Get the entry
        fat16_dir_entry_t *dir_entry = (fat16_dir_entry_t *)&sector_buffer[entry_offset * sizeof(fat16_dir_entry_t)];
        
        // Check if this is the end of directory entries
        if (dir_entry->name[0] == 0) {
            return 0; // End of directory
        }
        
        // Increment entry counter for next read
        dir->current_entry++;
        
        // Skip deleted entries
        if (dir_entry->name[0] == 0xE5) {
            return fat16_read_dir(dir, entry);
        }
        
        // Skip long filename entries (we're not handling those yet)
        if ((dir_entry->attributes & FAT_ATTR_LFN) == FAT_ATTR_LFN) {
            return fat16_read_dir(dir, entry);
        }
        
        // Return the entry
        mem_cpy(entry, dir_entry, sizeof(fat16_dir_entry_t));
        return 1;
    } else {
        // For non-root directories, we'd need to follow clusters - not implemented yet
        return FAT16_ERROR_INVALID_PARAMETER;
    }
}

// Close a directory
int fat16_close_dir(fat16_dir_t *dir) {
    if (!dir) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Reset the directory structure
    mem_set(dir, 0, sizeof(fat16_dir_t));
    return 0;
}

// Check if a filename is valid for FAT16
bool fat16_is_valid_filename(const char *filename) {
    if (!filename || !*filename) {
        return false;
    }
    
    // Check length
    u32_t len = strlen(filename);
    if (len > 12) { // 8 for name + 1 for dot + 3 for extension
        return false;
    }
    
    // Check illegal characters
    const char *invalid_chars = "<>:\"/\\|?*";
    for (u32_t i = 0; i < len; i++) {
        if (strchr(invalid_chars, filename[i]) || (unsigned char)filename[i] < 32) {
            return false;
        }
    }
    
    // Check if it has at most one dot
    int dot_count = 0;
    for (u32_t i = 0; i < len; i++) {
        if (filename[i] == '.') {
            dot_count++;
        }
    }
    
    if (dot_count > 1) {
        return false;
    }
    
    return true;
}

// Convert a filename to 8.3 format
int fat16_to_short_filename(const char *input, char *output) {
    if (!input || !output) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Check if the input filename is valid
    if (!fat16_is_valid_filename(input)) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Initialize output with spaces
    for (int i = 0; i < 11; i++) {
        output[i] = ' ';
    }
    output[11] = '\0';
    
    // Find the dot if present
    const char *dot = strchr(input, '.');
    u32_t name_len = dot ? (dot - input) : strlen(input);
    
    // Copy the name (up to 8 characters)
    for (u32_t i = 0; i < name_len && i < 8; i++) {
        output[i] = toupper(input[i]);
    }
    
    // Copy the extension if present (up to 3 characters)
    if (dot && *(dot + 1)) {
        for (u32_t i = 0; i < 3 && *(dot + 1 + i); i++) {
            output[8 + i] = toupper(dot[1 + i]);
        }
    }
    
    // Format with dot for display purposes
    for (int i = 11; i > 8; i--) {
        output[i] = output[i - 1];
    }
    output[8] = '.';
    
    // Remove trailing spaces and dot if no extension
    if (output[9] == ' ') {
        output[8] = '\0';
    } else {
        output[12] = '\0';
    }
    
    return 0;
}

// Create a new file
int fat16_create_file(fat16_filesystem_t *fs, const char *filename, u8_t attributes) {
    if (!fs || !filename) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Check if the file already exists
    fat16_file_t file;
    if (fat16_open_file(fs, filename, &file) == 0) {
        fat16_close_file(&file);
        return FAT16_ERROR_INVALID_PARAMETER; // File already exists
    }
    
    // Calculate the size of the root directory in sectors
    u32_t root_dir_sectors = ((fs->root_dir_entries * 32) + (fs->bpb.bytes_per_sector - 1)) / fs->bpb.bytes_per_sector;
    
    // Find a free directory entry
    fat16_dir_entry_t *free_entry = NULL;
    u32_t free_sector = 0;
    u32_t free_offset = 0;
    
    // Loop through all sectors in the root directory
    for (u32_t sector = 0; sector < root_dir_sectors; sector++) {
        if (read_sector(fs, fs->root_dir_sector + sector) < 0) {
            return FAT16_ERROR_IO;
        }
        
        // Each sector contains multiple directory entries
        for (u32_t entry = 0; entry < fs->bpb.bytes_per_sector / sizeof(fat16_dir_entry_t); entry++) {
            fat16_dir_entry_t *current = (fat16_dir_entry_t *)&sector_buffer[entry * sizeof(fat16_dir_entry_t)];
            
            // Check if this entry is free (deleted or empty)
            if (current->name[0] == 0xE5 || current->name[0] == 0) {
                free_entry = current;
                free_sector = fs->root_dir_sector + sector;
                free_offset = entry * sizeof(fat16_dir_entry_t);
                break;
            }
        }
        
        if (free_entry) {
            break;
        }
    }
    
    if (!free_entry) {
        return FAT16_ERROR_INVALID_FILESYSTEM; // Directory is full
    }
    
    // Convert filename to 8.3 format
    char short_name[12];
    if (fat16_to_short_filename(filename, short_name) < 0) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Fill in the directory entry
    mem_set(free_entry, 0, sizeof(fat16_dir_entry_t));
    
    // Parse the 8.3 filename
    char *dot = strchr(short_name, '.');
    int name_len = dot ? (dot - short_name) : strlen(short_name);
    
    // Fill name part (padded with spaces)
    for (int i = 0; i < 8; i++) {
        free_entry->name[i] = (i < name_len) ? toupper(short_name[i]) : ' ';
    }
    
    // Fill extension part (padded with spaces)
    for (int i = 0; i < 3; i++) {
        free_entry->ext[i] = (dot && dot[1+i]) ? toupper(dot[1+i]) : ' ';
    }
    
    // Set attributes
    free_entry->attributes = attributes;
    
    // Set creation/modification time and date with default values
    // Using January 1, 2023, 12:00:00
    free_entry->creation_date = DEFAULT_FAT_DATE;
    free_entry->creation_time = DEFAULT_FAT_TIME;
    free_entry->creation_time_tenths = 0;
    free_entry->last_access_date = DEFAULT_FAT_DATE;
    free_entry->last_mod_date = DEFAULT_FAT_DATE;
    free_entry->last_mod_time = DEFAULT_FAT_TIME;
    
    // No cluster assigned yet
    free_entry->first_cluster = 0;
    free_entry->first_cluster_high = 0;
    free_entry->file_size = 0;
    
    // Write the updated sector back
    if (_write_sector(fs, free_sector) < 0) {
        return FAT16_ERROR_IO;
    }
    
    return 0;
}

// Delete a file
int fat16_delete_file(fat16_filesystem_t *fs, const char *filename) {
    if (!fs || !filename) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Find the file
    fat16_file_t file;
    int result = fat16_open_file(fs, filename, &file);
    if (result < 0) {
        return result;
    }
    
    // Can't delete directories with this function
    if (file.attributes & FAT_ATTR_DIRECTORY) {
        fat16_close_file(&file);
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Free all clusters in the file
    u16_t cluster = file.first_cluster;
    while (cluster >= 2 && cluster < FAT16_EOF) {
        u16_t next_cluster = fat16_get_next_cluster(fs, cluster);
        
        // Mark the cluster as free
        if (_fat16_set_fat_entry(fs, cluster, 0) < 0) {
            fat16_close_file(&file);
            return FAT16_ERROR_IO;
        }
        
        cluster = next_cluster;
    }
    
    // Close the file
    fat16_close_file(&file);
    
    // Calculate the size of the root directory in sectors
    u32_t root_dir_sectors = ((fs->root_dir_entries * 32) + (fs->bpb.bytes_per_sector - 1)) / fs->bpb.bytes_per_sector;
    
    // Convert filename to 8.3 format
    char short_name[13];
    if (fat16_to_short_filename(filename, short_name) < 0) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Convert to uppercase for case-insensitive comparison
    for (int i = 0; short_name[i]; i++) {
        short_name[i] = toupper(short_name[i]);
    }
    
    // Find the file in the root directory
    for (u32_t sector = 0; sector < root_dir_sectors; sector++) {
        if (read_sector(fs, fs->root_dir_sector + sector) < 0) {
            return FAT16_ERROR_IO;
        }
        
        // Each sector contains multiple directory entries
        for (u32_t entry = 0; entry < fs->bpb.bytes_per_sector / sizeof(fat16_dir_entry_t); entry++) {
            fat16_dir_entry_t *current = (fat16_dir_entry_t *)&sector_buffer[entry * sizeof(fat16_dir_entry_t)];
            
            // Check if this is the end of directory entries
            if (current->name[0] == 0) {
                return FAT16_ERROR_NOT_FOUND;
            }
            
            // Skip deleted entries and long filename entries
            if (current->name[0] == 0xE5 || (current->attributes & FAT_ATTR_LFN) == FAT_ATTR_LFN) {
                continue;
            }
            
            // Extract the 8.3 filename
            char entry_name[13];
            mem_cpy(entry_name, current->name, 8);
            
            // Remove trailing spaces from name
            int name_len = 8;
            while (name_len > 0 && entry_name[name_len - 1] == ' ') {
                name_len--;
            }
            entry_name[name_len] = '\0';
            
            // If there's an extension, add it
            bool has_ext = false;
            for (int i = 0; i < 3; i++) {
                if (current->ext[i] != ' ') {
                    has_ext = true;
                    break;
                }
            }
            
            if (has_ext) {
                entry_name[name_len++] = '.';
                
                for (int i = 0; i < 3; i++) {
                    if (current->ext[i] != ' ') {
                        entry_name[name_len++] = current->ext[i];
                    }
                }
                entry_name[name_len] = '\0';
            }
            
            // Convert to uppercase for case-insensitive comparison
            for (int i = 0; entry_name[i]; i++) {
                entry_name[i] = toupper(entry_name[i]);
            }
            
            // Compare names
            if (strcmp(entry_name, short_name) == 0) {
                // Mark the entry as deleted
                current->name[0] = 0xE5;
                
                // Write the updated sector back
                if (_write_sector(fs, fs->root_dir_sector + sector) < 0) {
                    return FAT16_ERROR_IO;
                }
                
                return 0;
            }
        }
    }
    
    return FAT16_ERROR_NOT_FOUND;
}

// Rename a file
int fat16_rename_file(fat16_filesystem_t *fs, const char *old_name, const char *new_name) {
    if (!fs || !old_name || !new_name) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Check if the new name is valid
    if (!fat16_is_valid_filename(new_name)) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Check if the new name already exists
    fat16_file_t test_file;
    if (fat16_open_file(fs, new_name, &test_file) == 0) {
        fat16_close_file(&test_file);
        return FAT16_ERROR_INVALID_PARAMETER; // New name already exists
    }
    
    // Find the file in the directory
    fat16_dir_entry_t dir_entry;
    int result = _find_file_in_dir(fs, old_name, &dir_entry, fs->root_dir_sector, 
                                 ((fs->root_dir_entries * 32) + (fs->bpb.bytes_per_sector - 1)) / fs->bpb.bytes_per_sector);
    
    if (result < 0) {
        return result;
    }
    
    // Update the filename
    char short_name[12];
    if (fat16_to_short_filename(new_name, short_name) < 0) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Parse the 8.3 filename
    char *dot = strchr(short_name, '.');
    int name_len = dot ? (dot - short_name) : strlen(short_name);
    
    // Fill name part (padded with spaces)
    for (int i = 0; i < 8; i++) {
        dir_entry.name[i] = (i < name_len) ? toupper(short_name[i]) : ' ';
    }
    
    // Fill extension part (padded with spaces)
    for (int i = 0; i < 3; i++) {
        dir_entry.ext[i] = (dot && dot[1+i]) ? toupper(dot[1+i]) : ' ';
    }
    
    // Update the directory entry
    return _fat16_update_dir_entry(fs, old_name, &dir_entry);
}

/* =============================== Private Functions =============================== */

// Calculate the FAT entry offset for a given cluster
static u32_t _fat16_fat_offset(u16_t cluster) {
    return cluster * 2; // Each FAT entry is 2 bytes in FAT16
}

// Read a sector from the device into the sector buffer
static int _read_sector(fat16_filesystem_t *fs, u32_t sector) {
    return fs->read_sector(fs->device_data, sector, sector_buffer, SECTOR_SIZE);
}

// Write the sector buffer to the device
static int _write_sector(fat16_filesystem_t *fs, u32_t sector) {
    return fs->write_sector(fs->device_data, sector, sector_buffer, SECTOR_SIZE);
}

// Set the value of a FAT entry
static int _fat16_set_fat_entry(fat16_filesystem_t *fs, u16_t cluster, u16_t value) {
    // Calculate FAT parameters
    u32_t fat_offset = _fat16_fat_offset(cluster);
    u32_t fat_sector = fs->first_fat_sector + (fat_offset / fs->bpb.bytes_per_sector);
    u32_t ent_offset = fat_offset % fs->bpb.bytes_per_sector;
    
    // Read the FAT sector
    if (read_sector(fs, fat_sector) < 0) {
        return FAT16_ERROR_IO;
    }
    
    // Set the FAT entry value
    *(u16_t*)&sector_buffer[ent_offset] = value;
    
    // Write the updated sector back
    if (_write_sector(fs, fat_sector) < 0) {
        return FAT16_ERROR_IO;
    }
    
    // If there's a second FAT, update it too
    if (fs->bpb.num_fats > 1) {
        u32_t second_fat_sector = fat_sector + fs->sectors_per_fat;
        
        // Read the second FAT sector
        if (read_sector(fs, second_fat_sector) < 0) {
            return FAT16_ERROR_IO;
        }
        
        // Set the FAT entry value
        *(u16_t*)&sector_buffer[ent_offset] = value;
        
        // Write the updated sector back
        if (_write_sector(fs, second_fat_sector) < 0) {
            return FAT16_ERROR_IO;
        }
    }
    
    return 0;
}

// Find a free cluster in the FAT
static u16_t _fat16_find_free_cluster(fat16_filesystem_t *fs) {
    // Start searching from cluster 2 (first valid cluster)
    for (u16_t cluster = 2; cluster < fs->total_clusters + 2; cluster++) {
        u16_t next_cluster = fat16_get_next_cluster(fs, cluster);
        if (next_cluster == 0) {
            return cluster;
        }
    }
    
    return 0; // No free clusters found
}

// Allocate a new cluster and link it to a chain
static u16_t _fat16_allocate_cluster(fat16_filesystem_t *fs, u16_t prev_cluster) {
    // Find a free cluster
    u16_t new_cluster = _fat16_find_free_cluster(fs);
    if (new_cluster == 0) {
        return 0; // No free clusters
    }
    
    // Mark the cluster as end of chain
    if (_fat16_set_fat_entry(fs, new_cluster, FAT16_EOF) < 0) {
        return 0;
    }
    
    // Link the previous cluster to the new one
    if (prev_cluster != 0) {
        if (_fat16_set_fat_entry(fs, prev_cluster, new_cluster) < 0) {
            return 0;
        }
    }
    
    return new_cluster;
}

// Update a directory entry
static int _fat16_update_dir_entry(fat16_filesystem_t *fs, const char *filename, fat16_dir_entry_t *new_entry) {
    // Calculate the size of the root directory in sectors
    u32_t root_dir_sectors = ((fs->root_dir_entries * 32) + (fs->bpb.bytes_per_sector - 1)) / fs->bpb.bytes_per_sector;
    
    // Find the file in the directory
    char short_name[13];
    if (fat16_to_short_filename(filename, short_name) < 0) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Convert to uppercase for case-insensitive comparison
    for (int i = 0; short_name[i]; i++) {
        short_name[i] = toupper(short_name[i]);
    }
    
    // Loop through all sectors in the root directory
    for (u32_t sector = 0; sector < root_dir_sectors; sector++) {
        if (read_sector(fs, fs->root_dir_sector + sector) < 0) {
            return FAT16_ERROR_IO;
        }
        
        // Each sector contains multiple directory entries
        for (u32_t entry = 0; entry < fs->bpb.bytes_per_sector / sizeof(fat16_dir_entry_t); entry++) {
            fat16_dir_entry_t *current = (fat16_dir_entry_t *)&sector_buffer[entry * sizeof(fat16_dir_entry_t)];
            
            // Check if this is the end of directory entries
            if (current->name[0] == 0) {
                return FAT16_ERROR_NOT_FOUND;
            }
            
            // Skip deleted entries and long filename entries
            if (current->name[0] == 0xE5 || (current->attributes & FAT_ATTR_LFN) == FAT_ATTR_LFN) {
                continue;
            }
            
            // Extract the 8.3 filename
            char entry_name[13];
            mem_cpy(entry_name, current->name, 8);
            
            // Remove trailing spaces from name
            int name_len = 8;
            while (name_len > 0 && entry_name[name_len - 1] == ' ') {
                name_len--;
            }
            entry_name[name_len] = '\0';
            
            // If there's an extension, add it
            bool has_ext = false;
            for (int i = 0; i < 3; i++) {
                if (current->ext[i] != ' ') {
                    has_ext = true;
                    break;
                }
            }
            
            if (has_ext) {
                entry_name[name_len++] = '.';
                
                for (int i = 0; i < 3; i++) {
                    if (current->ext[i] != ' ') {
                        entry_name[name_len++] = current->ext[i];
                    }
                }
                entry_name[name_len] = '\0';
            }
            
            // Convert to uppercase for case-insensitive comparison
            for (int i = 0; entry_name[i]; i++) {
                entry_name[i] = toupper(entry_name[i]);
            }
            
            // Compare names
            if (strcmp(entry_name, short_name) == 0) {
                // Found the file, update the directory entry
                mem_cpy(current, new_entry, sizeof(fat16_dir_entry_t));
                
                // Write the updated sector back
                if (write_sector(fs, fs->root_dir_sector + sector) < 0) {
                    return FAT16_ERROR_IO;
                }
                
                return 0;
            }
        }
    }
    
    return FAT16_ERROR_NOT_FOUND;
}
