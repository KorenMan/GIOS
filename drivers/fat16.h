#pragma once

#include "../lib/types.h"
#include "../lib/memory.h"

#define FAT16_EOF            0xFFF8  // End of file marker (>= 0xFFF8)
#define FAT16_BAD_CLUSTER    0xFFF7  // Bad cluster marker
#define FAT16_FREE_CLUSTER   0x0000  // Free cluster marker

// Error codes
#define FAT16_ERROR_INVALID_FILESYSTEM    -1
#define FAT16_ERROR_NOT_FOUND             -2
#define FAT16_ERROR_IO                    -3
#define FAT16_ERROR_NO_MEMORY             -4
#define FAT16_ERROR_INVALID_PARAMETER     -5

// Default values for date/time fields (January 1, 1980, 00:00:00)
#define DEFAULT_FAT_DATE 0x0021  // 01:01:1980 in FAT format
#define DEFAULT_FAT_TIME 0x0000  // 00:00:00 in FAT format

// FAT16 BIOS Parameter Block structure
typedef struct {
    u8_t     jump[3];              // Jump instruction to boot code
    char     oem_name[8];          // OEM identifier
    u16_t    bytes_per_sector;     // Bytes per sector
    u8_t     sectors_per_cluster;  // Sectors per cluster
    u16_t    reserved_sectors;     // Reserved sectors count
    u8_t     num_fats;             // Number of FATs
    u16_t    root_entries;         // Root directory entries
    u16_t    total_sectors_16;     // Total sectors (16-bit)
    u8_t     media_type;           // Media descriptor
    u16_t    sectors_per_fat;      // Sectors per FAT
    u16_t    sectors_per_track;    // Sectors per track
    u16_t    num_heads;            // Number of heads
    u32_t    hidden_sectors;       // Hidden sectors
    u32_t    total_sectors_32;     // Total sectors (32-bit)
    
    // Extended Boot Record
    u8_t     drive_number;         // Drive number
    u8_t     reserved;             // Reserved
    u8_t     boot_signature;       // Extended boot signature (0x28 or 0x29)
    u32_t    volume_id;            // Volume serial number
    char     volume_label[11];     // Volume label
    char     fs_type[8];           // Filesystem type (FAT16)
} __attribute__((packed)) fat16_bpb_t;

// FAT16 directory entry structure 
typedef struct {
    char     name[8];              // File name
    char     ext[3];               // File extension
    u8_t     attributes;           // File attributes
    u8_t     reserved_nt;          // Reserved for Windows NT
    u8_t     creation_time_tenths; // Creation time (tenths of sec)
    u16_t    creation_time;        // Creation time (hours, minutes, seconds)
    u16_t    creation_date;        // Creation date
    u16_t    last_access_date;     // Last access date
    u16_t    first_cluster_high;   // High 16 bits of first cluster (always 0 in FAT16)
    u16_t    last_mod_time;        // Last modification time
    u16_t    last_mod_date;        // Last modification date
    u16_t    first_cluster;        // First cluster of the file
    u32_t    file_size;            // File size in bytes
} __attribute__((packed)) fat16_dir_entry_t;

// File attribute definitions
#define FAT_ATTR_READ_ONLY   0x01
#define FAT_ATTR_HIDDEN      0x02
#define FAT_ATTR_SYSTEM      0x04
#define FAT_ATTR_VOLUME_ID   0x08
#define FAT_ATTR_DIRECTORY   0x10
#define FAT_ATTR_ARCHIVE     0x20
#define FAT_ATTR_LFN         (FAT_ATTR_READ_ONLY | FAT_ATTR_HIDDEN | FAT_ATTR_SYSTEM | FAT_ATTR_VOLUME_ID)

// Long filename entry structure
typedef struct {
    u8_t     sequence_number;      // Sequence number
    u16_t    name_chars_1[5];      // First 5 characters
    u8_t     attributes;           // Attributes (always 0x0F)
    u8_t     entry_type;           // Long entry type (0 for name entries)
    u8_t     checksum;             // Checksum of the short filename
    u16_t    name_chars_2[6];      // Next 6 characters
    u16_t    reserved;             // Always zero
    u16_t    name_chars_3[2];      // Final 2 characters
} __attribute__((packed)) fat16_lfn_entry_t;

// FAT16 filesystem structure 
typedef struct {
    fat16_bpb_t bpb;               // Boot sector info
    u32_t    first_data_sector;    // First data sector
    u32_t    first_fat_sector;     // First FAT sector
    u32_t    root_dir_sector;      // Root directory sector
    u32_t    sectors_per_fat;      // Sectors per FAT
    u32_t    root_dir_entries;     // Root directory entries
    u32_t    data_sectors;         // Data sectors count
    u32_t    total_clusters;       // Total number of clusters
    u16_t    *fat_table;           // FAT table cache
    void     *device_data;         // Device-specific data for I/O operations
    
    // Function pointers for device I/O operations
    int (*read_sector)(void *device_data, u32_t sector, u8_t *buffer, u32_t sector_size);
    int (*write_sector)(void *device_data, u32_t sector, const u8_t *buffer, u32_t sector_size);
} fat16_filesystem_t;

// File structure
typedef struct {
    fat16_filesystem_t *fs;        // Reference to the filesystem
    u32_t    first_cluster;        // First cluster of the file
    u32_t    current_cluster;      // Current cluster being accessed
    u32_t    current_position;     // Current position in the file
    u32_t    file_size;            // File size
    u8_t     attributes;           // File attributes
    bool     is_open;              // If the file is open
    char     filename[13];         // 8.3 filename (with dot)
} fat16_file_t;

// Directory structure 
typedef struct {
    fat16_filesystem_t *fs;        // Reference to the filesystem
    u32_t    first_cluster;        // First cluster of the directory (0 for root)
    u32_t    current_cluster;      // Current cluster being accessed
    u32_t    current_position;     // Current position in the directory
    u32_t    current_entry;        // Current entry index
    bool     is_root;              // If this is the root directory
} fat16_dir_t;

int fat16_init(fat16_filesystem_t *fs, void *device_data,
                int (*read_sector)(void *device_data, u32_t sector, u8_t *buffer, u32_t sector_size),
                int (*write_sector)(void *device_data, u32_t sector, const u8_t *buffer, u32_t sector_size));
int fat16_open_file(fat16_filesystem_t *fs, const char *filename, fat16_file_t *file);
int fat16_read_file(fat16_file_t *file, void *buffer, u32_t size);
int fat16_write_file(fat16_file_t *file, const void *buffer, u32_t size);
int fat16_close_file(fat16_file_t *file);
int fat16_open_dir(fat16_filesystem_t *fs, const char *path, fat16_dir_t *dir);
int fat16_read_dir(fat16_dir_t *dir, fat16_dir_entry_t *entry);
int fat16_close_dir(fat16_dir_t *dir);
u16_t fat16_get_next_cluster(fat16_filesystem_t *fs, u16_t cluster);
u32_t fat16_cluster_to_sector(fat16_filesystem_t *fs, u16_t cluster);
void fat16_parse_date(u16_t fat_date, u16_t *year, u8_t *month, u8_t *day);
void fat16_parse_time(u16_t fat_time, u8_t *hour, u8_t *minute, u8_t *second);
bool fat16_is_valid_filename(const char *filename);
int fat16_to_short_filename(const char *input, char *output);
