#pragma once

#include "../lib/types.h"
#include "../drivers/ata-driver.h"

// FAT file system constants
#define FAT16_EOC 0xfff8      // End of cluster chain marker
#define FAT_ENTRY_FREE 0x0000 // Free cluster marker
#define FAT_ENTRY_BAD 0xfff7  // Bad cluster marker
#define SECTOR_SIZE 512
#define DIR_ENTRY_SIZE 32
#define ENTRIES_PER_SECTOR (SECTOR_SIZE / DIR_ENTRY_SIZE)
// File attributes
#define ATTR_READ_ONLY 0x01
#define ATTR_HIDDEN 0x02
#define ATTR_SYSTEM 0x04
#define ATTR_VOLUME_ID 0x08
#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE 0x20

// FAT Boot Record structure
typedef struct {
    u8_t jump_code[3];
    u8_t oem_name[8];
    u16_t bytes_per_sector;
    u8_t sectors_per_cluster;
    u16_t reserved_sectors;
    u8_t num_fats;
    u16_t root_dir_entries;
    u16_t total_sectors_16;
    u8_t media_descriptor;
    u16_t fat_size_sectors;
    u16_t sectors_per_track;
    u16_t num_heads;
    u32_t hidden_sectors;
    u32_t total_sectors_32;

    // Extended Boot Record
    u8_t drive_number;
    u8_t reserved;
    u8_t boot_signature;
    u32_t volume_id;
    u8_t volume_label[11];
    u8_t fat16_type[8];
} __attribute__((packed)) fat_boot_record_t;

// Directory entry structure
typedef struct {
    u8_t filename[8];
    u8_t extension[3];
    u8_t attributes;
    u8_t reserved;
    u8_t creation_time_tenths;
    u16_t creation_time;
    u16_t creation_date;
    u16_t last_access_date;
    u16_t first_cluster_high;
    u16_t last_modification_time;
    u16_t last_modification_date;
    u16_t first_cluster_low;
    u32_t file_size;
} __attribute__((packed)) dir_entry_t;

// File handle structure
typedef struct {
    dir_entry_t entry;
    u32_t position;
    u16_t current_cluster;
    u32_t dir_sector;
    u32_t dir_offset;
    bool is_open;
} file_t;

// Filesystem information
typedef struct {
    fat_boot_record_t boot_record;
    u32_t fat_start_sector;
    u32_t root_dir_start_sector;
    u32_t data_start_sector;
    u32_t cluster_size_bytes;
} fat16_info_t;

bool fat16_init();
bool fat16_format();
file_t fat16_open(const char *filename);
file_t fat16_create(const char *filename);
void fat16_close(file_t *file);
u32_t fat16_read(file_t *file, void *buffer, u32_t size, int position);
u32_t fat16_write(file_t *file, const void *buffer, u32_t size, int position);
bool fat16_delete(const char *filename);
bool fat16_rename(const char *old_name, const char *new_name);
void fat16_list_files();