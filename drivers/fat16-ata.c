#include "fat16-ata.h"
#include "fat16.h"
#include "ata-driver.h"
#include "vga-driver.h"
#include "../lib/string.h"
#include "../lib/types.h"

// MBR partition table entry structure
typedef struct {
    u8_t boot_indicator;        // 0x80 = bootable, 0x00 = non-bootable
    u8_t start_head;            // Starting head
    u8_t start_sector_cylinder; // Starting sector and cylinder bits (0-5: sector, 6-7: high cylinder)
    u8_t start_cylinder;        // Starting cylinder low 8 bits
    u8_t system_id;             // Partition type ID (0x06 = FAT16)
    u8_t end_head;              // Ending head
    u8_t end_sector_cylinder;   // Ending sector and cylinder bits 
    u8_t end_cylinder;          // Ending cylinder low 8 bits
    u32_t start_sector;         // Starting sector (LBA)
    u32_t total_sectors;        // Total sectors in this partition
} __attribute__((packed)) mbr_partition_entry_t;

// Master boot record structure
typedef struct {
    u8_t bootstrap[446];                 // Boot code
    mbr_partition_entry_t partitions[4]; // 4 partition entries
    u16_t signature;                     // MBR signature (0xAA55)
} __attribute__((packed)) mbr_t;

// FAT16 partition types
#define PARTITION_TYPE_FAT16_SMALL 0x04  // FAT16 with less than 32MB
#define PARTITION_TYPE_FAT16       0x06  // FAT16 with more than 32MB
#define PARTITION_TYPE_FAT16_LBA   0x0E  // FAT16 with LBA addressing

// Maximum number of mounted FAT16 filesystems
#define MAX_MOUNTED_FILESYSTEMS 4

// Structure to hold our FAT16 + ATA context
typedef struct {
    u32_t partition_start_lba;    // Start of the partition in LBA
    u32_t partition_sector_count; // Total sectors in the partition
    bool is_mounted;              // Is this context currently in use?
    int bus;                      // ATA bus (0 = primary, 1 = secondary)
    int drive;                    // ATA drive (0 = master, 1 = slave)
    int partition_index;          // Partition index (0-3)
} fat16_ata_context_t;

// Global contexts for our FAT16 filesystems
static fat16_ata_context_t fat16_ata_contexts[MAX_MOUNTED_FILESYSTEMS];

// Sector buffer for reading MBR and other operations
static u8_t sector_buffer[512];

// String buffer for constructing messages
static char string_buffer[256];

// Initialize the FAT16 ATA subsystem
void fat16_ata_init_subsystem() {
    // Initialize the context array
    for (int i = 0; i < MAX_MOUNTED_FILESYSTEMS; i++) {
        fat16_ata_contexts[i].is_mounted = false;
    }
    
    // Initialize the ATA driver
    if (ata_init() < 0) {
        vga_print("Failed to initialize ATA driver\n");
    }
}

// Find an available context for mounting a filesystem
static fat16_ata_context_t* find_available_context() {
    for (int i = 0; i < MAX_MOUNTED_FILESYSTEMS; i++) {
        if (!fat16_ata_contexts[i].is_mounted) {
            return &fat16_ata_contexts[i];
        }
    }
    return NULL; // No available contexts
}

// Wrapper function for the ATA read_sector that FAT16 will use
static int fat16_ata_read_sector(void *context, u32_t sector, u8_t *buffer, u32_t sector_size) {
    fat16_ata_context_t *ctx = (fat16_ata_context_t *)context;
    
    // Convert FAT16 relative sector to absolute LBA
    u32_t absolute_lba = ctx->partition_start_lba + sector;
    
    // Select the appropriate bus and drive
    ata_state.io_base = (ctx->bus == 0) ? PRIMARY_IO_BASE : SECONDARY_IO_BASE;
    ata_state.control_base = (ctx->bus == 0) ? PRIMARY_CONTROL_BASE : SECONDARY_CONTROL_BASE;
    ata_state.current_drive = ctx->drive;
    
    // Call ATA driver to read the sector
    return ata_read_sectors(absolute_lba, 1, buffer);
}

// Wrapper function for the ATA write_sector that FAT16 will use
static int fat16_ata_write_sector(void *context, u32_t sector, const u8_t *buffer, u32_t sector_size) {
    fat16_ata_context_t *ctx = (fat16_ata_context_t *)context;
    
    // Convert FAT16 relative sector to absolute LBA
    u32_t absolute_lba = ctx->partition_start_lba + sector;
    
    // Select the appropriate bus and drive
    ata_state.io_base = (ctx->bus == 0) ? PRIMARY_IO_BASE : SECONDARY_IO_BASE;
    ata_state.control_base = (ctx->bus == 0) ? PRIMARY_CONTROL_BASE : SECONDARY_CONTROL_BASE;
    ata_state.current_drive = ctx->drive;
    
    // Call ATA driver to write the sector
    return ata_write_sectors(absolute_lba, 1, (void *)buffer);
}

// Read the MBR from the disk
static int read_mbr(int bus, int drive, mbr_t *mbr) {
    // Select the appropriate bus and drive
    ata_state.io_base = (bus == 0) ? PRIMARY_IO_BASE : SECONDARY_IO_BASE;
    ata_state.control_base = (bus == 0) ? PRIMARY_CONTROL_BASE : SECONDARY_CONTROL_BASE;
    ata_state.current_drive = drive;
    
    // Read the MBR (sector 0)
    if (ata_read_sectors(0, 1, (u8_t *)mbr) < 0) {
        vga_print("Failed to read MBR\n");
        return -1;
    }
    
    // Verify MBR signature
    if (mbr->signature != 0xAA55) {
        // Instead of formatted output, use fixed strings
        vga_print("Invalid MBR signature\n");
        return -2;
    }
    
    return 0;
}

// Check if a partition entry is a FAT16 partition
static bool is_fat16_partition(mbr_partition_entry_t *partition) {
    return partition->system_id == PARTITION_TYPE_FAT16 ||
           partition->system_id == PARTITION_TYPE_FAT16_SMALL ||
           partition->system_id == PARTITION_TYPE_FAT16_LBA;
}

// Initialize FAT16 filesystem on the selected ATA partition
int fat16_ata_init_fs(fat16_filesystem_t *fs, fat16_ata_context_t *ctx) {
    if (!fs || !ctx) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Initialize the FAT16 filesystem with our wrapper functions
    return fat16_init(fs, ctx, fat16_ata_read_sector, fat16_ata_write_sector);
}

// Mount a FAT16 filesystem from an ATA disk
int fat16_mount_ata(fat16_filesystem_t *fs, int bus, int drive, int partition_index) {
    if (!fs || bus < 0 || bus > 1 || drive < 0 || drive > 1 || 
        partition_index < 0 || partition_index > 3) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Get information about the drive
    ata_device_info_t drive_info;
    if (ata_identify_drive(bus, drive, &drive_info) < 0) {
        vga_print("Failed to identify drive\n");
        return -1;
    }
    
    // Make sure the drive is an ATA drive
    if (drive_info.type != DEVICE_TYPE_ATA && drive_info.type != DEVICE_TYPE_SATA) {
        vga_print("Drive is not an ATA/SATA drive\n");
        return -1;
    }
    
    // Read the MBR
    mbr_t mbr;
    if (read_mbr(bus, drive, &mbr) < 0) {
        vga_print("Failed to read MBR\n");
        return -1;
    }
    
    // Check if the requested partition exists and is a FAT16 partition
    if (partition_index >= 0 && partition_index <= 3) {
        mbr_partition_entry_t *partition = &mbr.partitions[partition_index];
        
        if (partition->total_sectors == 0) {
            if (partition_index == 0) vga_print("Partition 0 does not exist\n");
            else if (partition_index == 1) vga_print("Partition 1 does not exist\n");
            else if (partition_index == 2) vga_print("Partition 2 does not exist\n");
            else vga_print("Partition 3 does not exist\n");
            return -1;
        }
        
        if (!is_fat16_partition(partition)) {
            vga_print("Partition is not a FAT16 partition\n");
            return -1;
        }
        
        // Find an available context
        fat16_ata_context_t *ctx = find_available_context();
        if (!ctx) {
            vga_print("No available mount points\n");
            return -1;
        }
        
        // Initialize the context
        ctx->partition_start_lba = partition->start_sector;
        ctx->partition_sector_count = partition->total_sectors;
        ctx->bus = bus;
        ctx->drive = drive;
        ctx->partition_index = partition_index;
        ctx->is_mounted = true;
        
        // Initialize the FAT16 filesystem on this partition
        int result = fat16_ata_init_fs(fs, ctx);
        if (result < 0) {
            if (partition_index == 0) vga_print("Failed to initialize FAT16 filesystem on partition 0\n");
            else if (partition_index == 1) vga_print("Failed to initialize FAT16 filesystem on partition 1\n");
            else if (partition_index == 2) vga_print("Failed to initialize FAT16 filesystem on partition 2\n");
            else vga_print("Failed to initialize FAT16 filesystem on partition 3\n");
            ctx->is_mounted = false;
            return result;
        }
        
        return 0;
    }
    
    return -1;
}

// Unmount a FAT16 filesystem
int fat16_unmount_ata(fat16_filesystem_t *fs) {
    if (!fs) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Find the context associated with this filesystem
    fat16_ata_context_t *ctx = (fat16_ata_context_t *)fs->device_data;
    if (!ctx) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Mark the context as free
    ctx->is_mounted = false;
    
    // Clear the filesystem structure
    mem_set(fs, 0, sizeof(fat16_filesystem_t));
    
    return 0;
}

// Format a partition as FAT16
int fat16_format_partition(int bus, int drive, int partition_index) {
    if (bus < 0 || bus > 1 || drive < 0 || drive > 1 || 
        partition_index < 0 || partition_index > 3) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Read the MBR
    mbr_t mbr;
    if (read_mbr(bus, drive, &mbr) < 0) {
        vga_print("Failed to read MBR\n");
        return -1;
    }
    
    // Check if the partition exists
    mbr_partition_entry_t *partition = &mbr.partitions[partition_index];
    if (partition->total_sectors == 0) {
        if (partition_index == 0) vga_print("Partition 0 does not exist\n");
        else if (partition_index == 1) vga_print("Partition 1 does not exist\n");
        else if (partition_index == 2) vga_print("Partition 2 does not exist\n");
        else vga_print("Partition 3 does not exist\n");
        return -1;
    }
    
    // Select the appropriate bus and drive
    ata_state.io_base = (bus == 0) ? PRIMARY_IO_BASE : SECONDARY_IO_BASE;
    ata_state.control_base = (bus == 0) ? PRIMARY_CONTROL_BASE : SECONDARY_CONTROL_BASE;
    ata_state.current_drive = drive;
    
    // Create a temporary context
    fat16_ata_context_t ctx;
    ctx.partition_start_lba = partition->start_sector;
    ctx.partition_sector_count = partition->total_sectors;
    ctx.bus = bus;
    ctx.drive = drive;
    ctx.partition_index = partition_index;
    ctx.is_mounted = true;
    
    // Clear buffer
    mem_set(sector_buffer, 0, 512);
    
    // Jump instruction to boot code
    sector_buffer[0] = 0xEB; // JMP SHORT
    sector_buffer[1] = 0x3C; // Offset
    sector_buffer[2] = 0x90; // NOP
    
    // OEM name
    mem_cpy(&sector_buffer[3], "MSDOS5.0", 8);
    
    // BPB (BIOS Parameter Block)
    *((u16_t *)&sector_buffer[0x0B]) = 512;         // Bytes per sector
    sector_buffer[0x0D] = 1;                        // Sectors per cluster
    *((u16_t *)&sector_buffer[0x0E]) = 1;           // Reserved sectors
    sector_buffer[0x10] = 2;                        // Number of FATs
    *((u16_t *)&sector_buffer[0x11]) = 512;         // Root directory entries
    *((u16_t *)&sector_buffer[0x13]) = 0;           // Total sectors (16-bit)
    sector_buffer[0x15] = 0xF8;                     // Media descriptor
    *((u16_t *)&sector_buffer[0x16]) = 32;          // Sectors per FAT
    *((u16_t *)&sector_buffer[0x18]) = 32;          // Sectors per track
    *((u16_t *)&sector_buffer[0x1A]) = 64;          // Number of heads
    *((u32_t *)&sector_buffer[0x1C]) = 0;           // Hidden sectors
    *((u32_t *)&sector_buffer[0x20]) = partition->total_sectors; // Total sectors (32-bit)
    
    // Extended BPB
    sector_buffer[0x24] = 0x80;                     // Drive number
    sector_buffer[0x25] = 0;                        // Reserved
    sector_buffer[0x26] = 0x29;                     // Extended boot signature
    *((u32_t *)&sector_buffer[0x27]) = 0x12345678;  // Volume serial number
    mem_cpy(&sector_buffer[0x2B], "NO NAME    ", 11); // Volume label
    mem_cpy(&sector_buffer[0x36], "FAT16   ", 8);     // File system type
    
    // Add boot code - just a simple message and halt
    const char *msg = "This is not a bootable partition\r\nSystem halted.";
    mem_cpy(&sector_buffer[0x3E], msg, str_len(msg));
    
    // Boot signature
    sector_buffer[0x1FE] = 0x55;
    sector_buffer[0x1FF] = 0xAA;
    
    // Write the boot sector
    if (ata_write_sectors(partition->start_sector, 1, sector_buffer) < 0) {
        vga_print("Failed to write boot sector\n");
        return -1;
    }
    
    // Initialize the FATs
    mem_set(sector_buffer, 0, 512);
    
    // First FAT sector
    // First two entries are reserved
    sector_buffer[0] = 0xF8; // Media descriptor
    sector_buffer[1] = 0xFF;
    sector_buffer[2] = 0xFF;
    sector_buffer[3] = 0xFF;
    
    // Write the first sector of each FAT
    u32_t fat_sector = partition->start_sector + 1; // First FAT starts after reserved sectors
    if (ata_write_sectors(fat_sector, 1, sector_buffer) < 0) {
        vga_print("Failed to write first FAT sector\n");
        return -1;
    }
    
    // Second FAT (copy of the first)
    fat_sector = partition->start_sector + 1 + 32; // Second FAT starts after the first FAT
    if (ata_write_sectors(fat_sector, 1, sector_buffer) < 0) {
        vga_print("Failed to write second FAT sector\n");
        return -1;
    }
    
    // Zero out the rest of the FATs
    mem_set(sector_buffer, 0, 512);
    for (int i = 1; i < 32; i++) {
        // Write the rest of the first FAT
        if (ata_write_sectors(partition->start_sector + 1 + i, 1, sector_buffer) < 0) {
            vga_print("Failed to write FAT sector\n");
            return -1;
        }
        
        // Write the rest of the second FAT
        if (ata_write_sectors(partition->start_sector + 1 + 32 + i, 1, sector_buffer) < 0) {
            vga_print("Failed to write FAT sector\n");
            return -1;
        }
    }
    
    // Initialize the root directory
    mem_set(sector_buffer, 0, 512);
    
    // Create a volume label entry
    fat16_dir_entry_t *volume_label = (fat16_dir_entry_t *)sector_buffer;
    mem_cpy(volume_label->name, "NO NAME    ", 11);
    volume_label->attributes = FAT_ATTR_VOLUME_ID;
    volume_label->creation_date = DEFAULT_FAT_DATE;
    volume_label->creation_time = DEFAULT_FAT_TIME;
    volume_label->last_access_date = DEFAULT_FAT_DATE;
    volume_label->last_mod_date = DEFAULT_FAT_DATE;
    volume_label->last_mod_time = DEFAULT_FAT_TIME;
    
    // Write the root directory sectors
    u32_t root_dir_sector = partition->start_sector + 1 + 32 + 32; // Root dir starts after both FATs
    if (ata_write_sectors(root_dir_sector, 1, sector_buffer) < 0) {
        vga_print("Failed to write root directory sector\n");
        return -1;
    }
    
    // Zero out the rest of the root directory
    mem_set(sector_buffer, 0, 512);
    for (int i = 1; i < 32; i++) { // 32 sectors for the root directory (512 entries)
        if (ata_write_sectors(root_dir_sector + i, 1, sector_buffer) < 0) {
            vga_print("Failed to write root directory sector\n");
            return -1;
        }
    }
    
    // Update the partition type in the MBR
    partition->system_id = PARTITION_TYPE_FAT16;
    
    // Write the updated MBR
    if (ata_write_sectors(0, 1, (u8_t *)&mbr) < 0) {
        vga_print("Failed to write updated MBR\n");
        return -1;
    }
    
    if (partition_index == 0) vga_print("Partition 0 formatted as FAT16\n");
    else if (partition_index == 1) vga_print("Partition 1 formatted as FAT16\n");
    else if (partition_index == 2) vga_print("Partition 2 formatted as FAT16\n");
    else vga_print("Partition 3 formatted as FAT16\n");
    return 0;
}

// List partitions on a disk
int fat16_list_partitions(int bus, int drive) {
    if (bus < 0 || bus > 1 || drive < 0 || drive > 1) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Read the MBR
    mbr_t mbr;
    if (read_mbr(bus, drive, &mbr) < 0) {
        vga_print("Failed to read MBR\n");
        return -1;
    }
    
    // Print partition information
    if (bus == 0 && drive == 0) vga_print("Partitions on bus 0, drive 0:\n");
    else if (bus == 0 && drive == 1) vga_print("Partitions on bus 0, drive 1:\n");
    else if (bus == 1 && drive == 0) vga_print("Partitions on bus 1, drive 0:\n");
    else vga_print("Partitions on bus 1, drive 1:\n");
    
    for (int i = 0; i < 4; i++) {
        mbr_partition_entry_t *part = &mbr.partitions[i];
        
        if (part->total_sectors > 0) {
            if (i == 0) vga_print("  Partition 0: ");
            else if (i == 1) vga_print("  Partition 1: ");
            else if (i == 2) vga_print("  Partition 2: ");
            else vga_print("  Partition 3: ");
            
            vga_print("Type 0x06");
            vga_print(", FAT16 filesystem\n");
        }
    }
    
    return 0;
}

// Create a new partition on a disk
int fat16_create_partition(int bus, int drive, int partition_index, u32_t start_sector, u32_t total_sectors) {
    if (bus < 0 || bus > 1 || drive < 0 || drive > 1 || 
        partition_index < 0 || partition_index > 3) {
        return FAT16_ERROR_INVALID_PARAMETER;
    }
    
    // Read the MBR
    mbr_t mbr;
    if (read_mbr(bus, drive, &mbr) < 0) {
        vga_print("Failed to read MBR\n");
        return -1;
    }
    
    // Check if the requested partition slot is available
    mbr_partition_entry_t *partition = &mbr.partitions[partition_index];
    if (partition->total_sectors > 0) {
        if (partition_index == 0) vga_print("Partition 0 already exists\n");
        else if (partition_index == 1) vga_print("Partition 1 already exists\n");
        else if (partition_index == 2) vga_print("Partition 2 already exists\n");
        else vga_print("Partition 3 already exists\n");
        return -1;
    }
    
    // Get information about the drive
    ata_device_info_t drive_info;
    if (ata_identify_drive(bus, drive, &drive_info) < 0) {
        vga_print("Failed to identify drive\n");
        return -1;
    }
    
    // Make sure the drive is an ATA drive
    if (drive_info.type != DEVICE_TYPE_ATA && drive_info.type != DEVICE_TYPE_SATA) {
        vga_print("Drive is not an ATA/SATA drive\n");
        return -1;
    }
    
    // Make sure the partition fits on the drive
    u32_t max_sectors = (drive_info.lba28_supported) ? drive_info.lba28_sectors : 0;
    if (start_sector + total_sectors > max_sectors) {
        vga_print("Partition would extend beyond the end of the drive\n");
        return -1;
    }
    
    // Check for overlapping partitions
    for (int i = 0; i < 4; i++) {
        if (i == partition_index) continue;
        
        mbr_partition_entry_t *other = &mbr.partitions[i];
        if (other->total_sectors == 0) continue;
        
        // Check if the new partition overlaps with an existing one
        if ((start_sector >= other->start_sector && 
             start_sector < other->start_sector + other->total_sectors) ||
            (start_sector + total_sectors > other->start_sector && 
             start_sector + total_sectors <= other->start_sector + other->total_sectors) ||
            (start_sector <= other->start_sector && 
             start_sector + total_sectors >= other->start_sector + other->total_sectors)) {
            if (i == 0) vga_print("New partition would overlap with partition 0\n");
            else if (i == 1) vga_print("New partition would overlap with partition 1\n");
            else if (i == 2) vga_print("New partition would overlap with partition 2\n");
            else vga_print("New partition would overlap with partition 3\n");
            return -1;
        }
    }
    
    // Initialize the partition entry
    mem_set(partition, 0, sizeof(mbr_partition_entry_t));
    
    // Calculate CHS values 
    u32_t cylinders = 1024;       // Typical value for modern drives
    u32_t heads = 255;            // Typical value for modern drives
    u32_t sectors_per_track = 63; // Typical value for modern drives
    
    u32_t sector = start_sector % sectors_per_track + 1;
    u32_t head = (start_sector / sectors_per_track) % heads;
    u32_t cylinder = (start_sector / sectors_per_track) / heads;
    
    if (cylinder > 1023) cylinder = 1023;
    
    partition->boot_indicator = 0x00; // Non-bootable
    partition->start_head = head;
    partition->start_sector_cylinder = ((cylinder >> 2) & 0xC0) | (sector & 0x3F);
    partition->start_cylinder = cylinder & 0xFF;
    
    // Calculate end CHS values
    u32_t end_lba = start_sector + total_sectors - 1;
    sector = end_lba % sectors_per_track + 1;
    head = (end_lba / sectors_per_track) % heads;
    cylinder = (end_lba / sectors_per_track) / heads;
    
    if (cylinder > 1023) cylinder = 1023;
    
    partition->end_head = head;
    partition->end_sector_cylinder = ((cylinder >> 2) & 0xC0) | (sector & 0x3F);
    partition->end_cylinder = cylinder & 0xFF;
    
    // Set other fields
    partition->system_id = PARTITION_TYPE_FAT16; // FAT16
    partition->start_sector = start_sector;
    partition->total_sectors = total_sectors;
    
    // Write the updated MBR
    if (ata_write_sectors(0, 1, (u8_t *)&mbr) < 0) {
        vga_print("Failed to write updated MBR\n");
        return -1;
    }
    
    if (partition_index == 0) vga_print("Created partition 0 (FAT16)\n");
    else if (partition_index == 1) vga_print("Created partition 1 (FAT16)\n");
    else if (partition_index == 2) vga_print("Created partition 2 (FAT16)\n");
    else vga_print("Created partition 3 (FAT16)\n");
    
    // Format the new partition as FAT16
    return fat16_format_partition(bus, drive, partition_index);
}