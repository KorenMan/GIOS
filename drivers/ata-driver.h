#pragma once

#include "../lib/types.h"

// IO port addresses for ATA buses
#define PRIMARY_IO_BASE 0x1F0
#define PRIMARY_CONTROL_BASE 0x3F6
#define SECONDARY_IO_BASE 0x170
#define SECONDARY_CONTROL_BASE 0x376

// Port offsets from IO base
#define ATA_DATA 0x0 // Read/Write PIO data bytes
#define ATA_ERROR 0x1 // Error register (read)
#define ATA_FEATURES 0x1 // Features register (write)
#define ATA_SECTOR_COUNT 0x2 // Number of sectors to read/write
#define ATA_LBA_LO 0x3 // LBA low bits (0:7)
#define ATA_LBA_MID 0x4 // LBA mid bits (8:15)
#define ATA_LBA_HI 0x5 // LBA high bits (16:23)
#define ATA_DRIVE_HEAD 0x6 // Drive/Head selection and LBA bits (24:27)
#define ATA_STATUS 0x7 // Status register (read)
#define ATA_COMMAND 0x7 // Command register (write)

// Port offsets from Control base
#define ATA_ALT_STATUS 0x0 // Alternate status register (read)
#define ATA_DEVICE_CONTROL 0x0 // Device control register (write)
#define ATA_DRIVE_ADDR 0x1 // Drive address register

// Status register bits
#define ATA_STATUS_ERR 0x01 // Error occurred
#define ATA_STATUS_DRQ 0x08 // Data Request ready
#define ATA_STATUS_SRV 0x10 // Service
#define ATA_STATUS_DF 0x20 // Drive Fault
#define ATA_STATUS_RDY 0x40 // Drive Ready
#define ATA_STATUS_BSY 0x80 // Busy

// Error register bits
#define ATA_ERROR_AMNF 0x01 // Address mark not found
#define ATA_ERROR_TKZNF 0x02 // Track zero not found
#define ATA_ERROR_ABRT 0x04 // Aborted command
#define ATA_ERROR_MCR 0x08 // Media change request
#define ATA_ERROR_IDNF 0x10 // ID not found
#define ATA_ERROR_MC 0x20 // Media changed
#define ATA_ERROR_UNC 0x40 // Uncorrectable data error
#define ATA_ERROR_BBK 0x80 // Bad block detected

// Drive/Head register bits
#define ATA_HEAD_MASK 0x0F // Head number mask (bits 0-3)
#define ATA_DRIVE_BIT 0x10 // Drive number bit (bit 4)
#define ATA_LBA_BIT 0x40 // LBA mode bit (bit 6)
#define ATA_ALWAYS_SET_BITS 0xA0 // Bits 5 and 7 are always set

// Device control register bits
#define ATA_DCR_NIEN 0x02 // No Interrupt
#define ATA_DCR_SRST 0x04 // Software Reset
#define ATA_DCR_HOB 0x80 // High Order Byte

// ATA commands
#define ATA_CMD_READ_PIO 0x20 // Read sectors (PIO)
#define ATA_CMD_READ_PIO_EXT 0x24 // Read sectors (PIO Extended - LBA48)
#define ATA_CMD_WRITE_PIO 0x30 // Write sectors (PIO)
#define ATA_CMD_WRITE_PIO_EXT 0x34 // Write sectors (PIO Extended - LBA48)
#define ATA_CMD_IDENTIFY 0xEC // Identify device

// Device types
#define DEVICE_TYPE_UNKNOWN 0
#define DEVICE_TYPE_ATA 1
#define DEVICE_TYPE_ATAPI 2
#define DEVICE_TYPE_SATA 3

// Signature values
#define ATAPI_SIG_MID 0x14
#define ATAPI_SIG_HI 0xEB
#define SATA_SIG_MID 0x3C
#define SATA_SIG_HI 0xC3

// Maximum number of sectors for LBA28 addressing
#define MAX_LBA28_SECTORS 0x0FFFFFFF // 268,435,455 sectors (128 GiB)

// Device information structure
typedef struct {
    int type; // Device type (ATA, ATAPI, SATA, etc.)
    bool lba28_supported; // LBA28 addressing supported
    bool lba48_supported; // LBA48 addressing supported
    u32_t lba28_sectors; // Number of LBA28 addressable sectors
    u64_t lba48_sectors; // Number of LBA48 addressable sectors
    int udma_supported; // Supported UDMA modes (bitmap)
    int udma_active; // Active UDMA mode
    bool cable_80_detected; // 80-conductor cable detected (master only)
} ata_device_info_t;

// Disk partition structure
typedef struct {
    u32_t start_lba; // Absolute start LBA of partition
    u32_t sector_count; // Number of sectors in partition
} ata_partition_t;

// Current ATA state
static struct {
    u16_t io_base; // Current IO base address
    u16_t control_base; // Current control base address
    int current_drive; // Current selected drive (0 = master, 1 = slave)
    ata_device_info_t drives[2][2]; // Device info for primary/secondary master/slave
    ata_partition_t current_partition; // Currently selected partition
} ata_state = {
    .io_base = PRIMARY_IO_BASE,
    .control_base = PRIMARY_CONTROL_BASE,
    .current_drive = 0,
};

int ata_init();
int ata_identify_drive(int bus, int drive, ata_device_info_t *info);
void ata_print_drive_info(ata_device_info_t *info);
int ata_select_partition(u32_t start_lba, u32_t sector_count);
int ata_read_sectors(u32_t lba, int count, void *buffer);
int ata_write_sectors(u32_t lba, int count, void *buffer);
