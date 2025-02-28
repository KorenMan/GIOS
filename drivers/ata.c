#include "ata.h"
#include "vga.h"
#include "../lib/ports.h"
#include "../lib/string.h"

static void _ata_insw(u16_t port, void *addr, int count);
static void _ata_outsw(u16_t port, void *addr, int count);
static void _ata_400ns_delay();
static int _ata_poll_status();
static int _ata_select_drive(int bus, int drive);
static void _ata_soft_reset();
static void _ata_wait_not_busy();
static void _ata_wait_ready();
static int _ata_process_error();
static u16_t *_ata_get_identify_data(int bus, int drive, u16_t *buffer);

/* =============================== Public Functions =============================== */

// Initialize the ATA driver 
int ata_init() {
    u16_t identify_data[256];
    
    // Initialize primary/secondary bus device control registers 
    port_byte_out(PRIMARY_CONTROL_BASE + ATA_DEVICE_CONTROL, 0);
    port_byte_out(SECONDARY_CONTROL_BASE + ATA_DEVICE_CONTROL, 0);
    
    // Identify all drives 
    for (int i = 0; i < 2; i++) {        // Bus: 0 = primary, 1 = secondary 
        for (int j = 0; j < 2; j++) {    // Drive: 0 = master, 1 = slave 
            ata_identify_drive(i, j, &ata_state.drives[i][j]);
        }
    }
    
    // Select the primary master by default 
    _ata_select_drive(0, 0);
    
    // Success 
    return 0;
}

// Identify an ATA drive and get its information 
int ata_identify_drive(int bus, int drive, ata_device_info_t *info) {
    u16_t identify_data[256];
    
    // Initialize device info 
    info->type = DEVICE_TYPE_UNKNOWN;
    info->lba28_supported = 0;
    info->lba48_supported = 0;
    info->lba28_sectors = 0;
    info->lba48_sectors = 0;
    info->udma_supported = 0;
    info->udma_active = 0;
    info->cable_80_detected = 0;
    
    // Try to get identify data 
    if (_ata_get_identify_data(bus, drive, identify_data) == 0) {
        return -1;  // Drive does not exist or is not an ATA drive 
    }
    
    // We have an ATA device 
    info->type = DEVICE_TYPE_ATA;
    
    // Check if LBA28 is supported and get sector count 
    if ((identify_data[60] != 0) || (identify_data[61] != 0)) {
        info->lba28_supported = 1;
        info->lba28_sectors = ((u32_t)identify_data[61] << 16) | identify_data[60];
    }
    
    // Check if LBA48 is supported 
    if (identify_data[83] & (1 << 10)) {
        info->lba48_supported = 1;
        
        // Get LBA48 sector count 
        info->lba48_sectors = 
            ((u64_t)identify_data[103] << 48) |
            ((u64_t)identify_data[102] << 32) |
            ((u64_t)identify_data[101] << 16) |
            identify_data[100];
    }
    
    // Get UDMA modes 
    if (identify_data[88] != 0) {
        info->udma_supported = identify_data[88] & 0xFF;
        info->udma_active = (identify_data[88] >> 8) & 0xFF;
    }
    
    // Check for 80-conductor cable (master only) 
    if (drive == 0 && (identify_data[93] & (1 << 11))) {
        info->cable_80_detected = 1;
    }
    
    // DEBUG
    //ata_print_drive_info(info);
    
    return 0;  // Success 
}

// Print drive information 
void ata_print_drive_info(ata_device_info_t *info) {
    char buffer[16];
    
    // Print device type 
    vga_print("Type: ");
    int_to_hex_string(info->type, buffer, sizeof(buffer));
    vga_print(buffer);
    vga_print("\n");
    
    // Only continue if it's an ATA device 
    if (info->type != DEVICE_TYPE_ATA) {
        return;
    }
    
    // Print LBA support 
    vga_print("LBA28: ");
    vga_print(info->lba28_supported ? "Yes" : "No");
    vga_print("\n");
    
    if (info->lba28_supported) {
        vga_print("LBA28 Sectors: ");
        int_to_hex_string(info->lba28_sectors, buffer, sizeof(buffer));
        vga_print(buffer);
        vga_print("\n");
    }
    
    vga_print("LBA48: ");
    vga_print(info->lba48_supported ? "Yes" : "No");
    vga_print("\n");
    
    // Print UDMA modes 
    vga_print("UDMA Supported: ");
    int_to_hex_string(info->udma_supported, buffer, sizeof(buffer));
    vga_print(buffer);
    vga_print("\n");
    
    vga_print("UDMA Active: ");
    int_to_hex_string(info->udma_active, buffer, sizeof(buffer));
    vga_print(buffer);
    vga_print("\n");
    
    // Print cable detection 
    vga_print("80-pin Cable: ");
    vga_print(info->cable_80_detected ? "Yes" : "No");
    vga_print("\n");
}

// Select a partition for subsequent operations 
int ata_select_partition(u32_t start_lba, u32_t sector_count) {
    // Validate the partition 
    if (start_lba + sector_count > ata_state.drives[0][0].lba28_sectors) {
        return -1;  // Partition exceeds drive capacity 
    }
    
    // Store the partition information 
    ata_state.current_partition.start_lba = start_lba;
    ata_state.current_partition.sector_count = sector_count;
    
    return 0;  // Success 
}

// Read sectors from the current partition 
int ata_read_sectors(u32_t lba, int count, void *buffer) {
    u32_t absolute_lba;
    int i;
    
    // Validate parameters 
    if (count <= 0 || count > 256) {
        return -1;  // Invalid count (0 means 256 sectors, but we don't support that) 
    }
    
    if (lba + count > ata_state.current_partition.sector_count) {
        return -2;  // Read beyond partition boundary 
    }
    
    // Convert relative LBA to absolute LBA 
    absolute_lba = ata_state.current_partition.start_lba + lba;
    
    // Ensure we're within LBA28 range 
    if (absolute_lba + count > MAX_LBA28_SECTORS) {
        return -3;  // Beyond LBA28 limit 
    }
    
    // Select the correct drive (we use primary master for simplicity) 
    _ata_select_drive(0, 0);
    
    // Wait for drive to be ready 
    _ata_wait_ready();
    
    // Set up registers for the read operation 
    port_byte_out(ata_state.io_base + ATA_SECTOR_COUNT, count);
    port_byte_out(ata_state.io_base + ATA_LBA_LO, absolute_lba & 0xFF);
    port_byte_out(ata_state.io_base + ATA_LBA_MID, (absolute_lba >> 8) & 0xFF);
    port_byte_out(ata_state.io_base + ATA_LBA_HI, (absolute_lba >> 16) & 0xFF);
    
    // Set drive/head register with the highest 4 bits of LBA and drive select 
    port_byte_out(ata_state.io_base + ATA_DRIVE_HEAD, 
              ATA_ALWAYS_SET_BITS | ATA_LBA_BIT | ((absolute_lba >> 24) & 0x0F));
    
    // Send the read command 
    port_byte_out(ata_state.io_base + ATA_COMMAND, ATA_CMD_READ_PIO);
    
    // Read all the sectors 
    for (i = 0; i < count; i++) {
        // Wait for data to be ready 
        if (_ata_poll_status() != 0) {
            return -4;  // Error during read 
        }
        
        // Read a sector (256 words = 512 bytes) 
        _ata_insw(ata_state.io_base + ATA_DATA, buffer, 256);
        
        // Move buffer pointer 
        buffer = (u8_t*)buffer + 512;
    }
    
    return 0;  // Success 
}

// Write sectors to the current partition 
int ata_write_sectors(u32_t lba, int count, void *buffer) {
    u32_t absolute_lba;
    int i;
    
    // Validate parameters 
    if (count <= 0 || count > 256) {
        return -1;  // Invalid count (0 means 256 sectors, but we don't support that) 
    }
    
    if (lba + count > ata_state.current_partition.sector_count) {
        return -2;  // Write beyond partition boundary 
    }
    
    // Convert relative LBA to absolute LBA 
    absolute_lba = ata_state.current_partition.start_lba + lba;
    
    // Ensure we're within LBA28 range 
    if (absolute_lba + count > MAX_LBA28_SECTORS) {
        return -3;  // Beyond LBA28 limit 
    }
    
    // Select the correct drive (we use primary master for simplicity) 
    _ata_select_drive(0, 0);
    
    // Wait for drive to be ready 
    _ata_wait_ready();
    
    // Set up registers for the write operation 
    port_byte_out(ata_state.io_base + ATA_SECTOR_COUNT, count);
    port_byte_out(ata_state.io_base + ATA_LBA_LO, absolute_lba & 0xFF);
    port_byte_out(ata_state.io_base + ATA_LBA_MID, (absolute_lba >> 8) & 0xFF);
    port_byte_out(ata_state.io_base + ATA_LBA_HI, (absolute_lba >> 16) & 0xFF);
    
    // Set drive/head register with the highest 4 bits of LBA and drive select 
    port_byte_out(ata_state.io_base + ATA_DRIVE_HEAD, 
              ATA_ALWAYS_SET_BITS | ATA_LBA_BIT | ((absolute_lba >> 24) & 0x0F));
    
    // Send the write command 
    port_byte_out(ata_state.io_base + ATA_COMMAND, ATA_CMD_WRITE_PIO);
    
    // Write all the sectors 
    for (i = 0; i < count; i++) {
        // Wait for drive to be ready to accept data 
        if (_ata_poll_status() != 0) {
            return -4;  // Error preparing for write 
        }
        
        // Write a sector (256 words = 512 bytes) 
        _ata_outsw(ata_state.io_base + ATA_DATA, buffer, 256);
        
        // Move buffer pointer 
        buffer = (u8_t*)buffer + 512;
        
        // Flush the write cache on the last sector 
        if (i == count - 1) {
            // The drive will set BSY again after receiving the last word 
            _ata_wait_not_busy();
        }
    }
    
    return 0;  // Success 
}

/* =============================== Private Functions =============================== */

// Input multiple words from ATA port 
static void _ata_insw(u16_t port, void *addr, int count) {
    asm ("rep insw" : "+D"(addr), "+c"(count) : "d"(port) : "memory");
}

// Output multiple words to ATA port 
static void _ata_outsw(u16_t port, void *addr, int count) {
    asm ("rep outsw" : "+S"(addr), "+c"(count) : "d"(port) : "memory");
}

// Delay for approximately 400ns by reading the alternate status 
static void _ata_400ns_delay() {
    // Reading the alternate status register takes about 100ns
    port_byte_in(ata_state.control_base + ATA_ALT_STATUS);
    port_byte_in(ata_state.control_base + ATA_ALT_STATUS);
    port_byte_in(ata_state.control_base + ATA_ALT_STATUS);
    port_byte_in(ata_state.control_base + ATA_ALT_STATUS);
}

// Poll the status register until an operation completes
static int _ata_poll_status() {
    u8_t status;
    
    // Wait for BSY to clear 
    _ata_400ns_delay();  // Initial delay to allow status to update 
    
    while ((port_byte_in(ata_state.io_base + ATA_STATUS) & ATA_STATUS_BSY));
    
    // Check for error conditions 
    status = port_byte_in(ata_state.io_base + ATA_STATUS);
    if (status & ATA_STATUS_ERR) {
        return _ata_process_error();
    }

    // Check for drive fault
    if (status & ATA_STATUS_DF) {
        return -1;  // Drive fault error 
    }

    // Ensure that data is ready to be transferred 
    if (!(status & ATA_STATUS_DRQ)) {
        return -2;  // Data not ready 
    }

    return 0;  // Success 
}

// Select a drive on a particular bus 
static int _ata_select_drive(int bus, int drive) {
    u16_t io_base, control_base;
    u8_t drive_head;
    
    // Set the correct base addresses
    if (bus == 0) {
        io_base = PRIMARY_IO_BASE;
        control_base = PRIMARY_CONTROL_BASE;
    } else {
        io_base = SECONDARY_IO_BASE;
        control_base = SECONDARY_CONTROL_BASE;
    }
    
    // Update the state
    ata_state.io_base = io_base;
    ata_state.control_base = control_base;
    ata_state.current_drive = drive;
    
    // Prepare drive/head value 
    drive_head = ATA_ALWAYS_SET_BITS | ATA_LBA_BIT;
    if (drive == 1) 
        drive_head |= ATA_DRIVE_BIT;

    
    // Select drive 
    port_byte_out(io_base + ATA_DRIVE_HEAD, drive_head);
    _ata_400ns_delay();  // Wait for drive to be selected 
    
    return 0;
}

// Perform a software reset on the current bus 
static void _ata_soft_reset() {
    // Set SRST bit in device control register 
    port_byte_out(ata_state.control_base + ATA_DEVICE_CONTROL, ATA_DCR_SRST);
    
    // Wait at least 5us 
    _ata_400ns_delay();
    _ata_400ns_delay();
    
    // Clear SRST bit in device control register 
    port_byte_out(ata_state.control_base + ATA_DEVICE_CONTROL, 0);
    
    // Wait for BSY to clear on the selected drive 
    _ata_wait_not_busy();
}

// Wait for the BSY bit to clear 
static void _ata_wait_not_busy() {
    // Timeout could be implemented with a counter here 
    while (port_byte_in(ata_state.io_base + ATA_STATUS) & ATA_STATUS_BSY);
}

// Wait for the drive to be ready (BSY clear and RDY set) 
static void _ata_wait_ready() {
    u8_t status;
    
    // Timeout could be implemented with a counter here 
    do {
        status = port_byte_in(ata_state.io_base + ATA_STATUS);
    } while ((status & ATA_STATUS_BSY) || !(status & ATA_STATUS_RDY));
}

// Process an error that occurred during an ATA operation 
static int _ata_process_error() {
    u8_t error = port_byte_in(ata_state.io_base + ATA_ERROR);
    
    // Return the specific error code for detailed error handling 
    return -(100 + error);  // Negative error code with error register value 
}

// Get identify data from a drive 
static u16_t* _ata_get_identify_data(int bus, int drive, u16_t* buffer) {
    u8_t status, lba_mid, lba_hi;
    
    // Select the drive 
    _ata_select_drive(bus, drive);
    
    // Set feature registers to 0 
    port_byte_out(ata_state.io_base + ATA_SECTOR_COUNT, 0);
    port_byte_out(ata_state.io_base + ATA_LBA_LO, 0);
    port_byte_out(ata_state.io_base + ATA_LBA_MID, 0);
    port_byte_out(ata_state.io_base + ATA_LBA_HI, 0);
    
    // Send IDENTIFY command 
    port_byte_out(ata_state.io_base + ATA_COMMAND, ATA_CMD_IDENTIFY);
    
    // Check if drive exists 
    status = port_byte_in(ata_state.io_base + ATA_STATUS);
    if (status == 0) {
        return 0;  // Drive does not exist 
    }
    
    // Wait for BSY to clear 
    _ata_wait_not_busy();
    
    // Check for ATAPI or SATA signature 
    lba_mid = port_byte_in(ata_state.io_base + ATA_LBA_MID);
    lba_hi = port_byte_in(ata_state.io_base + ATA_LBA_HI);
    
    if (lba_mid != 0 || lba_hi != 0) {
        // This is not an ATA device, or it aborted the command 
        return 0;
    }
    
    // Wait for data ready or error 
    status = port_byte_in(ata_state.io_base + ATA_STATUS);
    
    // Check for error 
    if (status & ATA_STATUS_ERR) {
        return 0;
    }
    
    // Wait for data ready 
    while (!(status & ATA_STATUS_DRQ)) {
        status = port_byte_in(ata_state.io_base + ATA_STATUS);
        
        if (status & ATA_STATUS_ERR) {
            return 0;
        }
    }
    
    // Read the identify data 
    _ata_insw(ata_state.io_base + ATA_DATA, buffer, 256);
    
    return buffer;
}

