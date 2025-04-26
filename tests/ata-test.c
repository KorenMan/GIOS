#include "../drivers/vga-driver.h"
#include "../drivers/ata-driver.h"
#include "../lib/string.h"

// Test buffer size (in sectors)
#define TEST_SECTOR_COUNT 2
#define SECTOR_SIZE 512

// Test function to verify ATA write functionality
void test_ata() {
    // Test buffer for writing data (1024 bytes = 2 sectors)
    u8_t write_buffer[TEST_SECTOR_COUNT * SECTOR_SIZE];
    u8_t verify_buffer[TEST_SECTOR_COUNT * SECTOR_SIZE];
    int result;
    char status_str[16];
    
    vga_print("ATA Write Test Starting...\n");
    
    // Select a test partition (for example, starting at LBA 1000 with 100 sectors)
    if (ata_select_partition(0, 1000) != 0) {
        vga_print("Failed to select partition\n");
        return;
    }
    
    // Fill write buffer with test pattern
    for (int i = 0; i < TEST_SECTOR_COUNT * SECTOR_SIZE; i++) {
        write_buffer[i] = (u8_t)(i & 0xFF);
    }
    
    // Write test pattern to LBA 0 of selected partition (which is LBA 1000 on disk)
    vga_print("Writing test data...\n");
    result = ata_write_sectors(0, TEST_SECTOR_COUNT, write_buffer);
    
    // Check result
    str_int_to_hex(result, status_str, sizeof(status_str));
    vga_print("Write result code: ");
    vga_print(status_str);
    vga_print("\n");
    
    if (result != 0) {
        vga_print("Write operation failed\n");
        return;
    }
    
    // Verification: Read back the sectors we just wrote
    vga_print("Reading back data for verification...\n");
    result = ata_read_sectors(0, TEST_SECTOR_COUNT, verify_buffer);
    
    // Check result
    str_int_to_hex(result, status_str, sizeof(status_str));
    vga_print("Read result code: ");
    vga_print(status_str);
    vga_print("\n");
    
    if (result != 0) {
        vga_print("Read operation failed\n");
        return;
    }
    
    // Compare buffers
    vga_print("Comparing data...\n");
    int match = 1;
    for (int i = 0; i < TEST_SECTOR_COUNT * SECTOR_SIZE; i++) {
        if (write_buffer[i] != verify_buffer[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        vga_print("Success! Data verified correctly.\n");
    } else {
        vga_print("Error: Data mismatch detected.\n");
    }
    
    vga_print("ATA Write Test Completed\n");
}
