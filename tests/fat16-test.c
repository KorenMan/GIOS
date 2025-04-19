#include "../drivers/vga-driver.h"
#include "../drivers/ata-driver.h"
#include "../lib/string.h"
#include "../drivers/fat16.h"

// Buffer sizes
#define TEST_SECTOR_COUNT 2
#define SECTOR_SIZE 512
#define TEST_BUFFER_SIZE 100

// Test content
static const char *TEST_FILE_CONTENT = "This is test file 1 content for validating FAT16 operations.";
static const char *TEST_FILE2_CONTENT = "This is test file 2 with different content to verify multiple files.";

// Device data for FAT16 callbacks
typedef struct {
    int bus;
    int drive;
} disk_device_t;

// Forward declarations
int disk_read_sector(void *device_data, u32_t sector, u8_t *buffer, u32_t sector_size);
int disk_write_sector(void *device_data, u32_t sector, const u8_t *buffer, u32_t sector_size);

// Global variables
static disk_device_t disk_device = { 0, 0 }; // Primary master
static fat16_filesystem_t fs;

/**
 * Test ATA and FAT16 functionality
 * 
 * @return 0 if all tests pass, negative value if any test fails
 */
int test_ata_fat16() {
    vga_print("ATA and FAT16 Test Starting...\n");
    
    // Initialize ATA driver
    vga_print("Initializing ATA driver...\n");
    if (ata_init() != 0) {
        vga_print("FAILED: ATA driver initialization failed\n");
        return -1;
    }
    vga_print("ATA driver initialized\n");
    
    // First test basic ATA read/write
    vga_print("\n--- Testing ATA Read/Write ---\n");
    
    // Test buffers
    u8_t write_buffer[TEST_SECTOR_COUNT * SECTOR_SIZE];
    u8_t verify_buffer[TEST_SECTOR_COUNT * SECTOR_SIZE];
    char status_str[16];
    int result;
    
    // Select a test partition (starting at LBA 1000 with 100 sectors)
    // This should be a non-critical area of the disk for testing
    if (ata_select_partition(0, 10) != 0) {
        vga_print("Failed to select partition for ATA test\n");
        return -2;
    }
    
    // Fill write buffer with test pattern
    for (int i = 0; i < TEST_SECTOR_COUNT * SECTOR_SIZE; i++) {
        write_buffer[i] = (u8_t)('a');
    }
    
    // Write test pattern
    vga_print("Writing test data...\n");
    result = ata_write_sectors(0, TEST_SECTOR_COUNT, write_buffer);
    
    // Check result
    str_int_to_hex(result, status_str, sizeof(status_str));
    vga_print("Write result code: ");
    vga_print(status_str);
    vga_print("\n");
    
    if (result != 0) {
        vga_print("Write operation failed\n");
        return -3;
    }
    
    // Read back the sectors we just wrote
    vga_print("Reading back data for verification...\n");
    result = ata_read_sectors(0, TEST_SECTOR_COUNT, verify_buffer);
    
    // Check result
    str_int_to_hex(result, status_str, sizeof(status_str));
    vga_print("Read result code: ");
    vga_print(status_str);
    vga_print("\n");
    
    if (result != 0) {
        vga_print("Read operation failed\n");
        return -4;
    }
    
    // Compare buffers
    //!!!!!!!!!
    while(1);
    vga_print("Comparing data...\n");
    for (int i = 0; i < TEST_SECTOR_COUNT * SECTOR_SIZE; i++) {
        if (write_buffer[i] != verify_buffer[i]) {
            vga_print("Error: Data mismatch detected.\n");
            return -5;
        }
    }
    
    vga_print("ATA read/write test passed\n");
    
    // Now test FAT16 functionality
    vga_print("\n--- Testing FAT16 Filesystem ---\n");
    
    // Select FAT16 partition (adjust these values to match your actual FAT16 partition)
    // For example, if FAT16 partition starts at LBA 2048 with 32768 sectors
    if (ata_select_partition(2048, 32768) != 0) {
        vga_print("Failed to select FAT16 partition\n");
        return -6;
    }
    
    // Initialize the FAT16 filesystem
    vga_print("Initializing FAT16 filesystem...\n");
    result = fat16_init(&fs, &disk_device, disk_read_sector, disk_write_sector);
    if (result != 0) {
        vga_print("Failed to initialize FAT16 filesystem: ");
        str_int_to_hex(result, status_str, sizeof(status_str));
        vga_print(status_str);
        vga_print("\n");
        return -7;
    }
    
    // Validate filesystem parameters
    if (fs.bpb.bytes_per_sector != 512) {
        vga_print("Unexpected bytes per sector\n");
        return -8;
    }
    
    // Check filesystem type
    char fs_type[9] = {0};
    mem_cpy(fs_type, fs.bpb.fs_type, 8);
    vga_print("Filesystem type: ");
    vga_print(fs_type);
    vga_print("\n");
    
    if (str_cmp(fs_type, "FAT16") != 0) {
        vga_print("Not a FAT16 filesystem\n");
        return -9;
    }
    
    // Test file operations
    vga_print("\n--- Testing File Operations ---\n");
    
    fat16_file_t file;
    char read_buffer[TEST_BUFFER_SIZE] = {0};
    
    // Test file 1
    vga_print("Testing file 1 (TEST1.TXT)...\n");
    
    // Try to open or create file 1
    result = fat16_open_file(&fs, "TEST1.TXT", &file);
    if (result != 0 && result != FAT16_ERROR_NOT_FOUND) {
        vga_print("Unexpected error opening file 1\n");
        return -10;
    }
    
    // If file doesn't exist, we would create it
    // NOTE: Your FAT16 implementation may need a creation function
    // This is simplified for the test
    if (result == FAT16_ERROR_NOT_FOUND) {
        vga_print("File not found, would create here\n");
        // Placeholder for file creation
        // For this test, we'll assume open succeeded
    } else {
        vga_print("File exists, continuing with test\n");
    }
    
    // Write to file 1
    vga_print("Writing to file 1...\n");
    result = fat16_write_file(&file, TEST_FILE_CONTENT, str_len(TEST_FILE_CONTENT));
    if (result != str_len(TEST_FILE_CONTENT)) {
        vga_print("Failed to write to file 1\n");
        fat16_close_file(&file);
        return -11;
    }
    
    // Close file 1
    fat16_close_file(&file);
    
    // Reopen file 1 for reading
    vga_print("Reopening file 1 for reading...\n");
    result = fat16_open_file(&fs, "TEST1.TXT", &file);
    if (result != 0) {
        vga_print("Failed to reopen file 1\n");
        return -12;
    }
    
    // Read from file 1
    vga_print("Reading from file 1...\n");
    mem_set(read_buffer, 0, TEST_BUFFER_SIZE);
    result = fat16_read_file(&file, read_buffer, TEST_BUFFER_SIZE - 1);
    if (result < 0) {
        vga_print("Failed to read file 1\n");
        fat16_close_file(&file);
        return -13;
    }
    
    // Verify file 1 content
    if (str_cmp(read_buffer, TEST_FILE_CONTENT) != 0) {
        vga_print("File 1 content verification failed\n");
        vga_print("Expected: ");
        vga_print(TEST_FILE_CONTENT);
        vga_print("\nGot: ");
        vga_print(read_buffer);
        vga_print("\n");
        fat16_close_file(&file);
        return -14;
    }
    
    // Close file 1
    fat16_close_file(&file);
    vga_print("File 1 test passed\n");
    
    // Test file 2
    vga_print("\nTesting file 2 (TEST2.TXT)...\n");
    
    // Try to open or create file 2
    result = fat16_open_file(&fs, "TEST2.TXT", &file);
    if (result != 0 && result != FAT16_ERROR_NOT_FOUND) {
        vga_print("Unexpected error opening file 2\n");
        return -15;
    }
    
    // If file doesn't exist, we would create it
    if (result == FAT16_ERROR_NOT_FOUND) {
        vga_print("File not found, would create here\n");
        // Placeholder for file creation
    } else {
        vga_print("File exists, continuing with test\n");
    }
    
    // Write to file 2
    vga_print("Writing to file 2...\n");
    result = fat16_write_file(&file, TEST_FILE2_CONTENT, str_len(TEST_FILE2_CONTENT));
    if (result != str_len(TEST_FILE2_CONTENT)) {
        vga_print("Failed to write to file 2\n");
        fat16_close_file(&file);
        return -16;
    }
    
    // Close file 2
    fat16_close_file(&file);
    
    // Reopen file 2 for reading
    vga_print("Reopening file 2 for reading...\n");
    result = fat16_open_file(&fs, "TEST2.TXT", &file);
    if (result != 0) {
        vga_print("Failed to reopen file 2\n");
        return -17;
    }
    
    // Read from file 2
    vga_print("Reading from file 2...\n");
    mem_set(read_buffer, 0, TEST_BUFFER_SIZE);
    result = fat16_read_file(&file, read_buffer, TEST_BUFFER_SIZE - 1);
    if (result < 0) {
        vga_print("Failed to read file 2\n");
        fat16_close_file(&file);
        return -18;
    }
    
    // Verify file 2 content
    if (str_cmp(read_buffer, TEST_FILE2_CONTENT) != 0) {
        vga_print("File 2 content verification failed\n");
        fat16_close_file(&file);
        return -19;
    }
    
    // Close file 2
    fat16_close_file(&file);
    vga_print("File 2 test passed\n");
    
    // Test directory reading
    vga_print("\n--- Testing Directory Listing ---\n");
    
    fat16_dir_t dir;
    fat16_dir_entry_t entry;
    bool found_file1 = false;
    bool found_file2 = false;
    
    // Open root directory
    result = fat16_open_dir(&fs, "/", &dir);
    if (result != 0) {
        vga_print("Failed to open root directory\n");
        return -20;
    }
    
    // List directory contents
    vga_print("Directory contents:\n");
    while (fat16_read_dir(&dir, &entry) == 0) {
        // Skip deleted entries and empty entries
        if (entry.name[0] == 0 || entry.name[0] == 0xE5) {
            continue;
        }
        
        // Extract filename (8.3 format)
        char filename[13] = {0};
        int i, j = 0;
        
        // Get filename portion
        for (i = 0; i < 8 && entry.name[i] != ' '; i++) {
            filename[j++] = entry.name[i];
        }
        
        // Add extension if present
        if (entry.ext[0] != ' ') {
            filename[j++] = '.';
            for (i = 0; i < 3 && entry.ext[i] != ' '; i++) {
                filename[j++] = entry.ext[i];
            }
        }
        
        // Display file info
        vga_print("- ");
        vga_print(filename);
        vga_print(" (");
        str_int_to_hex(entry.file_size, status_str, sizeof(status_str));
        vga_print(status_str);
        vga_print(" bytes)\n");
        
        // Check if our test files are found
        if (str_cmp(filename, "TEST1.TXT") == 0) {
            found_file1 = true;
        } else if (str_cmp(filename, "TEST2.TXT") == 0) {
            found_file2 = true;
        }
    }
    
    // Close directory
    fat16_close_dir(&dir);
    
    // Check if test files were found
    if (!found_file1) {
        vga_print("TEST1.TXT not found in directory listing\n");
        return -21;
    }
    
    if (!found_file2) {
        vga_print("TEST2.TXT not found in directory listing\n");
        return -22;
    }
    
    vga_print("Directory listing test passed\n");
    
    // All tests passed
    vga_print("\n=== All Tests Passed Successfully! ===\n");
    return 0;
}

// FAT16 callback for reading sectors via ATA
int disk_read_sector(void *device_data, u32_t sector, u8_t *buffer, u32_t sector_size) {
    disk_device_t *disk = (disk_device_t *)device_data;
    
    // Calculate absolute LBA based on current partition
    u32_t abs_lba = ata_state.current_partition.start_lba + sector;
    
    // Read the sector using ATA driver
    return ata_read_sectors(abs_lba, 1, buffer);
}

// FAT16 callback for writing sectors via ATA
int disk_write_sector(void *device_data, u32_t sector, const u8_t *buffer, u32_t sector_size) {
    disk_device_t *disk = (disk_device_t *)device_data;
    
    // Calculate absolute LBA based on current partition
    u32_t abs_lba = ata_state.current_partition.start_lba + sector;
    
    // Write the sector using ATA driver
    return ata_write_sectors(abs_lba, 1, (void *)buffer);
}