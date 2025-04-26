#include "../drivers/fat16.h"
#include "../drivers/vga-driver.h"
#include "../lib/types.h"
#include "../lib/memory.h"
#include "../lib/string.h"

// Define test buffer sizes
#define TEST_BUFFER_SIZE 1024
#define FILENAME_MAX_LENGTH 13  // 8.3 format + null terminator

// Helper function to print test results
void print_test_result(const char* test_name, bool result) {
    vga_print("[");
    if (result) {
        vga_print("PASS");
    } else {
        vga_print("FAIL");
    }
    vga_print("] ");
    vga_print(test_name);
    vga_print("\n");
}

// Helper function to print file content
void print_file_info(file_t* file) {
    char size_str[16];
    vga_print("File size: ");
    str_int_to_hex(file->entry.file_size, size_str, 16);
    vga_print(size_str);
    vga_print(" bytes\n");
    
    vga_print("First cluster: ");
    str_int_to_hex(file->entry.first_cluster_low, size_str, 16);
    vga_print(size_str);
    vga_print("\n");
    
    vga_print("Attributes: ");
    str_int_to_hex(file->entry.attributes, size_str, 16);
    vga_print(size_str);
    vga_print("\n");
}

// Test FAT16 initialization
bool test_fat16_init() {
    return fat16_init();
}

// Test FAT16 format
bool test_fat16_format() {
    return fat16_format();
}

// Test file creation and closing
bool test_file_create_close() {
    const char* test_filename = "TEST.TXT";
    file_t file = fat16_create(test_filename);

    if (!file.is_open) {
        return false;
    }
    
    fat16_close(&file);
    return !file.is_open;
}

// Test file opening
bool test_file_open() {
    const char* test_filename = "TEST.TXT";
    file_t file = fat16_open(test_filename);
    
    if (!file.is_open) {
        return false;
    }
    
    fat16_close(&file);
    return true;
}

// Test file writing
bool test_file_write() {
    const char* test_filename = "WRITE.TXT";
    const char* test_data = "This is test data for FAT16 fs.";
    u32_t test_data_len = str_len(test_data);
    file_t file = fat16_create(test_filename);
    if (!file.is_open) {
        return false;
    }


    u32_t bytes_written = fat16_write(&file, test_data, test_data_len, 0);
    fat16_close(&file);
    
    return bytes_written == test_data_len;
}

// Test file reading
bool test_file_read() {
    const char* test_filename = "WRITE.TXT";
    const char* expected_data = "This is test data for FAT16 fs.";
    u32_t expected_len = str_len(expected_data);
    
    char buffer[TEST_BUFFER_SIZE];
    mem_set(buffer, 0, TEST_BUFFER_SIZE);
    
    file_t file = fat16_open(test_filename);
    if (!file.is_open) {
        return false;
    }
    
    u32_t bytes_read = fat16_read(&file, buffer, TEST_BUFFER_SIZE, 0);
    fat16_close(&file);

    if (bytes_read != expected_len) {
        return false;
    }

    return str_cmp(buffer, expected_data);
}

// Test file deletion
bool test_file_delete() {
    const char* test_filename = "TEST.TXT";
    file_t filet = fat16_create(test_filename);

    bool delete_result = fat16_delete(test_filename);

    if (!delete_result) {
        return false;
    }

    // Try to open the deleted file - should fail
    file_t file = fat16_open(test_filename);
    bool file_gone = !file.is_open;
    
    if (file.is_open) {
        fat16_close(&file);
    }
    
    return file_gone;
}
bool test_large_file() {
    const char* filename = "LARGE.TXT";
    char large_buffer[TEST_BUFFER_SIZE];
    
    // Create a pattern in the buffer
    for (u32_t i = 0; i < TEST_BUFFER_SIZE; i++) {
        large_buffer[i] = 'A' + (i % 26);
    }
    
    // Create and write to a large file
    file_t file = fat16_create(filename);
    if (!file.is_open) {
        return false;
    }
    
    u32_t total_written = 0;
    u32_t write_size = TEST_BUFFER_SIZE;
    // Write 4 times to ensure we span multiple clusters
    for (int i = 0; i < 4; i++) {
        u32_t bytes_written = fat16_write(&file, large_buffer, write_size, 0);
        if (bytes_written != write_size) {
            fat16_close(&file);
            return false;
        }
        total_written += bytes_written;
    }
    
    fat16_close(&file);
    
    // Read back the file and verify
    file = fat16_open(filename);
    if (!file.is_open) {
        return false;
    }
    
    char read_buffer[TEST_BUFFER_SIZE];
    bool read_matches = true;
    
    for (int i = 0; i < 4; i++) {
        mem_set(read_buffer, 0, TEST_BUFFER_SIZE);
        u32_t bytes_read = fat16_read(&file, read_buffer, TEST_BUFFER_SIZE, 0);
        
        if (bytes_read != TEST_BUFFER_SIZE) {
            read_matches = false;
            break;
        }
        
        // Compare the pattern
        for (u32_t j = 0; j < TEST_BUFFER_SIZE; j++) {
            if (read_buffer[j] != ('A' + (j % 26))) {
                read_matches = false;
                break;
            }
        }
        
        if (!read_matches) {
            break;
        }
    }
    
    fat16_close(&file);
    fat16_delete(filename);
    
    return read_matches;
}

// Test file renaming
bool test_file_rename() {
    const char* old_name = "OLD.TXT";
    const char* new_name = "NEW.TXT";
    const char* test_content = "This is a file to test renaming.";
    
    // Create a test file
    file_t file = fat16_create(old_name);
    if (!file.is_open) {
        return false;
    }

    fat16_write(&file, test_content, str_len(test_content), 0);
    fat16_close(&file);
    
    // Rename the file
    bool rename_result = fat16_rename(old_name, new_name);
    if (!rename_result) {
        return false;
    }
    
    // Check that the old file doesn't exist anymore
    file_t old_file = fat16_open(old_name);
    if (old_file.is_open) {
        fat16_close(&old_file);
        return false;
    }
    
    // Check that the new file exists and has the same content
    file_t new_file = fat16_open(new_name);
    if (!new_file.is_open) {
        return false;
    }
    
    char buffer[TEST_BUFFER_SIZE];
    mem_set(buffer, 0, TEST_BUFFER_SIZE);
    
    u32_t bytes_read = fat16_read(&new_file, buffer, TEST_BUFFER_SIZE, 0);
    fat16_close(&new_file);
    return bytes_read == str_len(test_content) && str_cmp(buffer, test_content);
}

// Test sequential file creation to test directory entries
bool test_multiple_files() {
    const char* base_name = "FILE";
    char filename[FILENAME_MAX_LENGTH];
    const char* test_content = "Test content";
    bool all_succeeded = true;
    
    // Create 10 files
    for (int i = 0; i < 10; i++) {
        // Create filename like FILE0.TXT, FILE1.TXT, etc.
        mem_set(filename, 0, FILENAME_MAX_LENGTH);
        mem_cpy(filename, base_name, 4);
        filename[4] = '0' + i;
        filename[5] = '.';
        filename[6] = 'T';
        filename[7] = 'X';
        filename[8] = 'T';
        
        file_t file = fat16_create(filename);
        if (!file.is_open) {
            all_succeeded = false;
            break;
        }
        
        u32_t bytes_written = fat16_write(&file, test_content, str_len(test_content), 0);
        if (bytes_written != str_len(test_content)) {
            all_succeeded = false;
        }
        
        fat16_close(&file);
        
        if (!all_succeeded) {
            break;
        }
    }
    
    // Open and verify all files
    if (all_succeeded) {
        for (int i = 0; i < 10; i++) {
            mem_set(filename, 0, FILENAME_MAX_LENGTH);
            mem_cpy(filename, base_name, 4);
            filename[4] = '0' + i;
            filename[5] = '.';
            filename[6] = 'T';
            filename[7] = 'X';
            filename[8] = 'T';
            
            file_t file = fat16_open(filename);
            if (!file.is_open) {
                all_succeeded = false;
                break;
            }
            
            char buffer[TEST_BUFFER_SIZE];
            mem_set(buffer, 0, TEST_BUFFER_SIZE);
            
            u32_t bytes_read = fat16_read(&file, buffer, TEST_BUFFER_SIZE, 0);
            if (bytes_read != str_len(test_content) || !str_cmp(buffer, test_content)) {
                all_succeeded = false;
            }
            
            fat16_close(&file);
            
            if (!all_succeeded) {
                break;
            }
        }
    }
    
    // Clean up all files
    for (int i = 0; i < 10; i++) {
        mem_set(filename, 0, FILENAME_MAX_LENGTH);
        mem_cpy(filename, base_name, 4);
        filename[4] = '0' + i;
        filename[5] = '.';
        filename[6] = 'T';
        filename[7] = 'X';
        filename[8] = 'T';
        
        fat16_delete(filename);
    }
    
    return all_succeeded;
}

void run_all_tests() {
    vga_print("FAT16 FILESYSTEM TESTER\n");
    
    bool init_result = test_fat16_init();
    print_test_result("FAT16 Initialization", init_result);
    
    if (!init_result) {
        vga_print("\nInitialization failed. Attempting to format...\n");
        bool format_result = test_fat16_format();
        print_test_result("FAT16 Format", format_result);
        
        if (!format_result) {
            vga_print("\nFormat failed. Cannot continue tests.\n");
            return;
        }
        
        // Re-initialize after format
        init_result = test_fat16_init();
        print_test_result("FAT16 Re-initialization", init_result);
        
        if (!init_result) {
            vga_print("\nRe-initialization failed. Cannot continue tests.\n");
            return;
        }
    }
    
    print_test_result("File Create and Close", test_file_create_close());
    
    print_test_result("File Open", test_file_open());
    print_test_result("File Write", test_file_write());
    print_test_result("File Read", test_file_read());
    print_test_result("File Rename", test_file_rename());
    print_test_result("File Delete", test_file_delete());
    print_test_result("Large File", test_large_file());
    print_test_result("Multiple Files", test_multiple_files());
}

void test_fat16() {
    run_all_tests();
}