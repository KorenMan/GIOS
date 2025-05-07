#include "shell.h"
#include "../drivers/fat16.h"
#include "../drivers/vga-driver.h"
#include "../lib/string.h"

void shell_cmd(char *input) {
    char cmd[256];
    char arg1[256];
    char arg2[256];
    str_split(input, ' ', cmd, arg1, arg2);

    if (str_cmp(cmd, "help")) {
        vga_print("\n=== GIOS Shell Commands ===\n");
        vga_print("help      - Display this help message\n");
        vga_print("clear     - Clear the screen\n");
        vga_print("echo      - Display a message\n");
        vga_print("ls        - List files in current directory\n");
        vga_print("create    - Create a new file\n");
        vga_print("write     - Write content to a file\n");
        vga_print("read      - Read content from a file\n");
        vga_print("delete    - Delete a file\n");
        vga_print("rename    - Rename a file\n");
        vga_print("color     - Change the shell color\n");
    } else if (str_cmp(cmd, "clear")) {
        vga_clear_screen();
    } else if (str_cmp(cmd, "echo")) {
        vga_print("\n");
        if (arg1[0] != '\0') {
            vga_print(arg1);
            if (arg2[0] != '\0') {
                vga_print(" ");
                vga_print(arg2);
            }
        } else {
            vga_print("ECHO is on.");
        }
        vga_print("\n");
    } else if (str_cmp(cmd, "ls")) {
        vga_print("\n");
        fat16_list_files();
        vga_print("\n");
    } else if (str_cmp(cmd, "\0")) {
        vga_print("\n");
    } else if (str_cmp(cmd, "create")) {
        vga_print("\n");
        if (arg1[0] == '\0') {
            vga_print("Usage: create <filename>\n");
        } else {
            file_t file = fat16_create(arg1);
            if (file.is_open) {
                vga_print("File created successfully");
                fat16_close(&file);
            } else {
                vga_print("Problem creating file");
            }
            vga_print("\n");
        }
    } else if (str_cmp(cmd, "write")) {
        vga_print("\n");
        if (arg1[0] == '\0') {
            vga_print("Usage: write <filename> <content>\n");
        } else {
            file_t file = fat16_open(arg1);
            if (file.is_open) {
                if (arg2[0] != '\0') {
                    u32_t written = fat16_write(&file, arg2, str_len(arg2), 0);
                    vga_print("Wrote ");
                    char size_str[16];
                    str_int_to_dec(written, size_str, 16);
                    vga_print(size_str);
                    vga_print(" bytes to file");
                } else {
                    vga_print("No content provided to write");
                }
                fat16_close(&file);
            } else {
                vga_print("Could not open file");
            }
        }
        vga_print("\n");
    } else if (str_cmp(cmd, "read")) {
        vga_print("\n");
        if (arg1[0] == '\0') {
            vga_print("Usage: read <filename>\n");
        } else {
            file_t file = fat16_open(arg1);
            if (file.is_open) {
                char buffer[256];
                u32_t bytes_read = fat16_read(&file, buffer, 255, 0);
                buffer[bytes_read] = '\0';
                
                vga_print("Content: ");
                vga_print(buffer);
                fat16_close(&file);
            } else {
                vga_print("Could not open file");
            }
        }
        vga_print("\n");
    } else if (str_cmp(cmd, "delete")) {
        vga_print("\n");
        if (arg1[0] == '\0') {
            vga_print("Usage: delete <filename>\n");
        } else {
            if (fat16_delete(arg1)) {
                vga_print("File deleted successfully");
            } else {
                vga_print("Problem deleting file");
            }
        }
        vga_print("\n");
    } else if (str_cmp(cmd, "rename")) {
        vga_print("\n");
        if (arg1[0] == '\0' || arg2[0] == '\0') {
            vga_print("Usage: rename <old_name> <new_name>\n");
        } else {
            if (fat16_rename(arg1, arg2)) {
                vga_print("File renamed successfully");
            } else {
                vga_print("Problem renaming file");
            }
        }
        vga_print("\n");
    } else if (str_cmp(cmd, "color")) {
        vga_print("\n");
        if (str_len(arg1) > 2) {
            vga_print("Usage: color <byte in hex>\n");
        } else {
            int num = str_hex_to_num(arg1);
            if (arg1[0] == '\0') {
                vga_color(0x0f);
            } else if (num < 0) {
                vga_print("Usage: color <byte in hex>\n");
            } else {
                vga_color(num); 
            }
        }
        vga_print("\n");
    } else {
        vga_print("\n");
        vga_print("Command: '");
        vga_print(cmd);
        vga_print("' not found\n");
    }
   
    vga_print("GIOS:/$ ");
}
