#include "../drivers/vga-driver.h"
#include "../drivers/keyboard-driver.h"
#include "../drivers/ata-driver.h"
#include "../drivers/fat16.h"
#include "../lib/memory.h"

extern void test_ata();
extern void test_fat16();

void main() {
    vga_clear_screen();

    if (ata_init()) {
        vga_print("Failed to initialize ATA driver\n");
        asm volatile ("hlt");
        while (1);
    }
    
    if (ata_select_partition(0, 1000)) {
        vga_print("Failed to select partition\n");
        asm volatile ("hlt");
        while (1);
    }

    if (!fat16_init()) {
        vga_print("Failed to initialize fat16\n");
        if (!fat16_format()) {
            vga_print("Format failed. Cannot continue.\n");
            asm volatile ("hlt");
            while (1);
        }
        if (!fat16_init()) {
            vga_print("Failed to initialize fat16 after formating\n");
            asm volatile ("hlt");
            while (1);
        }
    }
    
    vga_print("GIOS:/$ ");

    // test_ata();

    // test_fat16();

   // enabling interrupts
   isr_install();
   keyboard_init();

   while (1);
}
