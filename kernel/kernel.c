#include "../drivers/vga-driver.h"
#include "../drivers/keyboard-driver.h"
#include "../drivers/ata-driver.h"
#include "../drivers/fat16.h"

extern void test_ata();
extern void test_fat16();

void main() {
    vga_clear_screen();
    
    if (ata_init() != 0) {
        vga_print("Failed to initialize ATA driver\n");
        return;
    }
    
    test_ata();

    test_fat16();

   // enabling interrupts
   isr_install();
   keyboard_init();

   while (1);
}
