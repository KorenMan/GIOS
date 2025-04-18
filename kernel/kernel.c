#include "../drivers/vga-driver.h"
#include "../drivers/keyboard-driver.h"
#include "../drivers/ata-driver.h"
#include "../drivers/fat16.h"
#include "../lib/memory.h"

extern void test_ata();

void main() {
    vga_clear_screen();

    mem_init();
    
    if (ata_init() != 0) {
        vga_print("Failed to initialize ATA driver\n");
        return;
    }
    
    test_ata();

    // enabling interrupts
    isr_install();
    keyboard_init();

    while (1);
}
