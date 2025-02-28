#include "../drivers/vga.h"
#include "../drivers/keyboard.h"
#include "../drivers/ata.h"
#include "../lib/string.h"

extern void test_ata_write();

void main() {
    vga_clear_screen();

    if (ata_init() != 0) {
        vga_print("Failed to initialize ATA driver\n");
        return;
    }

    // enabling interrupts
    isr_install();
    keyboard_init();

    test_ata_write();

    while (1);
}
