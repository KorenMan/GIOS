#include "../drivers/vga-driver.h"
#include "../drivers/keyboard-driver.h"
#include "../storage/disk.h"

void main() {
    vga_clear_screen();

    ata_init();
    
    // enabling interrupts
    isr_install();
    keyboard_init();

}
