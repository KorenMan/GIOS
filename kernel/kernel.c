#include "../drivers/vga.h"
#include "../drivers/keyboard.h"
#include "../drivers/ata.h"

void main() {
    vga_clear_screen();

    ata_init();
    
    // enabling interrupts
    isr_install();
    keyboard_init();

}
