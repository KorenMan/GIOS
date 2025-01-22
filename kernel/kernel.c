#include "../drivers/vga-driver.h"
#include "../drivers/keyboard-driver.h"
#include "../cpu/timer.h"

void main() {
    vga_clear_screen();

    // enabling interrupts
    isr_install();
    keyboard_init();
}
