#include "keyboard-driver.h"
#include "vga-driver.h"
#include "../cpu/isr.h"
#include "../lib/ports.h"
#include "../lib/types.h"

const char characters[][2] = {
    "?", "?", "1", "2", "3", "4", "5", "6", "7", "8",
    "9", "0", "-", "=", "?", "?", "Q", "W", "E", "R",
    "T", "Y", "U", "I", "O", "P", "[", "]", "?", "?",
    "A", "S", "D", "F", "G", "H", "J", "K", "L", ";",
    "\"", "`", "?", "\\", "Z", "X", "C", "V", "B", "N",
    "M", ",", ".", "/", "?", "?", "?", " "
};

/* =============================== Public Functions =============================== */

void keyboard_callback(registers_t registers) {
    u8_t scancode = port_byte_in(0x60);
    
    if (scancode > 58)
        return;

    switch (scancode) {
        case 0x0E:
            vga_backspace();
            break;
        case 0x1C:
            vga_print("\n");
            break;
        default:
            vga_print(characters[scancode]);
            break;
    }
}

void keyboard_init() {
    irq_set_handler(33, (void *)(keyboard_callback));
}
