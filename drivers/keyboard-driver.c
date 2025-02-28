#include "keyboard-driver.h"
#include "vga-driver.h"
#include "../cpu/isr.h"
#include "../lib/ports.h"
#include "../lib/types.h"

const char characters[][2] = {
    "?", "?", "1", "2", "3", "4", "5", "6", "7", "8",
    "9", "0", "-", "=", "?", "?", "Q", "W", "E", "R",
    "T", "Y", "U", "I", "O", "P", "[", "]", "\n", "?",
    "A", "S", "D", "F", "G", "H", "J", "K", "L", ";",
    "\"", "`", "?", "\\", "Z", "X", "C", "V", "B", "N",
    "M", ",", ".", "/", "?", "?", "?", " "
};

static u32_t tick = 0;
static u8_t last_scancode = 0; 

/* =============================== Public Functions =============================== */

void keyboard_callback(registers_t registers) {
    u8_t scancode = port_byte_in(0x60);
    
    if (scancode == last_scancode) {
        if (tick < 12) {
            tick++;
            return;
        }
    } else {
        tick = 0;
        last_scancode = scancode;
    }

    if (scancode == 0x0E) {
        vga_backspace();
        return;
    }
    
    if (scancode > 58)
        return;
    
    vga_print(characters[scancode]);
}

void keyboard_init() {
    irq_set_handler(34, (void *)(keyboard_callback));
}
