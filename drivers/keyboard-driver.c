#include "keyboard-driver.h"
#include "vga-driver.h"
#include "../cpu/isr.h"
#include "../kernel/shell.h"
#include "../lib/ports.h"
#include "../lib/types.h"
#include "../lib/string.h"

static char buffer[256];

const char characters[][2] = {
    "?", "?", "1", "2", "3", "4", "5", "6", "7", "8",
    "9", "0", "-", "=", "?", "?", "q", "w", "e", "r",
    "t", "y", "u", "i", "o", "p", "[", "]", "\n", "?",
    "a", "s", "d", "f", "g", "h", "j", "k", "l", ";",
    "\"", "`", "?", "\\", "z", "x", "c", "v", "b", "n",
    "m", ",", ".", "/", "?", "?", "?", " "
};

static u32_t tick = 0;
static u8_t last_scancode = 0; 

/* =============================== Public Functions =============================== */

void keyboard_callback(registers_t registers) {
    u8_t scancode = port_byte_in(0x60);
    
    if (scancode > 58) {
        tick = 5;
        return;
    }
    
    if (scancode == last_scancode) {
        if (tick < 5) {
            tick++;
            return;
        }
        tick = 0;
    } else {
        tick = 0;
        last_scancode = scancode;
    }

    if (scancode == 0x0e) {
        if (str_len(buffer) > 0) {
            buffer[str_len(buffer) - 1] = '\0';
            vga_backspace();
        }
        return;
    }
    
    if (str_cmp(characters[scancode], "\n")) {
        shell_cmd(buffer);
        buffer[0] = '\0';
        return;
    }

    str_cat(buffer, characters[scancode]);
    vga_print(characters[scancode]);
}

void keyboard_init() {
    buffer[0] = '\0';
    irq_set_handler(34, (void *)(keyboard_callback));
}
