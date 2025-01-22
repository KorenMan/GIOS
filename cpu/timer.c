#include "timer.h"
#include "isr.h"
#include "../lib/ports.h"
#include "../lib/types.h"
#include "../drivers/vga-driver.h"

u32_t timer_tick;

/* =============================== Public Functions =============================== */

void timer_callback(registers_t registers) {
    vga_print("aaaa\n");
}

void timer_init(u32_t frequency) {
    irq_set_handler(32, (void *)(timer_callback));

    // Init the PIT 
    // Hardware clock at 1193180 Hz
    // u32_t divisor = 1193180 / frequency;
    // port_byte_out(0x43, 0x36);
    // port_byte_out(0x40, (divisor & 0xFF));
    // port_byte_out(0x40, ((divisor >> 8) & 0xFF));
    vga_print("alskdfasdf"); 
    timer_tick = 0;
}
