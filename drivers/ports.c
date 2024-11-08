#include "ports.h"

u8_t port_byte_in(u16_t port) {
    u8_t data;
    asm("in %%dx, %%al" : "=a" (data) : "d" (port));
    return data;
}

void port_byte_out(u16_t port, u8_t data) {
    asm("out %%al, %%dx" : : "a" (data), "d" (port));
}
