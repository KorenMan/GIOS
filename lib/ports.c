#include "ports.h"

u8_t port_byte_in(u16_t port) {
    u8_t data;
    asm ("in %%dx, %%al" : "=a" (data) : "d" (port));
    return data;
}

void port_byte_out(u16_t port, u8_t data) {
    asm ("out %%al, %%dx" : : "a" (data), "d" (port));
}

u16_t port_word_in(u16_t port) {
    u16_t data;
    asm ("in %%dx, %%ax" : "=a" (data) : "d" (port));
    return data;
}

void port_word_out(u16_t port, u16_t data) {
    asm ("out %%ax, %%dx" : : "a" (data), "d" (port));
}
