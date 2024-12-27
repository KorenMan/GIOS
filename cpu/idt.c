#include "idt.h"

idt_entry_t idt[256];   
idt_ptr_t idt_ptr;

extern void idt_flush(u32_t);

/* =============================== Public Functions =============================== */

void idt_init() {
    idt_ptr.limit = sizeof(idt_entry_t) * 256 - 1;
    idt_ptr.base = (u32_t)&idt;

    asm volatile ("lidtl (%0)" : : "r" (&idt_ptr));
}   

void idt_set_gate(u8_t n, u32_t base) {
    idt[n].offset_low = (u16_t)(base & 0xFFFF);
    idt[n].selector = 0x08;
    idt[n].zero = 0;
    idt[n].flags = 0x8E;
    idt[n].offset_high = (u16_t)((base >> 16) & 0xFFFF);
}

