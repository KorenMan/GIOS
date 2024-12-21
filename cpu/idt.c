#include "idt.h"

idt_entry_t idt[256];   
idt_ptr_t idt_ptr;

extern void idt_flush(u32_t);

/* =============================== Public Functions =============================== */

void init_idt() {
    idt_ptr.limit = sizeof(idt_entry_t) * 256 - 1;
    idt_ptr.base = &idt;


}   

void set_idt_gate(u8_t n, u32_t base, u16_t selector, u8_t attr) {

}

