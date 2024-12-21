#pragma once

#include "../lib/types.h"

typdef struct {
    u16_t offset_low;
    u16_t selector;
    u8_t zero;
    u8_t flags;
    u16_t offset_high;   
} __attribute__((packed)) idt_entry_t;

typdef struct {  
    u16_t limit;
    u32_t base;
} __attribute__((packed)) idt_ptr_t;

void init_idt();
void set_idt_gate(u8_t n, u32_t base, u16_t selector, u8_t attr);
