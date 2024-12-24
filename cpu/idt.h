#pragma once

#include "../lib/types.h"

typedef struct {
    u16_t offset_low;
    u16_t selector;
    u8_t zero;
    u8_t flags;
    u16_t offset_high;   
} __attribute__((packed)) idt_entry_t;

typedef struct {  
    u16_t limit;
    u32_t base;
} __attribute__((packed)) idt_ptr_t;

void idt_init();
void idt_set_gate(u8_t n, u32_t base);
