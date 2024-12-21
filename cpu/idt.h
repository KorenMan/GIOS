#pragma once

#include "../lib/types.h"

struct {
    u16_t offset_low;
    u16_t selector;
    u8_t zero;
    u8_t type_attr;
    u16_t offset_high;   
} __attribute__((packed)) idt_t;
