#pragma once

#include "types.h"

#define NULL (void *) 0

void mem_set(void *buff, u8_t val, u32_t size);
void mem_cpy(void *dest, const void *source, u32_t size); 
