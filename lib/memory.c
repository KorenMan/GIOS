#include "memory.h"

void mem_set(void *buff, u8_t val, u32_t size) {
    for (u32_t i = 0; i < size; i++) {
        ((u8_t *)buff)[i] = (u8_t)val;
    }
}

void mem_cpy(void *dest, const void *src, u32_t size) {
    for (u32_t i = 0; i < size; i++) {
        ((u8_t *)dest)[i] = ((const u8_t *)src)[i];
    }
}