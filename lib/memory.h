#pragma once

#include "types.h"

#define NULL (void *) 0
#define SEG_SIZE 4*1024
#define MEM_SIZE sizeof(mem_block_t)

typedef struct mem_block {
    u32_t size;
    bool in_use;
    struct mem_block *prev;
    struct mem_block *next;
} mem_block_t;

void mem_init(); 
void *mem_alloc(u32_t size);
void mem_free(void *ptr);
