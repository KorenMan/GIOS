#include "memory.h"

static u8_t mem_area[SEG_SIZE];
static mem_block_t *mem_start;

static mem_block_t *_find_best_mem_block(mem_block_t *mem, u32_t size); 

/* =============================== Public Functions =============================== */

void mem_init() {
    mem_start = (mem_block_t *) mem_area;
    mem_start->size = SEG_SIZE - MEM_SIZE;
}

void *mem_alloc(u32_t size) {
    mem_block_t *best_mem_block = _find_best_mem_block(mem_start, size);
    
    if (!best_mem_block) { 
        return NULL;
    }

    // get the size allocated 
    best_mem_block->size = best_mem_block->size - size - MEM_SIZE;

    mem_block_t *mem_allocated = (men_block_t *) (best_mem_block + MEM_SIZE + best_mem_block->size);
    mem_allocated->size = size;
    mem_allocated->used = true;
    mem_allocated->prev = best_mem_block;
    mem_allocated->next = best_mem_block->next;

    if (best_mem_block->next){
        best_mem_block->next->prev = mem_allocated;
    }
    best_mem_block->next = mem_allocated;

    // return pointer to the new allocated memory 
    return (void *) (mem_allocated + MEM_SIZE);
}

/* =============================== Private Functions =============================== */

static mem_block_t *_find_best_mem_block(mem_block_t *mem, u32_t size) {
    // init result with invalid values
    mem_block_t *best_mem_block = NULL;
    u32_t best_block_size = SEG_SIZE + 1;

    // look for the smallest unused memory block
    mem_block_t *current_block = mem;
    while (current_block) {
        if ((!current_block->used) &&
            (best_block_size >= current_block->size >= size + MEM_SIZE)) {
            best_mem_block = current_block;
            best_mem_block_size = current_block->size; 
        }

        current_block = current_block->next;
    }

    return best_mem_block;
}
