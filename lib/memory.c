#include "memory.h"

static u8_t mem_seg[SEG_SIZE];
static mem_block_t *mem_start;

static mem_block_t *_find_best_mem_block(mem_block_t *mem, u32_t size); 
static mem_block_t *_merge_with_next_free_block(mem_block_t *current_block);
static void _merge_with_previous_free_block(mem_block_t *current_block);

/* =============================== Public Functions =============================== */

void mem_init() {
    mem_start = (mem_block_t *) mem_seg;
    mem_start->size = SEG_SIZE - MEM_SIZE;
    mem_start->prev = NULL;
    mem_start->next = NULL;
}

void *mem_alloc(u32_t size) {
    mem_block_t *best_mem_block = _find_best_mem_block(mem_start, size);
    
    if (!best_mem_block) 
        return NULL;

    // get the size allocated 
    best_mem_block->size = best_mem_block->size - size - MEM_SIZE;

    mem_block_t *mem_allocated = (mem_block_t *) (best_mem_block + MEM_SIZE + best_mem_block->size);
    mem_allocated->size = size;
    mem_allocated->in_use = true;
    mem_allocated->prev = best_mem_block;
    mem_allocated->next = best_mem_block->next;

    if (best_mem_block->next)
        best_mem_block->next->prev = mem_allocated;
    best_mem_block->next = mem_allocated;

    // return pointer to the new allocated memory 
    return (void *) (mem_allocated + MEM_SIZE);
}

void mem_free(void *ptr) {
    if (!ptr)
        return;

    // get the mem block of the pointer
    mem_block_t *mem_block = (mem_block_t *) ((u8_t *)ptr - MEM_SIZE);

    if (!mem_block) 
        return;

    mem_block->in_use = false;

    // merge unin_use blocks
    mem_block = _merge_with_next_free_block(mem_block);
    _merge_with_previous_free_block(mem_block);
}

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

/* =============================== Private Functions =============================== */

static mem_block_t *_find_best_mem_block(mem_block_t *mem, u32_t size) {
    // init result with invalid values
    mem_block_t *best_mem_block = NULL;
    u32_t best_block_size = SEG_SIZE + 1;

    // look for the smallest unin_use memory block
    mem_block_t *current_block = mem;
    while (current_block) {
        if ((!current_block->in_use) &&
            (best_block_size >= current_block->size >= size + MEM_SIZE)) {
            best_mem_block = current_block;
            best_block_size = current_block->size; 
        }

        current_block = current_block->next;
    }

    return best_mem_block;
}


static mem_block_t *_merge_with_next_free_block(mem_block_t *current_block) {
    mem_block_t *next_block = current_block->next;
    if (next_block && !next_block->in_use) {
        // Expand current block by absorbing the next block
        current_block->size += next_block->size + MEM_SIZE;

        // Remove next block from the linked list
        current_block->next = next_block->next;
        if (current_block->next)
            current_block->next->prev = current_block;
    }
    return current_block;
}

static void _merge_with_previous_free_block(mem_block_t *current_block) {
    mem_block_t *prev_block = current_block->prev;
    if (prev_block && !prev_block->in_use) {
        // Expand previous block by absorbing the current block
        prev_block->size += current_block->size + MEM_SIZE;

        // Remove current block from the linked list
        prev_block->next = current_block->next;
        if (current_block->next)
            current_block->next->prev = prev_block;
    }
}
