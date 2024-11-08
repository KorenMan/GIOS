#include "ports.h"
#include "vga-driver.h"

static inline u16_t _get_offset(u8_t row, u8_t column);
static inline u8_t _get_row(u16_t offset);
static u16_t _get_cursor_offset();
static void _set_cursor_offset(u16_t offset);
static inline void _set_char_at(char character, u16_t offset);
static void _scroll();

/* =============================== Public Functions =============================== */

void vga_clear_screen() {
    for (int i = 0; i < SCREEN_WIDTH * SCREEN_HEIGHT; i++)
        _set_char_at(' ', i * 2);
    _set_cursor_offset(_get_offset(0, 0));
}

void vga_printk(const char *str) {
    u16_t offset = _get_cursor_offset();
    
    for (int i = 0; str[i] != 0; i++) {
        if (offset >= SCREEN_WIDTH * SCREEN_WIDTH * 2) {
            _scroll();
            offset = _get_offset(_get_row(offset) + 1, 0);
        } else if (str[i] == '\n') {
            offset = _get_offset(_get_row(offset) + 1, 0);
        } else {
            _set_char_at(str[i], (offset * 2));
            offset++;
        }
    }

    _set_cursor_offset(offset);
}

/* =============================== Private Functions =============================== */

static inline u16_t _get_offset(u8_t row, u8_t column) {
    return row * SCREEN_WIDTH + column;
}

static inline u8_t _get_row(u16_t offset) {
    return offset / SCREEN_WIDTH;
}

static u16_t _get_cursor_offset() {
    port_byte_out(CONTROL_REGISTER, OFFSET_HIGH);
    u16_t cursor_offset = ((u16_t)port_byte_in(DATA_REGISTER)) << 8;
    port_byte_out(CONTROL_REGISTER, OFFSET_LOW);
    cursor_offset |= port_byte_in(DATA_REGISTER);
    return cursor_offset;
}

static void _set_cursor_offset(u16_t offset) {
    port_byte_out(CONTROL_REGISTER, OFFSET_HIGH);
    port_byte_out(DATA_REGISTER, (u8_t)(offset >> 8));
    port_byte_out(CONTROL_REGISTER, OFFSET_LOW);
    port_byte_out(DATA_REGISTER, (u8_t)(offset & 0xFF));
}

static inline void _set_char_at(char character, u16_t offset) {
    volatile u8_t *video_memory = (u8_t *)VIDEO_MEMORY;
    video_memory[offset] = character;
    video_memory[offset + 1] = WHITE_ON_BLACK;
}

// copy every line on the video memory to the line above it and clear a new line
static void _scroll() {
    volatile u8_t *source = (u8_t *)(VIDEO_MEMORY + _get_offset(0, 1)); 
    volatile u8_t *destination = (u8_t *)VIDEO_MEMORY; 
    
    while ((void *)source < (void *)(VIDEO_MEMORY + (SCREEN_WIDTH * SCREEN_HEIGHT))) {
        *destination = *source;
        destination++;
        source++;
    }
    
    while ((void *)destination < (void *)(VIDEO_MEMORY + (SCREEN_WIDTH * SCREEN_HEIGHT))) {
        *destination = ' ';
        destination += 2;
    }
}
