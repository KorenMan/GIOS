#pragma once

#include "../lib/types.h"

#define VIDEO_MEMORY 0xb8000
#define SCREEN_WIDTH 80 
#define SCREEN_HEIGHT 25

// First nibble represent the background color
// Second nibble represent the foreground color
#define WHITE_ON_BLACK 0x0f

// Cursor Control Ports
#define CONTROL_REGISTER 0x3d4
#define DATA_REGISTER 0x3d5
#define OFFSET_LOW 0x0f
#define OFFSET_HIGH 0x0e

void vga_clear_screen();
void vga_print(const char *str);
void vga_backspace();
void vga_color(u8_t color);
