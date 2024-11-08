#pragma once

#define VIDEO_MEMORY 0xB8000
#define SCREEN_WIDTH 80 
#define SCREEN_HEIGHT 25

// First nibble represent the background color
// Second nibble represent the foreground color
#define WHITE_ON_BLACK 0x0F

// Cursor Control Ports
#define CONTROL_REGISTER 0x3D4
#define DATA_REGISTER 0x3D5
#define OFFSET_LOW 0x0F
#define OFFSET_HIGH 0x0E

void vga_clear_screen();
void vga_printk(const char *str);
