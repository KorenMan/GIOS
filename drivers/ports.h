#pragma once

typedef unsigned char u8_t; 
typedef unsigned short u16_t;

u8_t port_byte_in(u16_t port);
void port_byte_out(u16_t port, u8_t data);
