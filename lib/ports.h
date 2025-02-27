#pragma once

#include "../lib/types.h"

u8_t port_byte_in(u16_t port);
void port_byte_out(u16_t port, u8_t data);

u16_t port_word_in(u16_t port);
void port_word_out(u16_t port, u16_t data);
