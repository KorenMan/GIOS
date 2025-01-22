#pragma once

#include "isr.h"
#include "../lib/types.h"

void timer_callback(registers_t registers);
void timer_init(u32_t frequency);
