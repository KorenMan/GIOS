#pragma once

#include "types.h"

void str_int_to_hex(int num, char *str, int size);
void str_int_to_dec(int num, char *str, int size);
char *str_chr(const char *str, int ch);
u32_t str_len(const char *str);
bool str_cmp(const char *str1, const char *str2);
char str_to_upper(char chr);
char *str_tok(char *str, const char *delim);

