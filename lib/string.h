#pragma once

#include "types.h"

void str_int_to_hex(int num, char *str, int size);
void str_int_to_dec(int num, char *str, int size);
char *str_chr(const char *str, char ch);
u32_t str_len(const char *str);
bool str_cmp(const char *str1, const char *str2);
char str_to_upper(char chr);
char *str_cat(char *dest, const char *src);
bool str_split(const char *str, char ch, char *part1, char *part2, char *part3);