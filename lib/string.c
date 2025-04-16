#include "string.h"

void int_to_hex_string(int num, char *str, int size) {
    char hex_digits[] = "0123456789ABCDEF";
    int i = 0;
    
    // Handle case where num is 0
    if (num == 0) {
        if (size > 1) {
            str[i++] = '0';
            str[i] = '\0';
        }
        return;
    }

    // Convert integer to hexadecimal
    while (num > 0 && i < size - 1) {  // Ensure we don't write beyond the buffer
        str[i++] = hex_digits[num % 16];
        num /= 16;
    }

    str[i] = '\0';

    // Reverse the string (since we filled it backwards)
    for (int j = 0, k = i - 1; j < k; j++, k--) {
        char temp = str[j];
        str[j] = str[k];
        str[k] = temp;
    }
}

char *str_chr(const char *str, int ch) {
    while (*str) {
        if (*str == (char)ch) {
            return (char *)str;
        }
        str++;
    }
    if ((char)ch == '\0') {
        return (char *)str;
    }
    return 0;
}

u32_t str_len(const char *str) {
    u32_t len = 0;
    while (str[len]) {
        len++;
    }
    return len;
}