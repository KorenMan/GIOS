#include "string.h"

void str_int_to_hex(int num, char *str, int size) {
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
    for (; i < size - 1; i++) {
        str[i] = hex_digits[num % 16];
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

void str_int_to_dec(int num, char *str, int size) {
    char hex_digits[] = "0123456789";
    int i = 0;

    // Convert integer to hexadecimal
    for (; i < size - 1; i++) {
        str[i] = hex_digits[num % 10];
        num /= 10;
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

bool str_cmp(const char *str1, const char *str2) {
    if (str_len(str1) != str_len(str2)) {
        return false;
    }
    for (int i = 0; str1[i] != '\0'; i++) {
        if (str1[i] != str2[i]) {
            return false;
        }
    }
    return true;
}

char str_to_upper(char chr) {
    if (chr >= 'a' && chr <= 'z') {
        return chr - 'a' + 'A';
    }
    return chr;
}

char *str_tok(char *str, const char *delim) {
    static char *next;
    if (str) {
        next = str;
    }
    if (!next) {
        return '\0';
    }

    char *start = next;

    // Skip leading delimiters
    while (*start && str_chr(delim, *start)) {
        start++;
    }

    if (*start == '\0') {
        next = '\0';
        return '\0';
    }

    char *token = start;

    // Find end of token
    while (*next && !str_chr(delim, *next)) {
        next++;
    }

    if (*next) {
        *next = '\0';
        next++;
    } else {
        next = '\0';
    }

    return token;
}

char *str_cat(char *dest, const char *src) {
    char *ptr = dest;

    while (*ptr) {
        ptr++;
    }

    while (*src) {
        *ptr = *src;
        ptr++;
        src++;
    }

    *ptr = '\0';

    return dest;
}