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

char *str_chr(const char *str, char ch) {
    while (*str) {
        if (*str == ch) {
            return (char *)str;
        }
        str++;
    }
    if (ch == '\0') {
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

bool str_split(const char *str, char ch, char *part1, char *part2, char *part3) {    
    const char *pos1 = str_chr(str, ch);
    if (!pos1) {
        while (*str) {
            *part1++ = *str++;
        }
        *part1 = '\0';
        part2[0] = '\0';
        part3[0] = '\0';
        return false;
    }
    
    while (str < pos1) {
        *part1++ = *str++;
    }
    *part1 = '\0';
    
    // Skip the first delimiter.
    str++;
    
    // Find the second occurrence of the delimiter.
    const char *pos2 = str_chr(str, ch);
    if (!pos2) {
        // Only one delimiter found: copy remainder of str into part2.
        while (*str) {
            *part2++ = *str++;
        }
        *part2 = '\0';
        part3[0] = '\0';
        return false;
    }
    
    // Copy from the current position until the second delimiter into part2.
    while (str < pos2) {
        *part2++ = *str++;
    }
    *part2 = '\0';
    
    // Skip the second delimiter.
    str++;
    
    // Copy the rest of the string into part3.
    while (*str) {
        *part3++ = *str++;
    }
    *part3 = '\0';
    
    return true;
}
