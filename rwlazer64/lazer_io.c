#include "lazer64.h"

#include <stdio.h>

/**
* str to data type size(char *str_type);
*/
size_t strtodtsz(char* str_type, bool print_info_only) {
    if (NULL == str_type) { return 0; }
    
    char* c_str_types[] = {
        "char",		/* 00 */
        "short"		/* 01 */
        "int",		/* 02 */
        "long",		/* 03 */
        "llong",	/* 04 */
        "float",	/* 05 */
        "double",	/* 06 */
        "ldouble",	/* 07 */
        "ptr",		/* 08 */
        "int8",		/* 09 */
        "int16",	/* 10 */
        "int32",	/* 11 */
        "int64"		/* 12 */
    };

    const size_t ctypes_dsz[] = { 
                                sizeof(char),
                                sizeof(short),
                                sizeof(int),
                                sizeof(long),
                                sizeof(long long),
                                sizeof(float),
                                sizeof(double),
                                sizeof(long double),
                                sizeof(void*),
                                sizeof(int8_t), sizeof(int16_t), sizeof(int32_t), sizeof(int64_t)
    };

    size_t n_types = sizeof(c_str_types) / sizeof(c_str_types[0]);

    
    str_type[strcspn(str_type, "\n")] = 0;
    
    for (size_t i = 0; i < n_types; i++) {
        if (true == print_info_only) {
            printf(" * '%s' - %zu bytes\n", c_str_types[i], ctypes_dsz[i]);
            continue;
        }

        if (strncmp(str_type, c_str_types[i], 16) == EXIT_SUCCESS) {
            return ctypes_dsz[i];
        }
    }

    return 0;
}


bool check_hex_input(byte *str) {
    if (NULL == str) { return false; }

    char hex_lookup_table[256] = {
        ['0'] = 1,['1'] = 1,['2'] = 1,['3'] = 1,['4'] = 1,
        ['5'] = 1,['6'] = 1,['7'] = 1,['8'] = 1,['9'] = 1,
        ['a'] = 1,['b'] = 1,['c'] = 1,['d'] = 1,['e'] = 1,['f'] = 1,
        ['A'] = 1,['B'] = 1,['C'] = 1,['D'] = 1,['E'] = 1,['F'] = 1
    };

    for (int i = 0; i < strlen((const char *) str); i++) {
        if (!hex_lookup_table[str[i]]) {
            return false;
        }
    }

    return true;
}

numbase_t strtou64(byte* input_buf, uintptr_t* output) {
    if (NULL == input_buf || NULL == output) {
        return BASE_ERROR;
    }

    input_buf[strcspn(input_buf, "\n")] = 0;

    if (strlen(input_buf) < 1) {
        return BASE_ERROR;
    }

    numbase_t input_base = BASE_DECIMAL;
    if (_strnicmp(input_buf, "0x", 2) == EXIT_SUCCESS) {
        if (check_hex_input(&input_buf[2])) {
            input_base = BASE_HEXADECIMAL;
        } else {
            return BASE_ERROR;
        }
    }

    char* endptr = NULL;
    uintptr_t result = strtoull((const char*)input_buf, &endptr, input_base);
    if (*endptr != 0 && *endptr != '\n') {
        input_base = BASE_ERROR;
    }

    *output = result;

    return input_base;
}