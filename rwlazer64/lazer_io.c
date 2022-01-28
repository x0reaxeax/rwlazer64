#include "lazer64.h"

#include <stdio.h>
#include <ctype.h>

/**
* str to data type size(char *str_type);
*/
size_t strtodtsz(char* str_type, bool print_info_only) {
    if (NULL == str_type && !(print_info_only)) { 
        LAZER_SETLASTERR("strtodtsz()", LAZER_ERROR_NULLPTR, false);
        return 0; 
    }
    
    char* c_str_types[] = {
        "char",		/* 00 */
        "short",    /* 01 */
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

    if (NULL != str_type) {
        str_type[strcspn(str_type, "\n")] = 0;
    }
    
    for (size_t i = 0; i < n_types; i++) {
        if (print_info_only) {
            char *bytes_str = "bytes";
            char spaces[12] = { 0 };
            if (ctypes_dsz[i] == 1) {
                bytes_str = "byte";
            }
            size_t pad = 12 - strlen(c_str_types[i]);
            if (pad < 12) {
                memset(spaces, ' ', pad);
            }
            printf(" * '%s' %s - %zu %s\n", c_str_types[i], spaces, ctypes_dsz[i], bytes_str);
            continue;
        }

        if (strncmp(str_type, c_str_types[i], 16) == EXIT_SUCCESS) {
            return ctypes_dsz[i];
        }
    }

    return 0;
}


bool check_hex_input_lookup(byte *str) {
    if (NULL == str) { 
        LAZER_SETLASTERR("check_hex_input_fast()", LAZER_ERROR_NULLPTR, false);
        return false; 
    }

    char hex_lookup_table[256] = {
        ['0'] = 1,['1'] = 1,['2'] = 1,['3'] = 1,['4'] = 1,
        ['5'] = 1,['6'] = 1,['7'] = 1,['8'] = 1,['9'] = 1,
        ['a'] = 1,['b'] = 1,['c'] = 1,['d'] = 1,['e'] = 1,['f'] = 1,
        ['A'] = 1,['B'] = 1,['C'] = 1,['D'] = 1,['E'] = 1,['F'] = 1
    };

    size_t slen = strlen((const char *) str);
    for (int i = 0; i < slen; i++) {
        if (!hex_lookup_table[str[i]]) {
            return false;
        }
    }

    return true;
}

bool check_hex_input(byte *str) {
    if (NULL == str) {
        LAZER_SETLASTERR("check_hex_input()", LAZER_ERROR_NULLPTR, false);
        return false;
    }

    size_t slen = strlen((const char *) str);
    for (size_t i = 0; i < slen; i++) {
        if (!isxdigit(str[i])) {
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
    *output = strtoull((const char*)input_buf, &endptr, input_base);
    if (*endptr != 0 && *endptr != '\n') {
        input_base = BASE_ERROR;
    }

    return input_base;
}

int lazer64_get_numinput(uint64_t *output, size_t nbytes) {
    if (0 == nbytes) {
        return LAZER_ERROR;
    }

    uint64_t result = 0;
    char *input_buffer = malloc(sizeof(char) * nbytes + 2); /* 0x prefix */
    if (NULL == input_buffer) {
        LAZER_SETLASTERR("lazer64_get_numinput()", errno, false);
        return LAZER_ERROR;
    }

    fgets(input_buffer, (int) nbytes, stdin);
    numbase_t res_base = strtou64((byte *) input_buffer, &result);
    free(input_buffer);

    if (BASE_ERROR == result) {
        return LAZER_ERROR;
    }

    *output = result;
    return LAZER_SUCCESS;
}

int lazer64_get_bytedata(byte *output, size_t nbytes) {
    if (NULL == output) {
        LAZER_SETLASTERR("lazer64_get_bytedata()", LAZER_ERROR_NULLPTR, false);
        return LAZER_ERROR;
    }

    size_t i, j;
    size_t slen = 0;
    size_t input_len = 0;
    char *input_data = malloc(sizeof(char) * LAZER_BYTEDATA_MAXLEN);
    if (NULL == input_data) {
        LAZER_SETLASTERR("lazer64_get_bytedata()", errno, false);
        return LAZER_ERROR;
    }
    printf("[*] Byte data: ");
    fflush(stdout);

    while ((input_data[input_len] = getchar()) != '\n' && input_len < LAZER_BYTEDATA_MAXLEN) {
        input_len++;
    }

    slen = strlen(input_data);

    for (i = 0, j = 0; i < nbytes && j < slen; i++, j+=2) {
        char byte_to_convert[2] = { 0 };
        char *endptr = NULL;
        int hexbyte = 0;

        /* omit spaces */
        while (input_data[j] == ' ') {
            j++;
        }

        memcpy(byte_to_convert, &input_data[j], 2);
        hexbyte = (int) strtoul(byte_to_convert, &endptr, BASE_HEXADECIMAL);
        
        if ((uintptr_t) endptr - ((uintptr_t) byte_to_convert) != 2) {
            LAZER_SETLASTERR("lazer64_get_bytedata()", LAZER_ERROR_CONVERSION, false);
            break;
        }

        if (hexbyte <= UINT8_MAX) { /* pointless, but log debugging info anyway */
            output[i] = (byte) hexbyte;
        }
    }

    free(input_data);

    if (i != nbytes) {
        log_write(LOG_DEBUG, "Conversion byte count mismatch");
        return LAZER_ERROR;
    }

    return LAZER_SUCCESS;
}