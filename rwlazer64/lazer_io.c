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

bool check_data_size(size_t data_size) {
    switch (data_size) {
        case 1:             /* char */
            return true;
            break;

        case 2:             /* short */
            return true;
            break;

        case 4:             /* int */
            return true;
            break;

        case 8:             /* long long */
            return true;
            break;

#ifdef LAZER_FUTURE         /* long double, but right now i have absolutely no idea on how to implement it in the first place.. */
        case 16:
            return true;
            break;
#endif /* !LAZER_FUTURE */

        default:
            break;
    }

    return false;
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

/* zavolaj mi, povedz co treba */
int lazer64_get_numinput(uint64_t *output, bool str_datasz_input, size_t nbytes) {
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
    
    /* check if we accept str data sizes */
    if (str_datasz_input) {
        result = strtodtsz(input_buffer, false);
    } 
    
    if (0 == result) {
        strtou64((byte *) input_buffer, &result);
    }
    
    free(input_buffer);

    /* strtodatasz returns 0 (0 == BASE_ERROR) on failure */
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

    if (nbytes > (LAZER_BYTEDATA_MAXLEN - 1) || 0 == nbytes) {
        LAZER_SETLASTERR("lazer64_get_bytedata()", LAZER_ERROR_OUTBOUNDS, false);
        return LAZER_ERROR;
    }

    size_t i;
    int64_t j;
    size_t input_len = 0;
    size_t wbytes = nbytes * 2;

    int shift = 0, pad = 2;
    int retcode = LAZER_SUCCESS;
    char *input_data = malloc(sizeof(char) * LAZER_BYTEDATA_MAXLEN);
    if (NULL == input_data) {
        LAZER_SETLASTERR("lazer64_get_bytedata()", errno, false);
        return LAZER_ERROR;
    }

    memset(input_data, 0, LAZER_BYTEDATA_MAXLEN);
    
    printf("[*] Byte data: ");
    fflush(stdout);

    while ((input_data[input_len] = getchar()) != '\n' && input_len < LAZER_BYTEDATA_MAXLEN) {
        if (isxdigit(input_data[input_len])) {
            /* count valid hex char */
            input_len++;
        }
    }

    input_data[strcspn(input_data, "\n")] = 0;
    if ((input_len % 2) != 0) {
        /* check if leading zero is missing from first byte */
        shift = 1;
    }

    if (input_len < 2) {
        /* one char byte entry */
        pad = 1;
    }

    if (wbytes < input_len) {
        input_len = wbytes;
    }

    /* auto convert to LE */
    for (i = 0, j = (input_len - pad); i < nbytes && j >= 0; i++, j -= pad) {
        char byte_to_convert[3] = { 0 };
        char *endptr = NULL;
        ptrdiff_t cpy_diff;
        int hexbyte = 0;

        /* omit spaces */
        while (input_data[j] == ' ') {
            j--;
        }

        memcpy(byte_to_convert, &input_data[j], pad);
        byte_to_convert[2] = 0;
        hexbyte = (int) strtoul(byte_to_convert, &endptr, BASE_HEXADECIMAL);
        
        cpy_diff = (uintptr_t) endptr - ((uintptr_t) byte_to_convert);
        
        if (cpy_diff > pad) {
            LAZER_SETLASTERR("lazer64_get_bytedata()", LAZER_ERROR_CONVERSION, false);
            retcode = LAZER_ERROR;
            break;
        }

        if (shift == 1 && j == 1) {
            /* last byte with missing zero-pad */
            pad = 1;
        }

        if (hexbyte <= UINT8_MAX) { /* pointless, but log debugging info anyway */
            output[i] = (byte) hexbyte;
        }
    }

    free(input_data);

    return retcode;
}

void lazer64_ftox_calc(void) {
    char fs_input[256] = { 0 };

    printf("[*] Float value: ");
    fflush(stdout);

    fgets(fs_input, sizeof(fs_input), stdin);

    float input = strtof(fs_input, NULL);
    union {
        float fpval;
        uint64_t uxval;
    } f2u64 = { .fpval = input };

    printf("[+] F2X: %f -> %#04llx\n", input, f2u64.uxval);
}