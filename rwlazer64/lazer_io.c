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

	const size_t ctypes_dsz[] = { sizeof(char),
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

num_base read_input_numdata(uintptr_t* num_output) {
	if (NULL == num_output) {
		return BASE_ERROR;
	}

	byte input_buffer[2048];
	fgets((char*)input_buffer, sizeof(input_buffer), stdin);
	
	char* hex_index = strchr(input_buffer, 'x');
	char* endptr = NULL;	/* later.. */

	*num_output = 0;
	
	if (NULL != hex_index) {
		/* hex or invalid input */
		uint16_t index = (uint16_t)(hex_index - input_buffer);

		if (index != 0 && index != 1) {
			return BASE_ERROR;
		}

		*num_output = strtoull((char*)input_buffer, &endptr, BASE_HEXADECIMAL);
		if (errno == ERANGE) {
			return BASE_ERROR;
		}


		return BASE_HEXADECIMAL;
	}

	*num_output = strtoull((char*)input_buffer, &endptr, BASE_DECIMAL);

	return (endptr != input_buffer) ? BASE_DECIMAL : BASE_ERROR;
}