#ifndef _RWLAZER64_BASE_H_
#define _RWLAZER64_BASE_H_

#ifdef _WIN32
#include <Windows.h>
#endif
#include <stdbool.h>

#define RWLAZER_VERSION_MAJOR	0
#define RWLAZER_VERSION_MINOR	70
#define RWLAZER_VERSION_BUILD	1000

#define LAZER_READ				0x10
#define LAZER_WRITE				0x20

#define LAZER_THREADS_MAX		16

#define LAZER_ERROR_NULLPTR									0xFFFFDEAD

#define LAZER_ADDRESS_INVALID								0xFFFFFFFFDEADBEEF

typedef unsigned char           byte;
typedef unsigned char           uchar;

typedef signed char             int8_t;
typedef unsigned char           uint8_t;

typedef signed short            int16_t;
typedef unsigned short          uint16_t;

typedef unsigned int            uint;
typedef signed int              int32_t;
typedef unsigned int            uint32_t;

typedef signed long long        int64_t;
typedef unsigned long long      uint64_t;

#ifndef _UINTPTR_T_DEFINED
typedef unsigned long long      uintptr_t;
#endif
#ifndef _PTRDIFF_T_DEFINED
typedef long long               ptrdiff_t
#endif
typedef long long               off_t;

typedef volatile bool           lzrmutex;

typedef enum _nbase {
    BASE_ERROR = 0,
    BASE_DECIMAL = 10,
    BASE_HEXADECIMAL = 16
} num_base;

typedef enum _lazer_ctypes {
    LAZER_INT8  = sizeof(char),
    LAZER_INT16 = sizeof(short),
    LAZER_INT32 = sizeof(int),
    LAZER_INT64 = sizeof(long long),
    LAZER_PTR64 = sizeof(void *)
} lazer_ctype;

/**
* Opcode Instruction Struct for signature scanning with wildcard mask support
*/
typedef struct {
    unsigned char opcode;
    bool wildcard;
} opcode64;

/* Linked list for running threads */
typedef struct __lazer_thread {
    HANDLE      thread_handle;
    lzrmutex    mutex;
    DWORD       handle_id;
    struct __lazer_thread* next;
} lazerthread;

#endif