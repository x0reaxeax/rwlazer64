#ifndef _RWLAZER64_BASE_H_
#define _RWLAZER64_BASE_H_

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS			0
#define EXIT_FAILURE			1
#endif

#define RWLAZER_VERSION_MAJOR	0
#define RWLAZER_VERSION_MINOR	70
#define RWLAZER_VERSION_BUILD	1000

#define LAZER_RETURN_SUCCESS    EXIT_SUCCESS
#define LAZER_SUCCESS			LAZER_RETURN_SUCCESS
#define LAZER_ERROR_NOPROC      0x7000          /* No process found to match PID */

#ifdef _WIN32
#include <Windows.h>
#endif

#ifndef LAZER_EFI_ONLY

#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#define LAZER_ERROR_GETHANDLE   0x7001
#define LAZER_ERROR_CONINFO     0x7002
#define LAZER_ERROR_EFICOMM     0x7003
#define LAZER_ERROR_INITINST    0x7004
#define LAZER_ERROR_NULLPTR     0x7005
#define LAZER_ERROR_EINVCFG     0x7006
#define LAZER_ERROR_BADKEY      0x7007
#define _LAZER_ERROR_BARRIER    0x7008


#define LAZER_READ				0x10
#define LAZER_WRITE				0x20

#define LAZER_THREADS_MAX		16

#define LAZER_NULLPTR           ((void *) 0xFFFFDEAD)

#define LAZER_ADDRESS_INVALID	0xFFFFFFFFDEADBEEF

#define LAZER_LOG_PATH			"lazer64.log"

#define LAZER_CONTINUE			LAZER_SUCCESS
#define LAZER_ERROR				EXIT_FAILURE
#define LAZER_EXIT				((uint32_t) (EXIT_SUCCESS - 1))

#define	COLOR_WHITE				7
#define COLOR_BLUE				9
#define COLOR_RED				12

#ifndef _UINTPTR_T_DEFINED
typedef unsigned long long      uintptr_t;
#endif
#ifndef _PTRDIFF_T_DEFINED
typedef long long               ptrdiff_t;
#endif

#ifndef _SSIZE_T_DEFINED
typedef int64_t					ssize_t;
#endif

typedef uint8_t					byte;
typedef int32_t					error_t;
typedef int64_t					off_t;
typedef volatile bool           lzrmutex_t;

/* logging levels */
typedef enum _lazer_log_level {
    LOG_DEBUG	 = 0,
    LOG_NOTIF	 = 1,
    LOG_WARNING  = 2,
    LOG_ERROR	 = 3,
    LOG_CRITICAL = 4
} loglevel_t;

typedef enum _lazer_nbase {
    BASE_ERROR		 = 0,
    BASE_DECIMAL	 = 10,
    BASE_HEXADECIMAL = 16
} numbase_t;

typedef enum _lazer_ctype {
    LAZER_INT8  = sizeof(char),
    LAZER_INT16 = sizeof(short),
    LAZER_INT32 = sizeof(int),
    LAZER_INT64 = sizeof(long long),
    LAZER_PTR64 = sizeof(void *)
} ctype_t;

typedef struct proc_info {
    unsigned long long	process_id;				/* LAZER process id*/
    unsigned long long	base_address;			/* LAZER base address */
    const char         *exec_path;				/* LAZER EXE name */
} process_info;

typedef struct lazer_settings {
    int32_t			exit_code;					/* LAZER exit code */
    error_t			last_errno;					/* last error number */
    int32_t			log_status;					/* log file write flag for displaying "log updated.." message */
    uint16_t		log_level;                  /* minimal logging severity level */
    WORD			default_console_attr;		/* LAZER console text attrb */
    HANDLE		    h_console;					/* LAZER console handle */
    process_info   *lazer64_procinfo;
} lazer64_cfg_t;

/* Opcode Instruction Struct for signature scanning with wildcard mask support */
typedef struct opcode64 {
    unsigned char opcode;
    bool wildcard;
} OPCODE64;

/* Linked list for running threads */
typedef struct __lazer_thread {
    HANDLE      thread_handle;
    lzrmutex_t  mutex;
    DWORD       handle_id;
    struct __lazer_thread* next;
} LAZERTHREAD;

extern lazer64_cfg_t *lazercfg;

/* Logging */
ssize_t log_write(loglevel_t log_level, const char* message, ...);

/* Reads last error value */
#define LAZER_READLASTERR       ( lazercfg->last_errno )

/** this is a straight shit show, so lemme walk you thru..
* first, we set `last_errno` in lazercfg to the error code this macro was called with
* next `exit_code` is set to `LAZER_ERROR`, to indicate an error just happened
* following, we check if `lazer_strerror()` returns `NULL`. if so, we yell "UNKNOWN_ERROR"
* and last, we want to check if current error was a winapi error, because `lazer_strerror()`
* calls `malloc()` in this case, so we need to free that..
*
*/

/* Sets last error number and logs error information */
#define LAZER_SETLASTERR(func_name, lazer_errno, is_nt_error) { \
    do { \
        lazercfg->last_errno = lazer_errno; \
        lazercfg->exit_code = LAZER_ERROR; \
        char *__str_err = (char *) lazer_strerror(LAZER_READLASTERR, (bool) is_nt_error); \
        __str_err = (NULL == __str_err) ? "UNKNOWN_ERROR" : __str_err; \
        log_write(LOG_ERROR, "%s: %s", func_name, __str_err); \
        if (is_nt_error && NULL != __str_err) { free(__str_err); } \
     } while (0); \
}


/* Lazer CTL */

/**
* Initializes new RWLAZER64 instance (config struct, process info) and probes EFI driver communication
*
* @param    const char *exec_path   - argv[0]
* @return   pointer to initialized LAZER64CFG or `NULL` on error
*/
int lazer64_init(const char *exec_path);

/**
* @brief	Finalizes RWLAZER64 instance 
*/
int32_t lazer64_final(error_t exit_code);


/**
* @brief Main menu input loop
*/
int lazer64_menu(void);

/**
* @brief Converts error number to a string containing information on specified error
* 
* @param    error_t error_num          - error id to convert
* @return   pointer to error string or `NULL` on error
*/
const char* lazer_strerror(error_t error_num, bool is_nt_error);


numbase_t strtou64(byte* input_buf, uintptr_t* output);

#endif  /* LAZER_EFI_ONLY */
#endif  /* _RWLAZER64_BASE_H_ */