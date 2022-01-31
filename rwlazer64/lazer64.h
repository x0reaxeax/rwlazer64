#ifndef _RWLAZER64_BASE_H_
#define _RWLAZER64_BASE_H_

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS			0
#define EXIT_FAILURE			1
#endif

#define RWLAZER_VERSION_MAJOR	0
#define RWLAZER_VERSION_MINOR	32
#define RWLAZER_VERSION_BUILD	3020

#define LAZER_RETURN_SUCCESS    EXIT_SUCCESS
#define LAZER_SUCCESS			LAZER_RETURN_SUCCESS

#define LAZER_JMPINTRO          0x6FFF

/* LAZER ERRORS. When updating this, dont forget to update lazer_strerror()! */
#define LAZER_ERROR_NOPROC          0x7000          /* No process found to match PID */
#define LAZER_ERROR_GETHANDLE       0x7001
#define LAZER_ERROR_CONINFO         0x7002
#define LAZER_ERROR_EFICOMM         0x7003
#define LAZER_ERROR_INITINST        0x7004
#define LAZER_ERROR_NULLPTR         0x7005
#define LAZER_ERROR_EINVCFG         0x7006
#define LAZER_ERROR_BADKEY          0x7007
#define LAZER_ERROR_UNINITIALIZED   0x7008
#define LAZER_ERROR_CONVERSION      0x7009
#define LAZER_ERROR_ATTACHBUSY      0x700A
#define LAZER_ERROR_OUTBOUNDS       0x700B
#define _LAZER_ERROR_BARRIER        0x700C

/* memory_command data indexes */
/* General */
#define LAZER_DATA_DEST_PROCID      0 
#define LAZER_DATA_DEST_ADDR        1
#define LAZER_DATA_SRC_PROCID       2
#define LAZER_DATA_SRC_ADDR         3
#define LAZER_DATA_SIZE             4
#define LAZER_DATA_RESULT           5

/* Dest process misc (EFI driver is marked as DEST) */
#define LAZER_DATA_DEST_MISC_0      6
#define LAZER_DATA_DEST_MISC_1      7
#define LAZER_DATA_DEST_MISC_2      8

/* Src process misc (RWLAZER user process is marked as SRC) */
#define LAZER_DATA_SRC_MISC_0       9
#define LAZER_DATA_SRC_MISC_1      10
#define LAZER_DATA_SRC_MISC_2      11

/* Result data misc */
#define LAZER_DATA_RESULT_MISC_0   12
#define LAZER_DATA_RESULT_MISC_1   13
#define LAZER_DATA_RESULT_MISC_2   14

/* Misc Misc xD */
#define LAZER_DATA_MISC_0          15

#define LAZER_DATA_SPEC_ADDREXPORT_0   LAZER_DATA_SRC_MISC_0
#define LAZER_DATA_SPEC_ADDREXPORT_1   LAZER_DATA_SRC_MISC_1
#define LAZER_DATA_SPEC_ADDREXPORT_2   LAZER_DATA_SRC_MISC_2
#define LAZER_DATA_SPEC_ADDREXPORT_3   LAZER_DATA_DEST_MISC_0   /* destination addresses can be used here, */
#define LAZER_DATA_SPEC_ADDREXPORT_4   LAZER_DATA_DEST_MISC_1   /* since the destination buffers are unused */
#define LAZER_DATA_SPEC_ADDREXPORT_5   LAZER_DATA_DEST_MISC_2

#define LAZER_DATA_SPEC_WRMSR_MSRID    LAZER_DATA_SRC_MISC_0
#define LAZER_DATA_SPEC_WRMSR_LOW32    LAZER_DATA_SRC_MISC_1
#define LAZER_DATA_SPEC_WRMSR_HIGH32   LAZER_DATA_SRC_MISC_2

#define LAZER_DATA_SPEC_RDMSR_MSRID    LAZER_DATA_SRC_MISC_0
#define LAZER_DATA_SPEC_RDMSR_LOW32    LAZER_DATA_RESULT_MISC_0
#define LAZER_DATA_SPEC_RDMSR_HIGH32   LAZER_DATA_RESULT_MISC_1


typedef enum _lazer_eficommand {
    LAZER_GETBADDR  = 0x300,
    LAZER_GETPROC   = 0x310,
    LAZER_RDMSR     = 0x320,
    LAZER_WRMSR     = 0x330,
    LAZER_MEMCPY    = 0x340,
    LAZER_PHYSADDR  = 0x350
} lazercmd_t;

#ifdef _WIN32
#include <Windows.h>
#endif

#ifndef LAZER_EFI_ONLY

#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#define LAZER_READ				0x10
#define LAZER_WRITE				0x20

#define LAZER_THREADS_MAX		16

/*
#define LAZER_NULLPTR           ((void *) 0xFFFFDEAD)
*/
#define LAZER_ADDRESS_INVALID	0xFFFFFFFFFFFFFFFF
#define LAZER_ADDRESS_GENERROR  0xFFFFFFFFDEADBEEF

#define LAZER_CHECK_ADDRESS(address) \
                                ( ( ((uintptr_t) address) ^ LAZER_ADDRESS_INVALID) && ( ((uintptr_t) address) ^ ((uintptr_t) NULL) ) )

#define LAZER_LOG_PATH			"lazer64.log"

#define LAZER_CONTINUE			LAZER_SUCCESS
#define LAZER_ERROR				EXIT_FAILURE
#define LAZER_EXIT				((uint32_t) (EXIT_SUCCESS - 1))

#define LAZER_INPUT_ADDRLEN     ( 24 )    /* UINT64_MAX = 20 decimal characters + "0x", newline and nullterm */
#define LAZER_INPUT_NBYTES      ( 20 )
#define LAZER_ADDRLEN_HEX       ( 18 ) 
#define LAZER_ARGLEN_MAX        32

#define LAZER_BYTEDATA_MAXLEN   8192

#define LAZER_FLAG_MEMREAD      (1 << 0)
#define LAZER_FLAG_MEMWRITE     (1 << 1)
#define LAZER_FLAG_ZEROMEMORY   (1 << 2)
#define LAZER_FLAG_MEMSET       (1 << 3)
#define LAZER_FLAG_EXTREAD      (1 << 4)

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

typedef enum _lazer_bool {      /* int */
    LAZER_FALSE = 0,
    LAZER_TRUE = 1
} lbool;

typedef enum _lazer_arg_id {
    LAZER_ARG_NULL = 0,
    LAZER_ARG_DEBUG,
    LAZER_ARG_NOLOGO,
    LAZER_ARG_HELP
} argid_t;

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

typedef enum _lazer_memop {
    LAZER_MEMOP_READ    = LAZER_FLAG_MEMREAD,
    LAZER_MEMOP_WRITE   = LAZER_FLAG_MEMWRITE
} lazer64_memop;

typedef struct proc_info {
    unsigned long long	process_id;				/* LAZER process id*/
    unsigned long long	base_address;			/* LAZER base address */
    const char         *exec_path;				/* LAZER EXE name */
} process_info;

typedef struct lazer_op_history {
    uintptr_t   last_read_address;
    uintptr_t   last_write_address;
    /* ... */
} lazer64_oplog;

typedef struct lazer_settings {
    int32_t         confirm_messages;           /* display confirmation messages 0 = no, 1 = yes */
    int32_t			exit_code;					/* LAZER exit code */
    error_t			last_errno;					/* last error number */
    int32_t			log_status;					/* log file write flag for displaying "log updated.." message */
    int32_t         launch_pass;                /* has to be set in order to init lazer. 
                                                 * used for situations where lazer is not meant to start, like passing '--help' arg at startup */
    uint16_t		log_level;                  /* minimal logging severity level */
    WORD			default_console_attr;		/* LAZER console text attrb */
    HANDLE		    h_console;					/* LAZER console handle */
    process_info   *lazer64_procinfo;           /* LAZER process info */
    process_info   *target_process;             /* target process info */
    lazer64_oplog  *operation_history;          /* operation history & saved values */
} lazer64_cfg_t;

/* Opcode Instruction Struct for signature scanning with wildcard mask support */
typedef struct opcode64 {
    unsigned char opcode;
    bool wildcard;
} opcode64_t;

/* Linked list for running threads */
typedef struct lazer_thread {
    HANDLE      thread_handle;
    lzrmutex_t  mutex;
    DWORD       handle_id;
    struct __lazer_thread* next;
} lazerthread_t;

extern lazer64_cfg_t *lazercfg;

/* Logging */
char *log_lvl_to_str(int loglevel);
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
        char *nt_flag = (is_nt_error) ? "[NT] " : ""; \
        log_write(LOG_ERROR, "%s%s: %s", nt_flag, func_name, __str_err); \
        if (is_nt_error && NULL != __str_err) { free(__str_err); } \
     } while (0); \
}


/* Lazer CTL */

/**
* Initializes new RWLAZER64 instance (config struct, process info) and probes EFI driver communication
*
* @param    int argc            - argc
* @param    const char **argv   - argv
* @return   pointer to initialized LAZER64CFG or `NULL` on error
*/
int lazer64_init(int argc, const char **argv);

/**
* @brief	Finalizes RWLAZER64 instance 
*/
int32_t lazer64_final(error_t exit_code);


/**
* @brief Main menu input loop
* 
* @param    lbool display_logo  - display/omit logo visual
*/
int lazer64_menu(lbool display_logo);

/**
* @brief Converts error number to a string containing information on specified error
* 
* @param    error_t error_num          - error id to convert
* @return   pointer to error string or `NULL` on error
*/
const char* lazer_strerror(error_t error_num, bool is_nt_error);

/**
* @brief Initializes new target process. Does NOT actually attach anything
* 
* @param process_info *target_process   - process_info of pre-set target process or `NULL` to automatically create a new one
* @return LAZER_SUCCESS or LAZER_ERROR
*/
int lazer64_attach(process_info *target_process);

/* LAZER_IO */
numbase_t strtou64(byte* input_buf, uintptr_t* output);
size_t strtodtsz(char *str_type, bool print_info_only);
int lazer64_get_numinput(uint64_t *output, bool str_datasz_input, size_t nbytes);
int lazer64_get_bytedata(byte *output, size_t nbytes);
bool check_data_size(size_t data_size);

/* Visuals */
void printeye(void);
void print_help(void);
void print_intro(void);
void print_datatypes(void);

/* misc tools */
void lazer64_ftox_calc(void);

#endif  /* LAZER_EFI_ONLY */
#endif  /* _RWLAZER64_BASE_H_ */