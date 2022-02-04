#include "lazer64.h"

#include <time.h>
#include <stdio.h>
#include <stdarg.h>

#pragma warning (disable : 4996)

char* log_lvl_to_str(int loglevel) {
    switch (loglevel) {
    case LOG_DEBUG:
        return "DBG";
        break;

    case LOG_NOTIF:
        return "INFO";
        break;

    case LOG_WARNING:
        return "WARN";
        break;
    case LOG_ERROR:
        return "ERR";
        break;

    case LOG_CRITICAL:
        return "CRIT";
        break;

    default:
        break;
    }

    return NULL;
}

ssize_t log_write(loglevel_t log_level, const char* message, ...) {
    if (NULL != lazercfg) {
        /* check minimum log level severity */
        if (log_level < lazercfg->log_level) {
            return 0;
        }
    }

    va_list args;

    time_t now;
    size_t retsum;
    char* newline = "\n";

    va_start(args, message);
    FILE* errfp = fopen(LAZER_LOG_PATH, "ab");

    if (NULL == errfp) {
        if (NULL != lazercfg) {
            lazercfg->last_errno = errno;
        }
        return -errno;
    }

    /* Get current time */
    time(&now);

    char tt_time[256 + 64];

    snprintf(tt_time, 64, ctime(&now));

    tt_time[strcspn(tt_time, "\n")] = 0;

    const char* log_lvl_str = log_lvl_to_str(log_level);
    if (log_lvl_str == NULL) { log_lvl_str = "UNKNOWN"; }

    size_t _prefix = fprintf(errfp, "[%s]-[%s]: ", tt_time, log_lvl_str);
    size_t _suffix = vfprintf(errfp, message, args);
    fprintf(errfp, newline);

    va_end(args);
    fclose(errfp);

    retsum = _prefix + _suffix + 1;

    if (lazercfg != NULL) {
        lazercfg->log_status += 1;
    }

    return retsum;
}

char *GetErrorMessage(DWORD dwErrorCode, char *output, size_t nbytes) {
    if (NULL == output) {
        return NULL;
    }

    DWORD ret = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), output, (DWORD) nbytes, NULL);
    /* todo: ret check */
    return output;
}

const char* lazer_strerror(error_t error_num, bool is_nt_error) {   
    if (is_nt_error) {
        char *nt_err_msg = malloc(sizeof(char) * 256);
        if (NULL == nt_err_msg) {
            lazercfg->last_errno = errno;
            lazercfg->exit_code = LAZER_ERROR;
            log_write(LOG_ERROR, "lazer_strerror(): %s - E%d", strerror(LAZER_READLASTERR), LAZER_READLASTERR);
            return NULL;
        }
        memset(nt_err_msg, 0, 256);
        GetErrorMessage(error_num, nt_err_msg, 255);
        /* FormatMessageA spits a newline, wipe it.. */
        nt_err_msg[strcspn(nt_err_msg, "\n")] = 0;
        return nt_err_msg;
    }
    
    const char* error_str = NULL;
    const char *lazer_error_list[] = {
        "No running process to match specified process ID",
        "Unable to obtain handle",
        "Unable to obtain console attributes",
        "Unable to establish communication with EFI driver",
        "EFI driver failed to retrieve information from RWLAZER64 user process",
        "Attempted to pass NULL pointer",
        "Invalid config entry",
        "Invalid key value",
        "Driver did not acknowledge user request",
        "Data conversion failure",
        "Target process already set",
        "Out of bounds",
        "Invalid argument",
        "Invalid operation requested"
    };

    size_t n_errors = sizeof(lazer_error_list) / sizeof(lazer_error_list[0]);

    /* LAZER errors start at 0x7000, so subtracting that from ERROR_BARRIER will yield number of defined errors */
    if (n_errors != (_LAZER_ERROR_BARRIER - 0x7000)) {
        /* can't call LAZER_SETLASTERR(), because it calls this function (lazer_strerror) */
        lazercfg->last_errno = EINVAL;
        log_write(LOG_ERROR, "Failed to initialize logging: %d", LAZER_READLASTERR);
        return NULL;
    }

    if (error_num < 0x7000) {
        /* assume cerrno */
        error_str = strerror(error_num);
    } else {
        for (error_t i = 0x7000; i < _LAZER_ERROR_BARRIER; i++) {
            if (i == error_num) {
                error_str = lazer_error_list[i - 0x7000];
                break;
            }
        }
    }

    return error_str;
}