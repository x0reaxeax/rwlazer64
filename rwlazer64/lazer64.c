#include "lazer64.h"
#include "driverctl.h"

#pragma warning (disable : 4996)

#include <stdio.h>

/**
* Initializes LAZER64 config struct and probes EFI driver communication
* 
* @param    const char *exec_path   - argv[0]
* @return   pointer to initialized LAZER64CFG or `NULL` on error
*/
int lazer64_init(const char **argv) {
    printf("[*] Initializing RWLAZER64..");
    fflush(stdout);

    if (NULL == argv) {
        goto LAZER_INIT_FAIL;
    }

    HANDLE h_console = NULL;
    process_info *lazerinfo = NULL;
    lazer64_oplog *operation_log = NULL;
    
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    lazercfg = malloc(sizeof(lazer64_cfg_t));
    lazerinfo = malloc(sizeof(process_info));
    operation_log = malloc(sizeof(lazer64_oplog));

    if (NULL == lazerinfo || NULL == lazercfg || NULL == operation_log) {
        log_write(LOG_ERROR, "Unable to initialize RWLAZER64: E%d - '%s'", errno, strerror(errno));
        goto LAZER_INIT_FAIL;
    }

    memset(operation_log, 0, sizeof(lazer64_oplog));

    /* set defaults */
    lazercfg->exit_code = LAZER_SUCCESS;
    lazercfg->operation_history = operation_log;

    lazercfg->log_status = 0;
    lazercfg->confirm_messages = 1;
    lazercfg->log_level = (uint16_t) LOG_NOTIF;
    
    lazercfg->target_process = NULL;
    lazercfg->default_console_attr = 0;
    
    lazerinfo->exec_path = argv[0];

    h_console = GetStdHandle(STD_OUTPUT_HANDLE);

    if (NULL == h_console) {
        LAZER_SETLASTERR("lazer64_init()", GetLastError(), true);
        goto LAZER_INIT_FAIL;
    }

    if (GetConsoleScreenBufferInfo(h_console, &csbi)) {
        lazercfg->default_console_attr = csbi.wAttributes;
    } else {
        LAZER_SETLASTERR("lazer64_init()", GetLastError(), true);
    }

    SetConsoleTextAttribute(h_console, COLOR_RED);

    if (driver_initialize() != true) {
        LAZER_SETLASTERR("lazer64_init()", LAZER_ERROR_EFICOMM, false);
        goto LAZER_INIT_FAIL;
    }

    if (driver_checkefi(lazerinfo) != true) {
        LAZER_SETLASTERR("lazer64_init()", LAZER_ERROR_INITINST, false);
        goto LAZER_INIT_FAIL;
    }

    lazercfg->h_console = h_console;
    lazercfg->lazer64_procinfo = lazerinfo;
    
    log_write(LOG_NOTIF, "Successfully initialized RWLAZER64");
    printf("\r[+] Successfully initialized RWLAZER64\n");

    return LAZER_SUCCESS;


LAZER_INIT_FAIL:
    ; char* error_str = (NULL == lazercfg) ? strerror(errno) : lazer_strerror(LAZER_READLASTERR, false);
    printf("\r[-] Failed to initialize RWLAZER64 [%s]\n", error_str);
    return LAZER_ERROR;
}

int32_t lazer64_final(error_t exit_code) {
    puts("[+] Exiting..\n");
    if (NULL != lazercfg) {
        /* check if default command line text color has been saved and if so, restore it */
        if (lazercfg->default_console_attr) {
            if (!SetConsoleTextAttribute(lazercfg->h_console, lazercfg->default_console_attr)) {
                LAZER_SETLASTERR("lazer64_final()", GetLastError(), true);
            }
        }

        if (lazercfg->exit_code != LAZER_SUCCESS) {
            printf("[-] RWLAZER exited with return code: %d\n", lazercfg->exit_code);
        }

        /* Display informational message if logfile has been updated */
        if (lazercfg->log_status > 0) {
            puts("[+] Logfile has been updated");
        }

        /* free lazer and target process info and global config */
        free(lazercfg->operation_history);
        free(lazercfg->lazer64_procinfo);
        free(lazercfg->target_process);
        free(lazercfg);
        lazercfg = NULL;
    }

    log_write(LOG_NOTIF, "Shutting down..");

    return exit_code;
}

void lazer64_restart(void) {
    if (NULL != lazercfg) {
        if (NULL != lazercfg->target_process) {
            free((void *) lazercfg->target_process->exec_path);
            lazercfg->target_process->base_address  = LAZER_ADDRESS_INVALID;
            lazercfg->target_process->process_id    = WIN_PROCESSID_INVALID;
            lazercfg->target_process->exec_path     = NULL;
        }
        if (NULL != lazercfg->operation_history) {
            memset(lazercfg->operation_history, 0, sizeof(lazer64_oplog));
        }
    }
}

int lazer64_attach(process_info *target_process) {
    if (NULL == target_process) {
        if (NULL == lazercfg->target_process) {
            target_process = malloc(sizeof(process_info));
            if (NULL == target_process) {
                LAZER_SETLASTERR("lazer64_attach()", errno, false);
                return LAZER_ERROR;
            }
        } else {
            LAZER_SETLASTERR("lazer64_attach()", LAZER_ERROR_ATTACHBUSY, false);
            return LAZER_ERROR;
        }
    }

    uint64_t target_pid = WIN_PROCESSID_INVALID;
    printf("[*] Enter PID: ");
    fflush(stdout);

    if (lazer64_get_numinput(&target_pid, LAZER_INPUT_ADDRLEN) != LAZER_SUCCESS) {
        goto _ERROR;
    }

    if (WIN_PROCESSID_INVALID == target_pid) {
        LAZER_SETLASTERR("lazer64_attach()", EINVAL, false);
        goto _ERROR;
    }

    target_process->exec_path = NULL;
    target_process->process_id = target_pid;
    target_process->base_address = LAZER_ADDRESS_INVALID;

    lazercfg->target_process = target_process;

    log_write(LOG_DEBUG, "Target process ID: %llu [%#02llx]", target_pid, target_pid);

    return EXIT_SUCCESS;

_ERROR:
    free(target_process);
    target_process = NULL;
    return LAZER_ERROR;
}

static size_t lazer64_mem_write(process_info *target_process) {
    if (NULL == target_process) {
        LAZER_SETLASTERR("lazer64_mem_write()", LAZER_ERROR_NULLPTR, false);
        return 0;
    }

    size_t nbytes = 0;
    byte *write_bytes = NULL;
    uintptr_t target_address = LAZER_ADDRESS_INVALID;

    printf("[*] Address: ");
    fflush(stdout);
    lazer64_get_numinput(&target_address, LAZER_INPUT_ADDRLEN);

    if (!LAZER_CHECK_ADDRESS(target_address)) {
        puts("[-] Invalid address");
        return 0;
    }

    printf("[*] Number of bytes: ");
    fflush(stdout);
    lazer64_get_numinput(&nbytes, LAZER_INPUT_ADDRLEN);

    write_bytes = malloc(sizeof(char) * nbytes);

    if (NULL == write_bytes) {
        LAZER_SETLASTERR("lazer64_mem_write()", errno, false);
        return 0;
    }

    if (lazer64_get_bytedata(write_bytes, nbytes) != LAZER_SUCCESS) {
        free(write_bytes);
        return 0;
    }

    if (lazercfg->confirm_messages) {
        /* confirmation & hennessy */

        char confirm_buffer[512] = { 0 }; /* to grab accidental garbage */
        printf("\n[ -=== CONFIRM WRITE ===- ]\n"
               "  * Address:           %#02llx\n"
               "  * Number of bytes:   %zu\n"
               "[BYTE DATA]:\n",
               target_address,
               nbytes
        );

        for (size_t i = 0; i < nbytes; i++) {
            printf("%#04x ", write_bytes[i]);
        }
        printf("\n[*] Confirm [y/N]: ");
        fflush(stdout);

        fgets(confirm_buffer, 512, stdin);
        putchar('\n');
        if (confirm_buffer[0] != 'y' && confirm_buffer[0] != 'Y') {
            nbytes = 0;
            goto _FINAL;
        }
    }

    if (!NT_SUCCESS(driver_write_memory(target_process, target_address, write_bytes, nbytes))) {
        nbytes = 0;
    }

_FINAL:
    free(write_bytes);
    return nbytes;
}

static size_t lazer64_mem_read(process_info *target_process) {
    return 0;
}


int lazer64_memrw(process_info *target_process, lazer64_memop memop, size_t *szout) {
    int ret_code = LAZER_SUCCESS;
    size_t affected_bytes = 0;

    switch (memop) {
        case LAZER_MEMOP_READ:
            affected_bytes = lazer64_mem_read(target_process);
            break;

        case LAZER_MEMOP_WRITE:
            affected_bytes = lazer64_mem_write(target_process);
            break;

        default:
            LAZER_SETLASTERR("lazer64_memrw()", EINVAL, false);
            ret_code = LAZER_ERROR;
            break;
    }

    if (NULL != szout) {
        *szout = affected_bytes;
    }

    return ret_code;
}

uint32_t lazer64_menu_input_handler(char *input) {
    if (NULL == input) {
        return LAZER_ERROR;
    }

    uint64_t menu_num_input = 0;
    uint32_t return_value = LAZER_CONTINUE;

    if (strtou64((byte*) input, &menu_num_input) == BASE_ERROR) {
        return LAZER_CONTINUE;
    }

    switch (menu_num_input) {
        /* --- Generic Ops --- */
        case 0:
            /* set target pid */
            if (lazer64_attach(NULL) != LAZER_SUCCESS) {
                if (LAZER_READLASTERR == LAZER_ERROR_ATTACHBUSY) {
                    fprintf(stderr, "[-] Target process already set!\n");
                } else {
                    fprintf(stderr, "[-] Unable to set target process: E%d\n", LAZER_READLASTERR);
                }
            } else {
                printf("[+] Target process: %llu [%#02llx]\n", lazercfg->target_process->process_id, lazercfg->target_process->process_id);
            }
            break;

        case 1:
            /* get base address */
            if (!LAZER_CHECK_ADDRESS(driver_get_base_address(lazercfg->target_process))) {
                fprintf(stderr, "[-] Unable to retrieve base address: E%#02x\n", LAZER_READLASTERR);
            } else {
                printf("[+] Target base address: %#02llx\n", lazercfg->target_process->base_address);
            }
            break;
        case 2:
            /* print data types */
            print_datatypes();
            break;

        case 3:
            /* print main menu */
            print_intro();
            break;

        case 4:
            /* clear history */
            if (NULL != lazercfg->operation_history) {
                memset(lazercfg->operation_history, 0, sizeof(lazer64_oplog));
            }
            break;

        case 5:
            /* cls .... */
            system("cls");
            break;

        case 6:
            /* fresh start */
            lazer64_restart();
            return_value = LAZER_JMPINTRO;
            break;

        case 99:
            return_value = LAZER_EXIT;
            break;

        /* --- Read Operations --- */
        case 30:
            break;

        case 40:
            lazer64_memrw(lazercfg->target_process, LAZER_MEMOP_WRITE, NULL);
            break;
        
        /* eggz */
        case 0x777:
            puts("*** CRACKED BY RAZOR1911 ***");
            break;

        case 0x31c0:
            for (int i = 0, j = 0; i < 0x31c0; i++) {
                char xor[] = " xoreaxeax **** ";
                if (j >= (sizeof(xor) - 1)) {
                    j = 0;
                }
                putchar(xor [j]);
                j++;
            }
            putchar('\n');
            break;


        default:
            break;
    }

    return return_value;
}

int lazer64_menu(void) {
_INTRO:
    printeye();
    print_intro();

    char input_buffer[16] = { 0 };
    uint32_t return_value = LAZER_RETURN_SUCCESS;

    printf("$: ");
    fflush(stdout);
    
    while (fgets(input_buffer, 15, stdin)) {
        return_value = lazer64_menu_input_handler(input_buffer);
        if (return_value != LAZER_SUCCESS) {
            break;
        }

        memset(input_buffer, 0, 4);
        printf("$: ");
        fflush(stdout);
    }
    if (LAZER_JMPINTRO == return_value) {
        goto _INTRO;
    }

    return (return_value == LAZER_EXIT) ? LAZER_SUCCESS : LAZER_ERROR;
}