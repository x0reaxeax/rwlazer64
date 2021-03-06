#include "lazer64.h"
#include "driverctl.h"

#pragma warning (disable : 4996)

#include <stdio.h>

static argid_t lazer64_strargid(const char *input) {
    if (NULL == input) {
        lazer64_setlasterr("lazer64_strargid()", LAZER_ERROR_NULLPTR, false, true);
        return LAZER_ARG_NULL;
    }

    const char *startup_args[] = {
        "--debug",
        "--nologo",
        "--help"
    };

    argid_t nargs = sizeof(startup_args) / sizeof(startup_args[0]);

    for (argid_t i = 0; i < nargs; i++) {
        if (strncmp(startup_args[i], input, LAZER_ARGLEN_MAX) == EXIT_SUCCESS) {
            return (i + 1);
        }
    }
    return LAZER_ARG_NULL;
}

static int lazer64_eval_argv(int argc, const char *argv[]) {
    for (int i = 1; i < argc; i++) {
        argid_t cur_arg = lazer64_strargid(argv[i]);
        switch (cur_arg) {
            case LAZER_ARG_DEBUG:
                log_write(LOG_DEBUG, "300Gs, full speed");  /* impossible notification, unless i decide to implement a config file */
                lazercfg->log_level = LOG_DEBUG;
                break;

            case LAZER_ARG_NOLOGO:
                //lazercfg->__pad
                break;

            case LAZER_ARG_HELP:
                print_help();
                lazercfg->launch_pass = 0;
                break;

            default:
                log_write(LOG_NOTIF, "Unknown argument: '%s'", argv[i]);
                break;
        }
    }

    return LAZER_SUCCESS;
}

/**
* Initializes LAZER64 config struct and probes EFI driver communication
* 
* @param    const char *exec_path   - argv[0]
* @return   pointer to initialized LAZER64CFG or `NULL` on error
*/
int lazer64_init(int argc, const char **argv) {
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
    
    lazercfg->lazer64_procinfo = lazerinfo;
    lazercfg->lazer64_procinfo->base_address = LAZER_ADDRESS_INVALID;
    lazercfg->lazer64_procinfo->process_id = WIN_PROCESSID_INVALID;
    lazercfg->lazer64_procinfo->exec_path = argv[0];

    lazercfg->log_status = 0;
    lazercfg->launch_pass = 1;
    lazercfg->confirm_messages = 1;
    lazercfg->log_level = (uint16_t) LOG_NOTIF;
    
    lazercfg->target_process = NULL;
    lazercfg->default_console_attr = 0;
    
    lazerinfo->exec_path = argv[0];

    /* eval startup args */
    lazer64_eval_argv(argc, argv);
    log_write(LOG_DEBUG, "Set loglevel: %s", log_lvl_to_str(lazercfg->log_level));

    if (lazercfg->launch_pass != 1) {
        return LAZER_EXIT;
    }

    h_console = GetStdHandle(STD_OUTPUT_HANDLE);

    if (NULL == h_console) {
        lazer64_setlasterr("lazer64_init()", GetLastError(), true, true);
        goto LAZER_INIT_FAIL;
    }

    lazercfg->h_console = h_console;

    if (GetConsoleScreenBufferInfo(h_console, &csbi)) {
        lazercfg->default_console_attr = csbi.wAttributes;
    } else {
        lazer64_setlasterr("lazer64_init()", GetLastError(), true, true);
    }

    SetConsoleTextAttribute(h_console, COLOR_RED);

    if (driver_initialize() != true) {
        lazer64_setlasterr("lazer64_init()", LAZER_ERROR_EFICOMM, false, true);
        goto LAZER_INIT_FAIL;
    }

    if (driver_checkefi(lazerinfo) != true) {
        lazer64_setlasterr("lazer64_init()", LAZER_ERROR_INITINST, false, true);
        goto LAZER_INIT_FAIL;
    }

    log_write(LOG_NOTIF, "Successfully initialized RWLAZER64");
    printf("\r[+] Successfully initialized RWLAZER64\n");

    return LAZER_SUCCESS;


LAZER_INIT_FAIL:
    ; char* error_str = (NULL == lazercfg) ? strerror(errno) : lazer_strerror(LAZER_READLASTERR, false);
    printf("\r[-] Failed to initialize RWLAZER64 [%s]\n", error_str);
    return LAZER_ERROR;
}

int32_t lazer64_final(error_t exit_code) {
    puts("\n[+] Exiting..\n");
    if (NULL != lazercfg) {
        /* check if default command line text color has been saved and if so, restore it */
        if (lazercfg->default_console_attr) {
            if (!SetConsoleTextAttribute(lazercfg->h_console, lazercfg->default_console_attr)) {
                lazer64_setlasterr("lazer64_final()", GetLastError(), true, true);
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

static inline lbool lazer64_checktarget(process_info *target_process) {
    if (NULL == target_process) {
        return LAZER_FALSE;
    }

    if (target_process->process_id == WIN_PROCESSID_INVALID) {
        return LAZER_FALSE;
    }

    return LAZER_TRUE;
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
                lazer64_setlasterr("lazer64_attach()", errno, false, true);
                return LAZER_ERROR;
            }
        } else {
            lazer64_setlasterr("lazer64_attach()", LAZER_ERROR_ATTACHBUSY, false, false);
            return LAZER_ERROR;
        }
    } else {
        if ((target_process->process_id != WIN_PROCESSID_INVALID) && (target_process == lazercfg->target_process)) {
            lazer64_setlasterr("lazer64_attach()", LAZER_ERROR_ATTACHBUSY, false, false);
            return LAZER_ERROR;
        }
    }

    uint64_t target_pid = WIN_PROCESSID_INVALID;
    printf("[*] Enter PID: ");
    fflush(stdout);

    if (lazer64_get_numinput(&target_pid, false, LAZER_INPUT_ADDRLEN) != LAZER_SUCCESS) {
        goto _ERROR;
    }

    if (WIN_PROCESSID_INVALID == target_pid) {
        lazer64_setlasterr("lazer64_attach()", EINVAL, false, true);
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

static size_t lazer64_mem_write(process_info *target_process, uintptr_t target_address, byte *force_write_byte_buf, size_t nbytes) {
    if (NULL == target_process) {
        lazer64_setlasterr("lazer64_mem_write()", LAZER_ERROR_NULLPTR, false, true);
        return 0;
    }


    byte *write_byte_buf = NULL;
    if (force_write_byte_buf != NULL) {
        write_byte_buf = force_write_byte_buf;
    } else {
        write_byte_buf = malloc(sizeof(byte) * nbytes);

        if (NULL == write_byte_buf) {
            lazer64_setlasterr("lazer64_mem_write()", errno, false, true);
            return 0;
        }
        
        memset(write_byte_buf, 0, nbytes);

        if (lazer64_get_bytedata(write_byte_buf, nbytes) != LAZER_SUCCESS) {
            free(write_byte_buf);
            return 0;
        }
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
            printf("0x%02x ", write_byte_buf[i]);
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

    if (!NT_SUCCESS(driver_write_memory(target_process, target_address, write_byte_buf, nbytes))) {
        nbytes = 0;
    }

    size_t last_write_sz = (nbytes <= sizeof(int)) ? sizeof(int) : sizeof(uint64_t);
    memset(&lazercfg->operation_history->last_write_value, 0, sizeof(lazercfg->operation_history->last_write_value));
    memcpy(&lazercfg->operation_history->last_write_value, write_byte_buf, last_write_sz);

_FINAL:
    if (NULL == force_write_byte_buf) {
        free(write_byte_buf);
    }
    return nbytes;
}

static size_t lazer64_mem_read(process_info *target_process, uintptr_t target_address, byte *force_read_byte_buf, size_t nbytes, bool quiet) {
    if (NULL == target_process) {
        lazer64_setlasterr("lazer64_mem_read()", LAZER_ERROR_NULLPTR, false, true);
        return 0;
    }

    byte *read_byte_buf = NULL;
    if (NULL != force_read_byte_buf) {
        read_byte_buf = force_read_byte_buf;
    } else {
        read_byte_buf = malloc(sizeof(byte) * nbytes);
        
        if (NULL == read_byte_buf) {
            lazer64_setlasterr("lazer64_mem_read()", errno, false, true);
            return 0;
        }
        
        memset(read_byte_buf, 0, nbytes);
    }

    
    if (!NT_SUCCESS(driver_read_memory(target_process, target_address, read_byte_buf, nbytes))) {
        nbytes = 0;
    } else {
        printf("\n[ -=== READ RESULT ===- ]\n"
               "  * Target Address:  %#02llx\n"
               "  * Number of bytes: %zu\n"
               "[BYTE DATA]:\n",
               target_address,
               nbytes
        );
    }

    if (!quiet) {
        for (int64_t i = (nbytes - 1); i >= 0; i--) {
            printf("%02x ", read_byte_buf[i]);
        }
        putchar('\n');
    }
    
    size_t last_read_sz = (nbytes <= sizeof(int)) ? sizeof(int) : ( (nbytes <= sizeof(uint64_t)) ? nbytes : sizeof(uint64_t));
    memset(&lazercfg->operation_history->last_read_value, 0, sizeof(lazercfg->operation_history->last_read_value));
    memcpy(&lazercfg->operation_history->last_read_value, read_byte_buf, last_read_sz);
    
    if (NULL == force_read_byte_buf) {
        free(read_byte_buf);
    }
    return nbytes;
}


int lazer64_memrw(process_info *target_process, lazer64_memop memop, uint8_t flags, size_t *szout) {
    if (!lazer64_checktarget(target_process)) {
        lazer64_setlasterr("lazer64_memrw()", LAZER_ERROR_NOPROC, false, false);
        fprintf(stderr, "[-] No target process set\n");
        return LAZER_ERROR;
    }

    int ret_code = LAZER_SUCCESS;
    size_t affected_bytes = 0;
    
    size_t nbytes = 0;
    uintptr_t target_address = LAZER_ADDRESS_INVALID;

    printf("[*] Address: ");
    fflush(stdout);
    lazer64_get_numinput(&target_address, false, LAZER_INPUT_ADDRLEN);

    if (!LAZER_CHECK_ADDRESS(target_address)) {
        fprintf(stderr, "[-] Invalid address\n");
        return LAZER_ERROR;
    }

    printf("[*] Number of bytes: ");
    fflush(stdout);

    if (lazer64_get_numinput(&nbytes, true, LAZER_INPUT_ADDRLEN) != LAZER_SUCCESS) {
        fprintf(stderr, "[-] Invalid input\n");
        return LAZER_ERROR;
    }

    if (0 == nbytes) {
        return LAZER_SUCCESS;
    }

    switch (memop) {
        case LAZER_MEMOP_READ:
            lazercfg->operation_history->last_read_address = target_address;
            bool quiet = (flags == (memop | LAZER_FLAG_EXTREAD)) ? true : false;
            affected_bytes = lazer64_mem_read(target_process, target_address, NULL, nbytes, quiet);
            break;

        case LAZER_MEMOP_WRITE:
            lazercfg->operation_history->last_write_address = target_address;
            byte *byte_buf = NULL;
            if ((flags & (LAZER_FLAG_ZEROMEMORY)) > 0) {
                byte_buf = malloc(sizeof(byte) * nbytes);
                if (NULL == byte_buf) {
                    lazer64_setlasterr("lazer64_memrw()", errno, false, true);
                    return 0;
                }

                memset(byte_buf, 0, nbytes);
            }
            affected_bytes = lazer64_mem_write(target_process, target_address, byte_buf, nbytes);
            free(byte_buf);
            break;

        default:
            lazer64_setlasterr("lazer64_memrw()", EINVAL, false, true);
            ret_code = LAZER_ERROR;
            break;
    }

    if (NULL != szout) {
        *szout = affected_bytes;
    }

    return ret_code;
}

int lazer64_phys(void) {
#ifdef _LAZER_TESTING
    size_t nbytes = 8;
    byte output[64] = { 0 };
    uintptr_t target_address = 0;

    lazer64_prompt_address(&target_address);

    if (driver_read_phys_memory(output, target_address, nbytes) != LAZER_SUCCESS) {
        return LAZER_ERROR;
    }

    puts("[ -=== BYTE DATA ===- ]");
    for (size_t i = 0; i < nbytes; i++) {
        printf("0x%02x ", output[i]);
    }
    putchar('\n');
#endif

    return LAZER_SUCCESS;
}

int lazer64_get_directorybasetable(process_info *target_process) {
    if (!lazer64_checktarget(target_process)) {
        lazer64_setlasterr("lazer64_get_directorybasetable()", LAZER_ERROR_NOPROC, false, false);
        fprintf(stderr, "[-] No target process set\n");
        return LAZER_ERROR;
    }

    
    uintptr_t proc_dbt = driver_get_directorybasetable(target_process);
    if (!LAZER_CHECK_ADDRESS(proc_dbt)) {
        printf("[-] Unable to read DirectoryBaseTable address for PID %llu\n", target_process->process_id);
        return LAZER_ERROR;
    }

    printf("[+] DirectoryBaseTable for PID %llu: 0x%02llx\n", target_process->process_id, proc_dbt);
    return LAZER_SUCCESS;
}

int lazer64_getphysicaladdr_nonpaged(void) {
    uintptr_t target_address = 0;

    printf( "[!] This function retrieves physical address corresponding to a NON-PAGED virtual address\n"
            "[*] Address: ");
    fflush(stdout);
    lazer64_get_numinput(&target_address, false, LAZER_INPUT_ADDRLEN);

    if (!LAZER_CHECK_ADDRESS(target_address)) {
        fprintf(stderr, "[-] Invalid address\n");
        return LAZER_ERROR;
    }

    uint32_t low = 0;
    int32_t  high = 0;
    uint64_t quad = 0;

    if (LAZER_SUCCESS != driver_mmgetphysicaladdress(target_address, &low, &high, &quad)) {
        return LAZER_ERROR;
    }

    printf("[+] * LOW:  %#02lx\n"
           "    * HIGH: %#02lx\n"
           "    * QUAD: %#02llx\n",
           low,
           high,
           quad
    );

    return LAZER_SUCCESS;
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
            if (lazer64_attach(lazercfg->target_process) != LAZER_SUCCESS) {
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
                fprintf(stderr, "[-] Unable to retrieve base address: E 0x%x\n", LAZER_READLASTERR);
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
            lazer64_memrw(lazercfg->target_process, LAZER_MEMOP_READ, 0, NULL);
            break;

        case 35:    /* read phys mem */
            lazer64_phys();
            break;

        /* --- Write Operations --- */
        case 40:    /* read memory */
            lazer64_memrw(lazercfg->target_process, LAZER_MEMOP_WRITE, 0, NULL);
            break;

        case 46:    /* zero memory */
            lazer64_memrw(lazercfg->target_process, LAZER_MEMOP_WRITE, LAZER_FLAG_ZEROMEMORY, NULL);
            break;

        /* --- misc ---- */
        case 60:
            lazer64_ftox_calc();
            break;

        case 72:
            lazer64_getphysicaladdr_nonpaged();
            break;

        case 73:    /* get directorytablebase */
            lazer64_get_directorybasetable(lazercfg->target_process);
            break;

        /* eggz */
        case 0xcc:
            /* open physmem */
            ; uint64_t open_status = STATUS_SUCCESS;
            uint32_t exit_code = 0;
            if (LAZER_SUCCESS == driver_open_physical_memory(&open_status, &exit_code)) {
                printf("[+] Opened/Closed PhysicalMemory handle\n");
            } else {
                printf("[-] Status: %#02llx (%llu) CLOSE: %#02x\n", open_status, open_status, exit_code);
            }
            break;

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

int lazer64_menu(lbool display_logo) {
    if (display_logo) {
        printeye();
    }

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
        return_value = lazer64_menu(LAZER_FALSE);
    }

    return (return_value == LAZER_EXIT) ? LAZER_SUCCESS : LAZER_ERROR;
}