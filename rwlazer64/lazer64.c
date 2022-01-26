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
int lazer64_init(const char *exec_path) {
    printf("[*] Initializing RWLAZER64..");
    fflush(stdout);

    HANDLE h_console = NULL;
    process_info *lazerinfo = NULL;
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    lazercfg = malloc(sizeof(lazer64_cfg_t));
    lazerinfo = malloc(sizeof(process_info));

    if (NULL == lazerinfo || NULL == lazercfg) {
        log_write(LOG_ERROR, "Unable to initialize RWLAZER64: E%d - '%s'", errno, strerror(errno));
        goto LAZER_INIT_FAIL;
    }

    /* set defaults */
    lazercfg->default_console_attr = 0;
    lazercfg->exit_code = LAZER_SUCCESS;
    lazercfg->log_status = 0;
    lazercfg->log_level = (uint16_t) LOG_NOTIF;
    lazerinfo->exec_path = exec_path;
    
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
    puts("[+] Exiting..");
    if (NULL != lazercfg) {
        /* check if default command line text color has been saved and if so, restore it */
        if (lazercfg->default_console_attr) {
            if (!SetConsoleTextAttribute(lazercfg->h_console, lazercfg->default_console_attr)) {
                LAZER_SETLASTERR("lazer64_final()", GetLastError(), true);
            }
        }

        /* Display informational message if logfile has been updated */
        if (lazercfg->log_status > 0) {
            puts("\n[+] Logfile has been updated");
        }

        /* free lazer process info and global config */
        free(lazercfg->lazer64_procinfo);
        free(lazercfg);
        lazercfg = NULL;
    }

    log_write(LOG_NOTIF, "Shutting down..");

    return exit_code;
}

static void printeye(void) {	
    const unsigned int char_count = 49;
    const unsigned int line_count = 27;
    char sigaint[][49] = {
        "                  64RWLAZER64R                  ",
        "             ZER64RWLAZER64RWLAZER6             ",
        "         AZER64RW              64RWLAZE         ",
        "      AZER64       B4RWLAZER6       V64RWL      ",
        "    ZER64        BRWLAZER64RWLA        VZER64   ",
        "  ER64          BLAZER6  LAZER64          VRWL  ",
        "C64RW           ZER64      R64RW           ZER64",
        "CLAZE           WZWOLLAZERZRLLR1           WLAZE",
        "  ER64RW         LAZER64RWLAZER         RWLAZE  ",
        "   AZER64RWLA      R64RWLAZER      WLAZER64RW   ",
        "     ER64RWLAZER                ER64RWLAZER     ",
        "      RWLAZER64RWLAZER64RWLAZER64RWLAZER        ",
        "      RW        LAZER64RWLAZER64    ZER         ",
        "      64          64RWLAZER64RW     R64         ",
        "     LAZE          ER     RWLA      RWL         ",
        "      64           LA      ZER      AZE         ",
        "                   64      RWL     LAZER        ",
        "                  ZER6      WZ      RWL         ",
        "                 LAZER6    ZER       L          ",
        "                  4RWL    RWLAZ                 ",
        "                   RW      ER6                  ",
        "                            4                   ",
        "    ____ _       ____    ___ _____   __________ ",
        "   / __ \\ |     / / /   /   /__  /  / ____/ __ \\",
        "  / /_/ / | /| / / /   / /| | / /  / __/ / /_/ /",
        " / _, _/| |/ |/ / /___/ ___ |/ /__/ /___/ _, _/ ",
        "/_/ |_| |__/|__/_____/_/  |_/____/_____/_/ |_|  "
    };

    const char sig_red = 'C';
    const char sig_blue = 'B';
    const char sig_white = 'V';

    putchar('\n');
    SetConsoleTextAttribute(lazercfg->h_console, COLOR_WHITE);
    for (unsigned int i = 0; i < line_count; i++) {
        for (unsigned int j = 0; j < char_count; j++) {
            if (sigaint[i][j] == sig_white) {
                SetConsoleTextAttribute(lazercfg->h_console, COLOR_WHITE);
                sigaint[i][j] = 'W';
            }
            else if (sigaint[i][j] == sig_red) {
                SetConsoleTextAttribute(lazercfg->h_console, COLOR_RED);
                sigaint[i][j] = 'R';
            }
            else if (sigaint[i][j] == sig_blue) {
                SetConsoleTextAttribute(lazercfg->h_console, COLOR_BLUE);
                sigaint[i][j] = 'Z';
            }

            printf("%c", sigaint[i][j]);
        }
        putchar('\n');
    }

    putchar('\n');
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
        case 0:
            printf("ENTER PID:\n");
            break;

        case 99:
            return_value = LAZER_EXIT;
            break;

        default:
            break;
    }

    return return_value;
}

int lazer64_attach(process_info* target_process) {

}

int lazer64_menu(void) {
    process_info* target_process = malloc(sizeof(process_info));

    if (NULL == target_process) {
        log_write(LOG_ERROR, "Unable to allocate memory: E%d - %s", errno, strerror(errno));
        return LAZER_ERROR;
    }
    

    printeye();
    printf(	"[ ---========== *** RWLAZER64 *** ==========--- ]\n"
            "  * RWLAZER PID: %llu [%llx]\n"
            "  * RWLAZER Base Address: %#02llx\n"
            "  * EXE Name: '%s'\n\n",
        lazercfg->lazer64_procinfo->process_id, lazercfg->lazer64_procinfo->process_id, lazercfg->lazer64_procinfo->base_address, lazercfg->lazer64_procinfo->exec_path
    );

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
    return (return_value == LAZER_EXIT) ? LAZER_SUCCESS : LAZER_ERROR;
}