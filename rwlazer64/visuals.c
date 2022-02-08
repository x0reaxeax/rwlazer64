#include "driverctl.h"

#include <stdio.h>

#pragma warning (disable : 4996)

void printeye(void) {
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
            } else if (sigaint[i][j] == sig_red) {
                SetConsoleTextAttribute(lazercfg->h_console, COLOR_RED);
                sigaint[i][j] = 'R';
            } else if (sigaint[i][j] == sig_blue) {
                SetConsoleTextAttribute(lazercfg->h_console, COLOR_BLUE);
                sigaint[i][j] = 'Z';
            }

            printf("%c", sigaint[i][j]);
        }
        putchar('\n');
    }

    putchar('\n');
}

void print_intro(void) {
    char target_process_info[128] = { 0 };
    if (lazercfg->target_process != NULL) {
        if (lazercfg->target_process->process_id != WIN_PROCESSID_INVALID) {
            char base_addr_info[64] = { 0 };
            if (LAZER_CHECK_ADDRESS(lazercfg->target_process->base_address)) {
                snprintf(base_addr_info, 64, "  * Target Base Address: %#02llx\n", lazercfg->target_process->base_address);
            }
            snprintf(target_process_info, 128, "  * Target PID: %llu [%#02llx]\n%s\n",
                     lazercfg->target_process->process_id,
                     lazercfg->target_process->process_id,
                     base_addr_info
            );
        }
    }

    size_t space_indent = 35;
    char format_spaces[5][48] = { 0 };
    size_t n_formats = sizeof(lazer64_oplog) / sizeof(uintptr_t);
    uintptr_t *oplog_entry = (uintptr_t *) lazercfg->operation_history;
    char lazer_baddr[LAZER_ADDRLEN_HEX] = { 0 };
    if (LAZER_CHECK_ADDRESS(lazercfg->lazer64_procinfo->base_address)) {
        snprintf(lazer_baddr, LAZER_ADDRLEN_HEX, "%#02llx", lazercfg->lazer64_procinfo->base_address);
    } else {
        strncpy(lazer_baddr, "INVALID ADDRESS", 16);
    }
    //uintptr_t lazer_baddr = (LAZER_CHECK_ADDRESS(lazercfg->lazer64_procinfo->base_address)) ? lazercfg->lazer64_procinfo->base_address : 

    printf("\n[ ---========== *** RWLAZER64 *** ==========--- ]\n"
           "  * RWLAZER PID: %llu [%llx]\n"
           "  * RWLAZER Base Address: %s\n"
           "  * EXE Name: '%s'\n%s\n",
           lazercfg->lazer64_procinfo->process_id,
           lazercfg->lazer64_procinfo->process_id,
           lazer_baddr,
           lazercfg->lazer64_procinfo->exec_path,
           target_process_info
    );

    for (size_t i = 0; i < n_formats; i++) {
        size_t indent = space_indent - int_ndigits(*oplog_entry, BASE_HEXADECIMAL);
        memset(format_spaces[i], ' ', indent);
        oplog_entry++;
    }

    printf("\n"
           "-----------------------------------------------------------------\n"
           "| OP | Generic operations       | OP | Misc Tools               |\n"
           "|====|==========================|====|==========================|\n"
           "|  0 | Set target process       | 50 | Memory scanner           |\n"
           "|  1 | Get base address         | 51 | Signature scanner        |\n"
           "|  2 | Print data type chart    | 60 | Float <-> Hex calculator |\n"
           "|  3 | Print this menu          | 61 | Base calculator          |\n"
           "|  4 | Clear history            | 72 | MmGetPhysicalAddress()   |\n"
           "|  5 | Clear console            | 73 | Get DirectoryTableBase   |\n"
           "|  6 | Fresh start              |    |                          |\n"
           "| 99 | Exit                     | CC | Debug [OpenPhysicalMem]  |\n"
           "|===============================================================|\n"
           "| OP | Read Operations          | OP | Write Operations         |\n"
           "|====|==========================|====|==========================|\n"
           "| 30 | Read memory              | 40 | Write memory             |\n"
           "| 31 | Read process info        | 41 | Alter process info       |\n"
           "| 32 | Read string              | 42 | Write string             |\n"
           "| 33 | Read from last address   | 43 | Write to last address    |\n"
           "| 34 | Read MSR                 | 44 | Write MSR                |\n"
           "| 35 | Read physical memory     | 45 | Write to physical memory |\n"
           "|    |                          | 46 | Zero memory              |\n"
           "|    |                          | 47 | Freeze value             |\n"
           "|===============================================================|\n"
           "| Last read address:      0x%llx%s |\n"
           "| Last read value:        0x%llx%s |\n"
           "| Last write address:     0x%llx%s |\n"
           "| Last write value:       0x%llx%s |\n"
           "| Last calculator result: 0x%llx%s |\n"
           "-----------------------------------------------------------------\n",
           lazercfg->operation_history->last_read_address,      format_spaces[0],
           lazercfg->operation_history->last_read_value,        format_spaces[1],
           lazercfg->operation_history->last_write_address,     format_spaces[2],
           lazercfg->operation_history->last_write_value,       format_spaces[3],
           lazercfg->operation_history->last_calculator_result, format_spaces[4]
    );

}

void print_datatypes(void) {
    puts("[ -=== DATA TYPE SIZE CHART ===- ]");
    strtodtsz(NULL, true);
}

void print_help(void) {
    puts("[*] Startup arguments:\n"
           "    --help      - Display this dialog\n"
           "    --nologo    - Disable logo art\n"
           "    --debug     - Enable debugging logs\n\n"
    );
}