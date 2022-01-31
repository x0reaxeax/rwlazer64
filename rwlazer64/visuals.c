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
                snprintf(base_addr_info, 64, "  * Target Base Address: %#02llx", lazercfg->target_process->base_address);
            }
            snprintf(target_process_info, 128, "  * Target PID: %llu [%#02llx]\n%s\n",
                     lazercfg->target_process->process_id,
                     lazercfg->target_process->process_id,
                     base_addr_info
            );
        }
    }

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

    printf("\n"
           "------------------------------------------------------------------------------------------------------------------------------------------------------------\n"
           "| OP | Generic operations       | OP | Read Operations          | OP | Write Operations         | OP | Misc Tools               | Information              |\n"
           "|____|__________________________|____|__________________________|____|__________________________|____|__________________________|__________________________|\n"
           "|  0 | Set target process       | 30 | Read memory              | 40 | Write memory             | 50 | Memory scanner           | Last read address:       |\n"
           "|  1 | Get base address         | 31 | Read process info        | 41 | Alter process info       | 51 | Signature scanner        | Last read value:         |\n"
           "|  2 | Print data type chart    | 32 | Read string              | 42 | Write string             | 60 | Float <-> Hex calculator | Last write address:      |\n"
           "|  3 | Print this menu          | 33 | Read from last address   | 43 | Write to last address    | 61 | Base calculator          | Last write value:        |\n"
           "|  4 | Clear history            | 34 | Read MSR                 | 44 | Write MSR                |    |                          | Last calculator result:  |\n"
           "|  5 | Clear console            |    |                          | 45 | Zero memory              |    |                          |                          |\n"
           "|  6 | Fresh start              |    |                          | 46 | Freeze value             |    |                          |                          |\n"
           "| 99 | Exit                     |    |                          |    |                          |    |                          |                          |\n"
           "------------------------------------------------------------------------------------------------------------------------------------------------------------\n"
    );


    //printf("[0]   - ")
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

void print_random_startup_quote(void) {
    char quotes[][128] = {
        "Deploying 64 heavy-duty lazers..",
        "Molotov cocktail z Grey Goose",
        "Just use radare2",
        "R-W-L-A-Z-E-R, what's your emergency?",
        "Downloading Digital Insanity Keygen..",
        "No BSOD? Whaaaaat???",
        "914nm Lazer a suprava od Louis V",
        "=== I n T e G r A t E d  =  C i R c U i T s ===",
        "Writing to PID 4 is usually a bad idea",
        "Ah shit, here we go again..",
        "Please tell me this is a Virtual Machine..",
        "300Gs, full-speed",
        "Used by professional spijons",
        "Interpol boys, keep your nasty hands away",
        "No Giorgio Armani suit detected, exiting..",
        "Using RWLAZER grants diplomatic immunity",
        "Predecessor of RWLAZER128",
        "Goldman Sachs cely majetok prec.."
    };

    size_t nquotes = sizeof(quotes) / sizeof(quotes[0]);
    uint64_t tick = GetTickCount64();
    srand((unsigned int) tick);

    unsigned int psrnum = (rand() % (nquotes + 1));
    if (psrnum < nquotes) {
        printf("< %s >\n", quotes[psrnum]);
    }
}