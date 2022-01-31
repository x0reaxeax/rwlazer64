/**
* TODO_NEXT:
*   LOGGING:   Write DEBUG info
*   DOCUMENT:  Write documentation/info
*/

#include "lazer64.h"

lazer64_cfg_t *lazercfg = NULL;

int main(int argc, const char* argv[]) {
    if (LAZER_SUCCESS != lazer64_init(argc, argv) || NULL == lazercfg) {
        /* Unable to initialize RWLAZER or operation aborted */
        return lazer64_final(LAZER_ERROR);
    }

    /* Run main menu loop, dont display logo on startup */
    lazer64_menu(LAZER_TRUE);

    return lazer64_final(LAZER_READLASTERR);
}