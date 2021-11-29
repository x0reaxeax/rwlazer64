#include "lazer64.h"
#include "driver_userctl.h"

#include <stdio.h>

process_info* lazer64_init(void) {
	printf("[*] Initializing RWLAZER64..");
	fflush(stdout);

	process_info* lazerinfo = malloc(sizeof(process_info));
	char* error_msg = NULL;

	if (NULL == lazerinfo) {
		return NULL;
	}

	if (driver_initialize() != true) {
		error_msg = "EFI_INIT_FAILURE";
		goto LAZER_INIT_FAIL;
	}

	if (driver_checkefi(lazerinfo) != true) {
		error_msg = "EFI_COMM_FAILURE";
		goto LAZER_INIT_FAIL;
	}


	printf("\r[+] Successfully initialized RWLAZER64\n");
	return lazerinfo;


LAZER_INIT_FAIL:
	printf("\r[-] Failed to initialize RWLAZER64 [%s]\n", (error_msg != NULL) ? error_msg : "ERR_UNKNOWN");
	free(lazerinfo);
	return NULL;
}

inline void lazer64_final(process_info* lazer64) {
	free(lazer64);
}

int main(int argc, const char* argv[]) {
	process_info* lazer64 = lazer64_init();

	if (NULL == lazer64) {
		return EXIT_FAILURE;
	}
	

	
	lazer64_final(lazer64);
	return EXIT_SUCCESS;
}