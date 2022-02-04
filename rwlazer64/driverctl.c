#include "driverctl.h"

#include <intrin.h>

GUID EFI_GUID					= { 0x31c0 };

#ifdef __LAZER_DEBUG
#include <stdio.h>

static int debug_step(const char *printmsg) {
    char buffer[4] = { 0 };
    printf("%s", printmsg);
    printf("ENTER to continue..\n");
    fgets(buffer, 2, stdin);
    if (buffer[0] == '\n') {
        return LAZER_SUCCESS;
    }
    return LAZER_ERROR;
}
#endif


NTSTATUS SetSystemEnvironmentPrivilege(bool enable, bool* was_enabled) {
    if (NULL != was_enabled) { was_enabled = false; }	/* reset */ 

    bool __was_enabled = false;
    NTSTATUS status = RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, enable, false, &__was_enabled);

    if (NT_SUCCESS(status) && NULL != was_enabled) { *was_enabled = __was_enabled; }

    return status;
}

uintptr_t GetKernelModuleExport(uintptr_t kernel_module_base, char* function_name) {
    if (0 == kernel_module_base || NULL == function_name) { return 0; }

    uintptr_t export_base = 0;
    uint64_t export_base_size = 0;
    
    IMAGE_DOS_HEADER dos_header = { 0 };
    IMAGE_NT_HEADERS64 nt_headers = { 0 };

    IMAGE_EXPORT_DIRECTORY* export_data = NULL;

    process_info procinfo;

    /**
    * AddressOfNames [32 bits]
    * AddressOfNameOrdinals [16 bits]
    * AddressOfFunctions [32 bits]
    */
    uintptr_t delta = 0;
    uint32_t *names_table = NULL;
    uint16_t *ordinals_table = NULL;
    uint32_t *functions_table = NULL;

    uintptr_t function_address = 0;

    procinfo.process_id = WIN_PROCESSID_SYSTEM;
    procinfo.base_address = LAZER_ADDRESS_INVALID;
    
    if (!NT_SUCCESS(driver_read_memory(&procinfo, kernel_module_base, (byte *) &dos_header, sizeof(dos_header)))) {
        return 0; 
    }


    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        return 0; 
    }

    if (!NT_SUCCESS(driver_read_memory(&procinfo, kernel_module_base + dos_header.e_lfanew, (byte *) &nt_headers, sizeof(nt_headers)))) { return 0; }

    if (nt_headers.Signature != IMAGE_NT_SIGNATURE) { 
        return 0;
    }

    export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (0 == export_base || 0 == export_base_size) { 
        return 0; 
    }

    export_data = VirtualAlloc(NULL, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NULL == export_data) { 
        return 0; 
    }

    if (!NT_SUCCESS(driver_read_memory(&procinfo, kernel_module_base + export_base, (byte *) export_data, export_base_size))) { 
        return 0;
    }

    delta = (uintptr_t) export_data - export_base;
    names_table = (uint32_t *) (export_data->AddressOfNames + delta);
    ordinals_table = (uint16_t*)(export_data->AddressOfNameOrdinals + delta);
    functions_table = (uint32_t*)(export_data->AddressOfFunctions + delta);

    /**
    * https://resources.infosecinstitute.com/topic/the-export-directory/
    */
    for (uint64_t i = 0; i < export_data->NumberOfNames; i++) {
        char* current_function_name = (char *) (names_table[i] + delta);
        if (strncmp(current_function_name, function_name, MAXIMUM_FILENAME_LENGTH) == EXIT_SUCCESS) {
            function_address = kernel_module_base + functions_table[ordinals_table[i]];

            if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
                function_address = 0;
            }
            
            break;
        }
    }

    VirtualFree(export_data, 0, MEM_RELEASE);
    return function_address;
}

uintptr_t GetKernelModuleAddress(char* module_name) {
    if (NULL == module_name) { return 0; }
    uintptr_t result_address = 0;
    NTSTATUS status = STATUS_SUCCESS;
    void* system_information_buffer = NULL;
    RTL_PROCESS_MODULES* proc_modules = NULL;
    unsigned long system_information_bufsiz = 0;

    /* "may be altered or unavailable in future versions of Windows. Applications should use the alternate functions listed in this topic."
     * That's fucking helpful when 90% of this shit is undocumented. stupid fuckwads.
    */
    status = NtQuerySystemInformation(SystemModuleInformation, system_information_buffer, system_information_bufsiz, &system_information_bufsiz);
    while (status == STATUS_INFO_LENGTH_MISMATCH && status != STATUS_NO_MEMORY) {
        /**
        * dwSize: "If the dwFreeType parameter is MEM_RELEASE, this parameter must be 0 (zero). The function frees the entire region that is reserved in the initial allocation call to VirtualAlloc."
        */
        if (NULL != system_information_buffer) {
            if (VirtualFree(system_information_buffer, 0, MEM_RELEASE) != true) { return 0; }
        }

        system_information_buffer = VirtualAlloc(NULL, system_information_bufsiz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (NULL == system_information_buffer) { 
            return 0;
        }

        status = NtQuerySystemInformation(SystemModuleInformation, system_information_buffer, system_information_bufsiz, &system_information_bufsiz);
    }

    if (!NT_SUCCESS(status)) {
        if (system_information_buffer != NULL) {
            VirtualFree(system_information_buffer, 0, MEM_RELEASE);
        }
        return 0;
    }

    proc_modules = (RTL_PROCESS_MODULES*) system_information_buffer;
    if (NULL == proc_modules) {
        if (system_information_buffer != NULL) {
            VirtualFree(system_information_buffer, 0, MEM_RELEASE);
        }
        return 0;
    }

    for (uint64_t i = 0; i < proc_modules->NumberOfModules; i++) {
        log_write(LOG_DEBUG, "Enumerating proc_modules: %u", i);
        char* current_module_name = (char *) (proc_modules->Modules[i].FullPathName + proc_modules->Modules[i].OffsetToFileName);

        if (strncmp(current_module_name, module_name, MAXIMUM_FILENAME_LENGTH) == EXIT_SUCCESS) {
            log_write(LOG_DEBUG, "Found '%s'..", current_module_name);
            result_address = (uintptr_t) (proc_modules->Modules[i].ImageBase);
            break;
        }
    }

    VirtualFree(system_information_buffer, 0, MEM_RELEASE);
    return result_address;
}

bool driver_initialize(void) {
    if (NULL == lazercfg) {
        log_write(LOG_CRITICAL, "Process info for LAZER64 process has not been initialized");
        return false;
    }

    bool se_sysenv_enabled = false;
    uintptr_t result = 0;
    NTSTATUS status = STATUS_SUCCESS;
    uintptr_t ntoskrnl_address = 0;

    /* ntoskrnl */
    uintptr_t pslprocbypid_address = 0;
    uintptr_t psgetbaseaddr_address = 0;
    uintptr_t mmcpvirtualmem_address = 0;
    uintptr_t mmgetphysicaladdress_address = 0;
    uintptr_t rtlinitunicodestring_address = 0;
    uintptr_t zwopensection_address = 0;
    uintptr_t zwclose_address = 0;

    byte ntoskrnl_exe[]		= "ntoskrnl.exe";
    
    /* ntoskrnl exports */
    byte pslprocbypid[]		    = "PsLookupProcessByProcessId";
    byte psgetbaseaddr[]	    = "PsGetProcessSectionBaseAddress";
    byte mmcpvirtualmem[]	    = "MmCopyVirtualMemory";
    byte mmgetphysicaladdress[] = "MmGetPhysicalAddress";
    byte rtlinitunicodestring[] = "RtlInitUnicodeString";
    byte zwopensection[]        = "ZwOpenSection";
    byte zwclose[]              = "ZwClose";
    


    memory_command cmd = { 0 };
    lazercfg->lazer64_procinfo->process_id = GetCurrentProcessId();

    log_write(LOG_DEBUG, "Calling SetSystemEnvironmentPrivilege()..");
    status = SetSystemEnvironmentPrivilege(true, &se_sysenv_enabled);
    if (!NT_SUCCESS(status)) { 
        /* log_write(LOG_ERROR, "SetSystemEnvironmentPrivilege(): %#02lx", status); */
        LAZER_SETLASTERR("driver_initialize() -> SetSystemEnvironmentPrivilege()", status, true);
        return false; 
    }

    log_write(LOG_DEBUG, "Retrieving '%s' address..", ntoskrnl_exe);
    ntoskrnl_address = GetKernelModuleAddress(ntoskrnl_exe);
    log_write(LOG_DEBUG, "Got '%s' address: %#02llx", ntoskrnl_exe, ntoskrnl_address);

    if (!LAZER_CHECK_ADDRESS(ntoskrnl_address)) {
        LAZER_SETLASTERR("driver_initialize()", LAZER_ERROR_INITINST, false);
        return false;
    }

    pslprocbypid_address = GetKernelModuleExport(ntoskrnl_address, pslprocbypid);
    psgetbaseaddr_address = GetKernelModuleExport(ntoskrnl_address, psgetbaseaddr);
    mmcpvirtualmem_address = GetKernelModuleExport(ntoskrnl_address, mmcpvirtualmem);
    mmgetphysicaladdress_address = GetKernelModuleExport(ntoskrnl_address, mmgetphysicaladdress);
    rtlinitunicodestring_address = GetKernelModuleExport(ntoskrnl_address, rtlinitunicodestring);
    zwopensection_address = GetKernelModuleExport(ntoskrnl_address, zwopensection);
    zwclose_address = GetKernelModuleExport(ntoskrnl_address, zwclose);
    log_write(LOG_DEBUG, "Function addresses exported from '%s'\n"
              " [+] PsLookupProcessByProcessId()     = %#02llx\n"
              " [+] PsGetProcessSectionBaseAddress() = %#02llx\n"
              " [+] MmCopyVirtualMemory()            = %#02llx\n"
              " [+] MmGetPhysicalAddress()           = %#02llx\n"
              " [+] RtlInitUnicodeString()           = %#02llx\n"
              " [+] ZwOpenSection()                  = %#02llx\n"
              " [+] ZwClose()                        = %#02llx\n",
              ntoskrnl_exe,
              pslprocbypid_address, psgetbaseaddr_address,
              mmcpvirtualmem_address, mmgetphysicaladdress_address,
              rtlinitunicodestring_address, zwopensection_address, zwclose_address
    );

    cmd.driver_operation = DRIVER_CMD_GETPROC;
    cmd.data[LAZER_DATA_SPEC_ADDREXPORT_0] = pslprocbypid_address;
    cmd.data[LAZER_DATA_SPEC_ADDREXPORT_1] = psgetbaseaddr_address;
    cmd.data[LAZER_DATA_SPEC_ADDREXPORT_2] = mmcpvirtualmem_address;
    cmd.data[LAZER_DATA_SPEC_ADDREXPORT_3] = mmgetphysicaladdress_address;
    cmd.data[LAZER_DATA_SPEC_ADDREXPORT_4] = rtlinitunicodestring_address;
    cmd.data[LAZER_DATA_SPEC_ADDREXPORT_5] = zwopensection_address;
    cmd.data[LAZER_DATA_SPEC_ADDREXPORT_6] = zwclose_address;
    cmd.data[LAZER_DATA_RESULT] = (uintptr_t) &result;

    status = driver_sendcommand(&cmd);

    if (!NT_SUCCESS(status)) { 
        LAZER_SETLASTERR("driver_initialize()", status, true);
        return false; 
    }
    log_write(LOG_DEBUG, "driver_sendcommand() success: %ld", status);

    return result;
}

bool driver_checkefi(process_info *procinfo) {
    if (NULL == procinfo) {
        return false;
    }
    
    uint32_t pid = WIN_PROCESSID_INVALID;
    NTSTATUS status = STATUS_SUCCESS;
    uintptr_t base_address = 0;

    procinfo->process_id = GetCurrentProcessId();

    base_address = driver_get_base_address(procinfo);

    if ( base_address != procinfo->base_address || !(LAZER_CHECK_ADDRESS(base_address)) ) {
        return false;
    }

    return true;
}

/**
* STATUS_SUCCESS				The function succeeded.
* STATUS_INSUFFICIENT_RESOURCES	Insufficient system resources exist for this request to complete.
* STATUS_INVALID_PARAMETER		One of the parameters is invalid.
* STATUS_NOT_IMPLEMENTED		This function is not supported on this platform.
* STATUS_UNSUCCESSFUL			The firmware returned an unrecognized error.
* STATUS_PRIVILEGE_NOT_HELD		The caller does not have the required privilege.
* STATUS_ACCESS_VIOLATION		One of the input parameters cannot be read.
*/
NTSTATUS driver_sendcommand(memory_command* cmd) {
    if (NULL == cmd) { return LAZER_ERROR_NULLPTR; }
    UNICODE_STRING variable_name = RTL_CONSTANT_STRING(LAZER_EFI_VARIABLE_NAME);
    cmd->exit_status = LAZER_ERROR_UNINITIALIZED;
    cmd->lazer_key = 0xDE7EC7ED1A7E1264;
    NTSTATUS status = NtSetSystemEnvironmentValueEx(&variable_name, &EFI_GUID, cmd, sizeof(memory_command), EFI_ATTRIBUTES);
    
    return status;
}

NTSTATUS driver_readmsr(uint64_t cpureg, int32_t *low32, int32_t *high32) {
    NTSTATUS status = STATUS_SUCCESS;
    memory_command cmd = { 0 };

    cmd.driver_operation = DRIVER_CMD_RDMSR;
    cmd.data[LAZER_DATA_SPEC_RDMSR_MSRID] = cpureg;
    status = driver_sendcommand(&cmd);

    if (NT_SUCCESS(status)) {
        *low32  = (int32_t) cmd.data[LAZER_DATA_SPEC_RDMSR_LOW32];
        *high32 = (int32_t) cmd.data[LAZER_DATA_SPEC_RDMSR_HIGH32];
    } else {
        LAZER_SETLASTERR("driver_readmsr()", status, true);
    }

    return status;
}

NTSTATUS driver_writemsr(uint64_t cpureg, int32_t low32, int32_t high32) {
    NTSTATUS status = STATUS_SUCCESS;
    memory_command cmd = { 0 };

    cmd.driver_operation = DRIVER_CMD_WRMSR;
    cmd.data[LAZER_DATA_SPEC_WRMSR_MSRID]  = cpureg;
    cmd.data[LAZER_DATA_SPEC_WRMSR_LOW32]  = low32;
    cmd.data[LAZER_DATA_SPEC_WRMSR_HIGH32] = high32;
    status = driver_sendcommand(&cmd);

    if (!NT_SUCCESS(status)) {
        LAZER_SETLASTERR("driver_writemsr()", status, true);
    }

    return status;
}

NTSTATUS driver_copy_memory(uint64_t dest_process_id, uintptr_t dest_address, uint64_t src_process_id, uintptr_t src_address, size_t size) {
    NTSTATUS status = STATUS_SUCCESS;
    uintptr_t op_result = 0;
    memory_command cmd = { 0 };

    cmd.driver_operation = DRIVER_CMD_MEMCPY;
    cmd.data[LAZER_DATA_DEST_PROCID]    = dest_process_id;
    cmd.data[LAZER_DATA_DEST_ADDR]      = dest_address;
    cmd.data[LAZER_DATA_SRC_PROCID]     = src_process_id;
    cmd.data[LAZER_DATA_SRC_ADDR]       = src_address;
    cmd.data[LAZER_DATA_SIZE]           = size;
    cmd.data[LAZER_DATA_RESULT]         = (uintptr_t)&op_result;
    
    log_write(LOG_DEBUG, 
            "Driver Command:\n"
            "[*] Operation: DRIVER_CMD_MEMCPY:\n"
            " Target Process ID:  %llu [%#02llx]\n"
            " Target Address:     %#02llx\n"
            " Source Process ID:  %llu [%#02llx]\n"
            " Source Address:     %#02llx\n"
            " Number of bytes:    %llu\n",
              cmd.data[LAZER_DATA_DEST_PROCID], cmd.data[LAZER_DATA_DEST_PROCID],
              cmd.data[LAZER_DATA_DEST_ADDR], 
              cmd.data[LAZER_DATA_SRC_PROCID],  cmd.data[LAZER_DATA_SRC_PROCID],
              cmd.data[LAZER_DATA_SRC_ADDR],    cmd.data[LAZER_DATA_SIZE]
    );

    status = driver_sendcommand(&cmd);
    if (!NT_SUCCESS(status)) {
        LAZER_SETLASTERR("driver_copy_memory()", status, true);
        return (NTSTATUS) op_result;
    }

    if (LAZER_SUCCESS != cmd.exit_status) {
        LAZER_SETLASTERR("driver_copy_memory()", cmd.exit_status, false);
        return cmd.exit_status;
    }

    log_write(LOG_DEBUG, "EFI exit status: %u", cmd.exit_status);
    return status;
}

uintptr_t driver_get_base_address(process_info* procinfo) {
    if (NULL == procinfo) { 
        LAZER_SETLASTERR("driver_get_base_address()", LAZER_ERROR_NULLPTR, false);
        return LAZER_ERROR_NULLPTR; 
    }
    NTSTATUS status = STATUS_SUCCESS;

    memory_command cmd = { 0 };
    cmd.driver_operation = DRIVER_CMD_GETBADDR;
    cmd.data[LAZER_DATA_DEST_PROCID] = procinfo->process_id;
    cmd.data[LAZER_DATA_RESULT]      = (uintptr_t)(&(procinfo->base_address));
    log_write(LOG_DEBUG,
                "Driver Command:\n"
                "[*] Operation: DRIVER_CMD_GETBADDR:\n"
                " Target Process ID:  %llu [%#02llx]\n",
        cmd.data[LAZER_DATA_DEST_PROCID], cmd.data[LAZER_DATA_DEST_PROCID]
    );

    status = driver_sendcommand(&cmd);

    if (!NT_SUCCESS(status)) {
        LAZER_SETLASTERR("driver_get_base_address()", status, true);
        return LAZER_ADDRESS_INVALID;
    }

    if (LAZER_SUCCESS != cmd.exit_status) {
        LAZER_SETLASTERR("driver_get_base_address()", cmd.exit_status, false);
        return LAZER_ADDRESS_INVALID;
    }

    return procinfo->base_address;
}

uintptr_t driver_get_directorybasetable(process_info *procinfo) {
    if (NULL == procinfo) {
        LAZER_SETLASTERR("driver_get_directorybasetable()", LAZER_ERROR_NULLPTR, false);
        return LAZER_ERROR_NULLPTR;
    }

    NTSTATUS status = STATUS_SUCCESS;

    memory_command cmd = { 0 };

    cmd.driver_operation = DRIVER_CMD_GETDIRTABLEBASE;
    cmd.data[LAZER_DATA_DEST_PROCID] = procinfo->process_id;
    status = driver_sendcommand(&cmd);
    
    if (!NT_SUCCESS(status)) {
        LAZER_SETLASTERR("driver_get_directorybasetable()", status, true);
        return LAZER_ADDRESS_INVALID;
    }

    if (LAZER_SUCCESS != cmd.exit_status) {
        LAZER_SETLASTERR("driver_get_directorybasetable()", cmd.exit_status, false);
        return LAZER_ADDRESS_INVALID;
    }

    return cmd.data[LAZER_DATA_RESULT];
}

int driver_mmgetphysicaladdress(uintptr_t target_address, uint32_t *low, int32_t *high, uint64_t *quad) {
    if (quad == NULL || high == NULL || low == NULL) {
        LAZER_SETLASTERR("driver_mmgetphysicaladdress()", LAZER_ERROR_NULLPTR, false);
        return LAZER_ERROR;
    }

    if (!LAZER_CHECK_ADDRESS(target_address)) {
        LAZER_SETLASTERR("driver_mmgetphysicaladdress()", EINVAL, false);
        return LAZER_ERROR;
    }

    NTSTATUS status = STATUS_SUCCESS;
    memory_command cmd = { 0 };

    cmd.driver_operation = DRIVER_CMD_VTOPHYS_NONPAGED;
    cmd.data[LAZER_DATA_SRC_ADDR] = target_address;

    status = driver_sendcommand(&cmd);

    if (!NT_SUCCESS(status)) {
        LAZER_SETLASTERR("driver_mmgetphysicaladdress()", status, true);
        return LAZER_ERROR;
    }

    if (LAZER_SUCCESS != cmd.exit_status) {
        LAZER_SETLASTERR("driver_mmgetphysicaladdress()", cmd.exit_status, false);
        return LAZER_ERROR;
    }

    *low  = (uint32_t) cmd.data[LAZER_DATA_RESULT_MISC_0];
    *high = (int32_t)  cmd.data[LAZER_DATA_RESULT_MISC_1];
    *quad = cmd.data[LAZER_DATA_RESULT_MISC_2];

    return LAZER_SUCCESS;
}

NTSTATUS driver_read_phys_memory(byte *output, uintptr_t target_phys_addr, size_t nbytes) {
    if (NULL == output) {
        LAZER_SETLASTERR("driver_read_phys_memory()", LAZER_ERROR_NULLPTR, false);
        return LAZER_ERROR;
    }

    if (!LAZER_CHECK_ADDRESS(target_phys_addr) || nbytes == 0 || nbytes > 64) {
        LAZER_SETLASTERR("driver_read_phys_memory()", EINVAL, false);
        return LAZER_ERROR;
    }

    NTSTATUS status = STATUS_SUCCESS;
    memory_command cmd = { 0 };

    cmd.driver_operation = DRIVER_CMD_READPHYSMEM;
    cmd.data[LAZER_DATA_SRC_ADDR] = target_phys_addr;
    cmd.data[LAZER_DATA_SIZE] = nbytes;

    status = driver_sendcommand(&cmd);

    if (!NT_SUCCESS(status)) {
        LAZER_SETLASTERR("driver_read_phys_memory()", status, true);
        return status;
    }

    if (LAZER_SUCCESS != cmd.exit_status) {
        LAZER_SETLASTERR("driver_read_phys_memory()", cmd.exit_status, false);
        return LAZER_ERROR;
    }

    memcpy(output, cmd.byte_data, nbytes);

    return LAZER_SUCCESS;
}

NTSTATUS driver_open_physical_memory(uint64_t *ret_status, uint32_t *exit_code) {
    NTSTATUS status = STATUS_SUCCESS;
    
    memory_command cmd = { 0 };
    cmd.driver_operation = DRIVER_CMD_DEBUGOP;
    
    status = driver_sendcommand(&cmd);

    *ret_status = cmd.data[LAZER_DATA_RESULT];
    *exit_code = cmd.exit_status;

    if (!NT_SUCCESS(status)) {
        LAZER_SETLASTERR("driver_read_phys_memory()", status, true);
        return status;
    }

    if (LAZER_SUCCESS != cmd.exit_status) {
        LAZER_SETLASTERR("driver_read_phys_memory()", cmd.exit_status, false);
        return LAZER_ERROR;
    }

    return LAZER_SUCCESS;
}

NTSTATUS driver_read_memory(process_info* procinfo, uintptr_t address, byte *outbuf, size_t size) {
    if (NULL == procinfo || 0 == outbuf) { 
        LAZER_SETLASTERR("driver_read_memory()", LAZER_ERROR_NULLPTR, false);
        return LAZER_ERROR_NULLPTR; 
    }
    return driver_copy_memory(lazercfg->lazer64_procinfo->process_id, (uintptr_t) outbuf, procinfo->process_id, address, size);
}

NTSTATUS driver_write_memory(process_info* procinfo, uintptr_t address, byte* inputbuf, size_t size) {
    if (NULL == procinfo || NULL == inputbuf) { 
        LAZER_SETLASTERR("driver_write_memory()", LAZER_ERROR_NULLPTR, false);
        return LAZER_ERROR_NULLPTR; 
    }
    return driver_copy_memory(procinfo->process_id, address, lazercfg->lazer64_procinfo->process_id, (uintptr_t) inputbuf, size);
}