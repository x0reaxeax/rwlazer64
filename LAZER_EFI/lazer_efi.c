/**
 * @file lazer_efi.c
 * @author x0reaxeax (x0reaxeax@sigaint.net)
 * @brief EFI driver for RWLAZER64
 * This code is heavily based on CRZEFI by @TheCruZ (https://github.com/TheCruZ/EFI_Driver_Access)
 * I rewrote this one from scratch in order to understand what's really going on here.
 * A lot of the code is obviously very similar to CRZEFI.
 * I included actual NT prototypes in "ntkernel.h", it helped me understand what, where and why.
 * 
 * Here are my resources, big thanks to all of the people behind these:
 * https://processhacker.sourceforge.io/
 * https://www.nirsoft.net/
 * https://github.com/TheCruZ/EFI_Driver_Access
 * https://uefi.org/sites/default/files/resources/UEFI_Spec_2_9_2021_03_18.pdf
 * 
 * I will write comments and documentation when RWLAZER will be glued together in one piece
 * @version 0.1 alpha
 * @date 2022-01-20
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#define LAZER_EFI_ONLY
#define GNU_EFI_USE_MS_ABI 1
#define MS_ABI __attribute__((ms_abi))

#include "rwlazer64/driverctl.h"
#include "LAZER_EFI/include/ntkernel.h"

#define LAZER_KEY           0xDE7EC7ED1A7E1264

/* NT */
typedef unsigned int NTSTATUS;
typedef unsigned int DWORD;

typedef struct __dummy_protocol_data {
    UINTN empty;
} dummy_protocol_data;

typedef NTSTATUS (MS_ABI *PsLookupProcessByProcessId) (
    IN void *proc_handle, OUT KPROCESS **out_process
);

typedef void * (MS_ABI *PsGetProcessSectionBaseAddress) (
    IN KPROCESS *process
);

typedef NTSTATUS (MS_ABI *MmCopyVirtualMemory) (
    KPROCESS *src_process, void *src_address,
    KPROCESS *target_process, void *target_address,
    UINT64 bufsize,
    KPROCESSOR_MODE ring_level,
    SIZE_T *returnsz
);

typedef PHYSICAL_ADDRESS (MS_ABI *MmGetPhysicalAddress) (
    void *base_address
);

typedef void (MS_ABI *RtlInitUnicodeString) (
    OUT UNICODE_STRING *destination_string,
    OPTIONAL const WCHAR *source_string
);

typedef NTSTATUS (MS_ABI *ZwOpenSection) (
    OUT void **section_handle,
    IN  ACCESS_MASK desired_access,
    IN  OBJECT_ATTRIBUTES *object_attributes
);

typedef NTSTATUS (MS_ABI *ZwClose) (
    IN void *handle
);

/**
 * UINT32  Data1;
 * UINT16  Data2;
 * UINT16  Data3;
 * UINT8   Data4[8];
 */

/* LAZER UNIQUE */
static const EFI_GUID protocol_guid
	= { 0x10147312, 0x1473, 0x1264, { 0x12, 0x44, 0x01, 0x04, 0x07, 0x03, 0x12, 0x64} };

/* VirtualAddressMap GUID (gEfiEventVirtualAddressChangeGuid) 
 * EFI_GUID(0x13fa7698, 0xc831, 0x49c7, 0x87, 0xea, 0x8f, 0x43, 0xfc, 0xc2, 0x51, 0x96)
 */
static const EFI_GUID virtual_guid
	= { 0x13fa7698, 0xc831, 0x49c7, { 0x87, 0xea, 0x8f, 0x43, 0xfc, 0xc2, 0x51, 0x96 } };

/* ExitBootServices GUID (gEfiEventExitBootServicesGuid) 
 * EFI_GUID(0x27abf055, 0xb1b8, 0x4c26, 0x80, 0x48, 0x74, 0x8f, 0x37, 0xba, 0xa2, 0xdf)
 */
static const EFI_GUID exit_guid
    = { 0x27abf055, 0xb1b8, 0x4c26, { 0x80, 0x48, 0x74, 0x8f, 0x37, 0xba, 0xa2, 0xdf } };


static EFI_SET_VARIABLE setvariable = NULL;

static EFI_EVENT notify_event       = NULL;
static EFI_EVENT exit_event         = NULL;
static BOOLEAN virtual              = FALSE;
static BOOLEAN runtime              = FALSE;

static PsLookupProcessByProcessId       get_process_by_pid      = (PsLookupProcessByProcessId)      NULL;
static PsGetProcessSectionBaseAddress   get_base_address        = (PsGetProcessSectionBaseAddress)  NULL;
static MmCopyVirtualMemory              copy_virtual_memory     = (MmCopyVirtualMemory)             NULL;
static MmGetPhysicalAddress             get_physical_address    = (MmGetPhysicalAddress)            NULL;
static RtlInitUnicodeString             rtl_init_unicodestr     = (RtlInitUnicodeString)            NULL;
static ZwOpenSection                    zw_open_section         = (ZwOpenSection)                   NULL;
static ZwClose                          zw_close_handle         = (ZwClose)                         NULL;

static void printeye(void);

static HANDLE open_physical_memory (NTSTATUS *status) {
    if (NULL == status) {
        return NULL;
    }
    
    HANDLE physmem_handle = NULL;
    UNICODE_STRING physmem_string;
    OBJECT_ATTRIBUTES object_attribs;
    WCHAR physmem_path[] = L"\\device\\physicalmemory";

    rtl_init_unicodestr(&physmem_string, physmem_path);
    InitializeObjectAttributes(&object_attribs, &physmem_string, OBJ_CASE_INSENSITIVE, NULL, NULL);

    *status = zw_open_section(&physmem_handle, SECTION_MAP_READ, &object_attribs);

    if (status != STATUS_SUCCESS) {
        return NULL;
    }

    return physmem_handle;
}

EFI_STATUS exec_cmd(memory_command *cmd) {
    if (NULL == cmd) {
        return EFI_ABORTED;
    }

    if (LAZER_KEY != cmd->lazer_key) {
        cmd->exit_status = LAZER_ERROR_BADKEY;
    }

    if (cmd->driver_operation == DRIVER_CMD_GETBADDR) {
        KPROCESS            *process_ptr    = NULL;
        LAZER_UINT64        *process_id     = (LAZER_UINT64 *) cmd->data[LAZER_DATA_DEST_PROCID];
        LAZER_UINT64        *result_addr    = (LAZER_UINT64 *) cmd->data[LAZER_DATA_RESULT];
        if (get_process_by_pid(process_id, &process_ptr) != STATUS_SUCCESS || process_ptr == NULL) {
            *result_addr = 0;
            cmd->exit_status    = LAZER_ERROR_NOPROC;
            return EFI_SUCCESS;
        }

        *result_addr = (LAZER_UINT64) get_base_address(process_ptr);
        cmd->exit_status    = LAZER_RETURN_SUCCESS;
        return EFI_SUCCESS;
    } else if (cmd->driver_operation == DRIVER_CMD_MEMCPY) {
        LAZER_UINT64   *dest_process_id     = (LAZER_UINT64 *) cmd->data[LAZER_DATA_DEST_PROCID];
        LAZER_UINT64   *dest_address        = (LAZER_UINT64 *) cmd->data[LAZER_DATA_DEST_ADDR];
        LAZER_UINT64   *src_process_id      = (LAZER_UINT64 *) cmd->data[LAZER_DATA_SRC_PROCID];
        LAZER_UINT64   *src_address         = (LAZER_UINT64 *) cmd->data[LAZER_DATA_SRC_ADDR];
        LAZER_UINT64    size                =                  cmd->data[LAZER_DATA_SIZE];
        LAZER_UINT64   *result_addr         = (LAZER_UINT64 *) cmd->data[LAZER_DATA_RESULT];

        if (src_process_id == (LAZER_UINT64 *) WIN_PROCESSID_SYSTEM) {
            CopyMem(dest_address, src_address, size);
        } else {
            KPROCESS *src_process = NULL;
            KPROCESS *dest_process = NULL;
            SIZE_T outsz = 0;
            int status = STATUS_SUCCESS;
            cmd->exit_status = LAZER_ERROR_NOPROC;

            status = get_process_by_pid(src_process_id, &src_process);
            if (status != STATUS_SUCCESS) {
                *result_addr = 0;
                return EFI_SUCCESS;
            }

            status = get_process_by_pid(dest_process_id, &dest_process);
            if (status != STATUS_SUCCESS) {
                *result_addr = 0;
                return EFI_SUCCESS;
            }
            
            *result_addr = copy_virtual_memory(src_process, src_address, dest_process, dest_address, size, KernelMode, &outsz);
        }
        cmd->exit_status    = LAZER_RETURN_SUCCESS;

        return EFI_SUCCESS;
    } else if (cmd->driver_operation == DRIVER_CMD_GETPROC) {
        /* get function addresses from KernelModuleExport */
        get_process_by_pid  = (PsLookupProcessByProcessId)      cmd->data[LAZER_DATA_SPEC_ADDREXPORT_0];
        get_base_address    = (PsGetProcessSectionBaseAddress)  cmd->data[LAZER_DATA_SPEC_ADDREXPORT_1];
        copy_virtual_memory = (MmCopyVirtualMemory)             cmd->data[LAZER_DATA_SPEC_ADDREXPORT_2];
        get_physical_address= (MmGetPhysicalAddress)            cmd->data[LAZER_DATA_SPEC_ADDREXPORT_3];
        rtl_init_unicodestr = (RtlInitUnicodeString)            cmd->data[LAZER_DATA_SPEC_ADDREXPORT_4];
        zw_open_section     = (ZwOpenSection)                   cmd->data[LAZER_DATA_SPEC_ADDREXPORT_5];
        zw_close_handle     = (ZwClose)                         cmd->data[LAZER_DATA_SPEC_ADDREXPORT_6];
        
        LAZER_UINT64 *resaddr   = (LAZER_UINT64 *) cmd->data[LAZER_DATA_RESULT];
        *resaddr                = 1;
        cmd->exit_status        = LAZER_RETURN_SUCCESS;
        return EFI_SUCCESS;
    } else if (cmd->driver_operation == DRIVER_CMD_RDMSR) {
        uint32_t msr_id = (uint32_t) cmd->data[LAZER_DATA_SPEC_RDMSR_MSRID];
        uint32_t low32 = 0, high32 = 0;
        __asm__ volatile (  ".intel_syntax noprefix;"
                            "push   rax;"
                            "push   rcx;"
                            "push   rdx;"
                            "xor    eax, eax;"
                            "xor    ecx, ecx;"
                            "xor    edx, edx;"
                            "mov    ecx, %[MSR32];"
                            "rdmsr;"
                            "mov    %[LOW32],   eax;"
                            "mov    %[HIGH32],  edx;"
                            "pop    rdx;"
                            "pop    rcx;"
                            "pop    rax;"
                            ".att_syntax;"
                            : [LOW32] "=r" (low32), [HIGH32] "=r" (high32)
                            : [MSR32] "r" (msr_id)
                            : "rax", "rdx", "rcx"
        );

        cmd->data[LAZER_DATA_SPEC_RDMSR_LOW32]    = low32;
        cmd->data[LAZER_DATA_SPEC_RDMSR_HIGH32]   = high32;
        cmd->exit_status = LAZER_RETURN_SUCCESS;
        return EFI_SUCCESS;
    } else if (cmd->driver_operation == DRIVER_CMD_WRMSR) {
        uint32_t msr_id = cmd->data[LAZER_DATA_SPEC_WRMSR_MSRID];
        uint32_t low32  = cmd->data[LAZER_DATA_SPEC_WRMSR_LOW32];
        uint32_t high32 = cmd->data[LAZER_DATA_SPEC_WRMSR_HIGH32];
        /* "Undefined or reserved bits in an MSR should be set to values previously read"
         * self_note: when out of testing, probably do rdmsr first or pass read data in cmd->data,
         * before doing wrmsr
         */
        __asm__ volatile ( ".intel_syntax noprefix;"
                            "push   rax;"
                            "push   rcx;"
                            "push   rdx;"
                            "xor    eax, eax;"
                            "xor    ecx, ecx;"  /* on IA64, high32 of RCX is ignored anyway, but whatever, not important now */
                            "xor    edx, edx;"
                            "mov    eax, %[LOW32];"
                            "mov    edx, %[HIGH32];"
                            "mov    ecx, %[MSRID];"
                            "wrmsr;"
                            "pop    rdx;"
                            "pop    rcx;"
                            "pop    rax;"
                            ".att_syntax;"
                            :
                            : [LOW32] "r" (low32), [HIGH32] "r" (high32), [MSRID] "r" (msr_id)
                            : "rax", "rdx", "rcx"
        );
        return EFI_SUCCESS;
    } else if (cmd->driver_operation == DRIVER_CMD_GETDIRTABLEBASE) {
        NTSTATUS status = STATUS_SUCCESS;
        KPROCESS *dest_process = NULL;
        LAZER_UINT64 *dest_process_id = (LAZER_UINT64 *) cmd->data[LAZER_DATA_DEST_PROCID];
        
        status = get_process_by_pid(dest_process_id, &dest_process);
        if (status != STATUS_SUCCESS) {
            cmd->exit_status = LAZER_ERROR_NOPROC;
            return EFI_SUCCESS;
        }

        /* read directory table base */
        cmd->data[LAZER_DATA_RESULT] = dest_process->DirectoryTableBase;

        cmd->exit_status = LAZER_RETURN_SUCCESS;
        return EFI_SUCCESS;
    } else if (cmd->driver_operation == DRIVER_CMD_VTOPHYS_NONPAGED) {
        void *virt_base_addr = (void *) cmd->data[LAZER_DATA_SRC_ADDR];

        if (NULL == virt_base_addr) {
            cmd->exit_status = LAZER_ERROR_EINVAL;
            return EFI_SUCCESS;
        }

        PHYSICAL_ADDRESS phys_addr = get_physical_address(virt_base_addr);
        cmd->data[LAZER_DATA_RESULT_MISC_0] = phys_addr.u.LowPart;
        cmd->data[LAZER_DATA_RESULT_MISC_1] = phys_addr.u.HighPart;
        cmd->data[LAZER_DATA_RESULT_MISC_2] = phys_addr.QuadPart;
        cmd->exit_status = LAZER_RETURN_SUCCESS;

        return EFI_SUCCESS;
    } else if (cmd->driver_operation == DRIVER_CMD_READPHYSMEM) {
        /* goldman sachs cely majetok prec */
        cmd->exit_status = LAZER_RETURN_SUCCESS;
        return EFI_SUCCESS;
    } else if (cmd->driver_operation == DRIVER_CMD_DEBUGOP) {
        NTSTATUS status = STATUS_SUCCESS;
        HANDLE phys_mem = open_physical_memory(&status);
        cmd->data[LAZER_DATA_RESULT] = status;
        cmd->data[LAZER_DATA_RESULT_MISC_0] = (uintptr_t) phys_mem;
        /*
            ...
            cmd->exit_status = zw_close_handle(phys_mem);
        */
        cmd->exit_status = LAZER_RETURN_SUCCESS;
        return EFI_SUCCESS;
    }

    cmd->exit_status = LAZER_ERROR_EINVOP;
    return EFI_UNSUPPORTED;
}


EFI_STATUS EFIAPI hooked_set_variable (IN CHAR16 *variable_name,
                                       IN EFI_GUID *vendor_guid,
                                       IN UINT32 attributes, IN UINTN datasz,
                                       IN VOID *data)
{
    if (virtual && runtime) {
        if (variable_name != NULL && variable_name[0] != CHAR_NULL && vendor_guid != NULL) {
            if (StrnCmp(variable_name, LAZER_EFI_VARIABLE_NAME, StrLen(LAZER_EFI_VARIABLE_NAME)) == EFI_SUCCESS) {
                if (datasz == 0 && data == NULL) {
                    return EFI_SUCCESS;
                }

                if (datasz == sizeof(memory_command)) {
                    return exec_cmd((memory_command *) data);
                }
            }
        }
    }

    return setvariable(variable_name, vendor_guid, attributes, datasz, data);
}

VOID EFIAPI SetVirtualAddressMapEvent(IN EFI_EVENT event, IN VOID *ctx) {
    RT->ConvertPointer(0, (void **) &setvariable);
    RT->ConvertPointer(0, (void **) &oGetTime);
	RT->ConvertPointer(0, (void **) &oSetTime);
	RT->ConvertPointer(0, (void **) &oGetWakeupTime);
	RT->ConvertPointer(0, (void **) &oSetWakeupTime);
	RT->ConvertPointer(0, (void **) &oSetVirtualAddressMap);
	RT->ConvertPointer(0, (void **) &oConvertPointer);
	RT->ConvertPointer(0, (void **) &oGetVariable);
	RT->ConvertPointer(0, (void **) &oGetNextVariableName);
	RT->ConvertPointer(0, (void **) &oGetNextHighMonotonicCount);
	RT->ConvertPointer(0, (void **) &oResetSystem);
	RT->ConvertPointer(0, (void **) &oUpdateCapsule);
	RT->ConvertPointer(0, (void **) &oQueryCapsuleCapabilities);
	RT->ConvertPointer(0, (void **) &oQueryVariableInfo);

    RtLibEnableVirtualMappings();

    notify_event = NULL;
    
    /* virtual address space switch */
    virtual = TRUE;
}

VOID EFIAPI ExitBootServicesEvent(IN EFI_EVENT event, IN VOID *ctx) {
    BS->CloseEvent(exit_event);
    exit_event = NULL;

    BS = NULL;
    runtime = TRUE;
}

VOID *SetServicePointer( IN OUT EFI_TABLE_HEADER *service_table_header, IN OUT VOID **service_table_function, IN VOID *new_function) {
    if (service_table_function == NULL || new_function == NULL) {
        return NULL;
    }

    ASSERT(BS != NULL);
    ASSERT(BS->CalculateCrc32 != NULL);

    CONST EFI_TPL tpl = BS->RaiseTPL(TPL_HIGH_LEVEL);
    VOID *original_function = *service_table_function;
    *service_table_function = new_function;

    service_table_header->CRC32 = 0;
    BS->CalculateCrc32((UINT8 *) service_table_header, service_table_header->HeaderSize, &service_table_header->CRC32);

    BS->RestoreTPL(tpl);

    return original_function;
}

static EFI_STATUS EFI_FUNCTION efi_unload(IN EFI_HANDLE image_handle) {
    return EFI_ACCESS_DENIED;
}

EFI_STATUS efi_main(IN EFI_HANDLE image_handle, IN EFI_SYSTEM_TABLE *system_table) {
    InitializeLib(image_handle, system_table);

    static EFI_LOADED_IMAGE *loaded_image = NULL;
    EFI_STATUS status = BS->OpenProtocol(image_handle, &LoadedImageProtocol, (void **) &loaded_image, image_handle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);

    if (EFI_ERROR(status)) {
        Print(L"Cannot open protocol: %d\n", status);
        return status;
    }

    EFI_DEVICE_PATH_PROTOCOL *wboot_path = FileDevicePath(loaded_image->DeviceHandle, L"\\EFI\\Microsoft\\Boot\\bootmgfwx.efi");

    /* checkout InstallMultipleProtocolInterfaces */
    dummy_protocol_data dummy_data = { 0 };
    status = LibInstallProtocolInterfaces(&image_handle, &protocol_guid, &dummy_data, NULL);

    if (EFI_ERROR(status)) {
        Print(L"Cannot register interface: %d\n", status);
        return status;
    }

    loaded_image->Unload = (EFI_IMAGE_UNLOAD) efi_unload;

    status = BS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY, SetVirtualAddressMapEvent, NULL, &virtual_guid, &notify_event);

    if (EFI_ERROR(status)) {
        Print(L"Cannot create event (SetVirtualAddressMapEvent): %d\n", status);
        return status;
    }

    status = BS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY, ExitBootServicesEvent, NULL, &exit_guid, &exit_event);

    if (EFI_ERROR(status)) {
        Print(L"Cannot create event (ExitBootServicesEvent): %d\n", status);
        return status;
    }

    // Hook SetVariable (should not fail)
	setvariable = (EFI_SET_VARIABLE) SetServicePointer(&RT->Hdr, (VOID**)&RT->SetVariable, (VOID**)&hooked_set_variable);

	// Hook all the other runtime services functions
	oGetTime                    = (EFI_GET_TIME)                   SetServicePointer(&RT->Hdr, (VOID**)&RT->GetTime,                    (VOID**)&HookedGetTime);
	oSetTime                    = (EFI_SET_TIME)                   SetServicePointer(&RT->Hdr, (VOID**)&RT->SetTime,                    (VOID**)&HookedSetTime);
	oGetWakeupTime              = (EFI_GET_WAKEUP_TIME)            SetServicePointer(&RT->Hdr, (VOID**)&RT->GetWakeupTime,              (VOID**)&HookedGetWakeupTime);
	oSetWakeupTime              = (EFI_SET_WAKEUP_TIME)            SetServicePointer(&RT->Hdr, (VOID**)&RT->SetWakeupTime,              (VOID**)&HookedSetWakeupTime);
	oSetVirtualAddressMap       = (EFI_SET_VIRTUAL_ADDRESS_MAP)    SetServicePointer(&RT->Hdr, (VOID**)&RT->SetVirtualAddressMap,       (VOID**)&HookedSetVirtualAddressMap);
	oConvertPointer             = (EFI_CONVERT_POINTER)            SetServicePointer(&RT->Hdr, (VOID**)&RT->ConvertPointer,             (VOID**)&HookedConvertPointer);
	oGetVariable                = (EFI_GET_VARIABLE)               SetServicePointer(&RT->Hdr, (VOID**)&RT->GetVariable,                (VOID**)&HookedGetVariable);
	oGetNextVariableName        = (EFI_GET_NEXT_VARIABLE_NAME)     SetServicePointer(&RT->Hdr, (VOID**)&RT->GetNextVariableName,        (VOID**)&HookedGetNextVariableName);
	oGetNextHighMonotonicCount  = (EFI_GET_NEXT_HIGH_MONO_COUNT)   SetServicePointer(&RT->Hdr, (VOID**)&RT->GetNextHighMonotonicCount,  (VOID**)&HookedGetNextHighMonotonicCount);
	oResetSystem                = (EFI_RESET_SYSTEM)               SetServicePointer(&RT->Hdr, (VOID**)&RT->ResetSystem,                (VOID**)&HookedResetSystem);
	oUpdateCapsule              = (EFI_UPDATE_CAPSULE)             SetServicePointer(&RT->Hdr, (VOID**)&RT->UpdateCapsule,              (VOID**)&HookedUpdateCapsule);
	oQueryCapsuleCapabilities   = (EFI_QUERY_CAPSULE_CAPABILITIES) SetServicePointer(&RT->Hdr, (VOID**)&RT->QueryCapsuleCapabilities,   (VOID**)&HookedQueryCapsuleCapabilities);
	oQueryVariableInfo          = (EFI_QUERY_VARIABLE_INFO)        SetServicePointer(&RT->Hdr, (VOID**)&RT->QueryVariableInfo,          (VOID**)&HookedQueryVariableInfo);
    
    printeye();
    Print(  L"****************************************************\n"
	        L"*         PRESS ANY KEY TO BOOT WINDOWS 10         *\n"
	        L"****************************************************\n"
    );
    
    WaitForSingleEvent(system_table->ConIn->WaitForKey, 0);
    Print(L"\n[+] Booting Windows 10...\n");
    EFI_HANDLE wimage;
    status = BS->LoadImage(FALSE, image_handle, wboot_path, NULL, 0, &wimage);

    if (EFI_ERROR(status)) {
        Print(L"Failed to load Windows 10 boot image [bootmgfwx.efi]: %d\n", status);
        return status;
    }

    status = BS->StartImage(wimage, NULL, NULL);

    if (EFI_ERROR(status)) {
        Print(L"Failed to start Windows 10 boot image [bootmgfwx.efi]: %d\n", status);
        return status;
    }

    return EFI_SUCCESS;
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

	ST->ConOut->SetAttribute(ST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);
	const char sig_red = 'C';
	const char sig_blue = 'B';
	const char sig_white = 'V';

	for (unsigned int i = 0; i < line_count; i++) {
		for (unsigned int j = 0; j < char_count; j++) {
			if (sigaint[i][j] == sig_white) {
				ST->ConOut->SetAttribute(ST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);
				sigaint[i][j] = 'W';
			}
			else if (sigaint[i][j] == sig_red) {
				ST->ConOut->SetAttribute(ST->ConOut, EFI_RED | EFI_BACKGROUND_BLACK);
				sigaint[i][j] = 'R';
			}
			else if (sigaint[i][j] == sig_blue) {
				ST->ConOut->SetAttribute(ST->ConOut, EFI_BLUE | EFI_BACKGROUND_BLACK);
				sigaint[i][j] = 'Z';
			}

			Print(L"%c", sigaint[i][j]);
		}
		Print(L"\n");
	}

	Print(L"\n");
}