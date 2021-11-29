#define LAZER_EFI_ONLY
#define GNU_EFI_USE_MS_ABI 1
#define MS_ABI __attribute__((ms_abi))
#include "../rwlazer64/driverctl.h"
#include "ntkernel.h"


/* NT */
typedef unsigned int NTSTATUS;
typedef unsigned int DWORD;

typedef struct __dummy_protocol_data {
    UINTN empty;
} dummy_protocol_data;

typedef NTSTATUS            (MS_ABI *PsLookupProcessByProcessId) (void *proc_handle, KPROCESS **out_process);
typedef void *              (MS_ABI *PsGetProcessSectionBaseAddress) (KPROCESS *process);
typedef NTSTATUS            (MS_ABI *MmCopyVirtualMemory)(KPROCESS *src_process, void *src_address, KPROCESS *target_process, void *target_address, UINT64 bufsize, KPROCESSOR_MODE ring_level, SIZE_T *returnsz);
typedef PHYSICAL_ADDRESS    (MS_ABI *MmGetPhysicalAddress)(void *virtual_address);

/**
 * UINT32  Data1;
 * UINT16  Data2;
 * UINT16  Data3;
 * UINT8   Data4[8];
*/
static const EFI_GUID protocol_guid = { 0x00147312, 0xdead, 0xc0de, { 0x14, 0x73, 0x12, 0x64, 0x14, 0x73, 0x12, 0x64 } };
static const EFI_GUID virtual_guid  = { 0x00147312, 0xdead, 0xc0de, { 0x14, 0x73, 0x12, 0x64, 0x14, 0x73, 0x12, 0x64 } };
static const EFI_GUID exit_guid     = { 0x00147312, 0xdead, 0xc0de, { 0x14, 0x73, 0x12, 0x64, 0x14, 0x73, 0x12, 0x64 } };

static EFI_SET_VARIABLE setvariable = NULL;

static EFI_EVENT notify_event       = NULL;
static EFI_EVENT exit_event         = NULL;
static BOOLEAN virtual              = FALSE;
static BOOLEAN runtime              = FALSE;

static PsLookupProcessByProcessId get_process_by_pid    = (PsLookupProcessByProcessId)0;
static PsGetProcessSectionBaseAddress get_base_address  = (PsGetProcessSectionBaseAddress)0;
static MmCopyVirtualMemory copy_virtual_memory          = (MmCopyVirtualMemory)0;
static MmGetPhysicalAddress get_physical_address        = (MmGetPhysicalAddress)0;

void printeye(void);

EFI_STATUS exec_cmd(memory_command *cmd) {
    if (NULL == cmd) {
        return EFI_ABORTED;
    }

    if (cmd->driver_operation == DRIVER_CMD_GETBADDR) {
        struct _KPROCESS *process_ptr = NULL;
        uint64_t *process_id = (uint64_t *) cmd->data[0];
        uintptr_t *result_addr = (uintptr_t *) cmd->data[1];
        if (get_process_by_pid(process_id, &process_ptr) != STATUS_SUCCESS || process_ptr == NULL) {
            *result_addr = 0;
            return EFI_SUCCESS;
        }

        *result_addr = (uintptr_t) get_base_address(process_ptr);
        return EFI_SUCCESS;
    } else if (cmd->driver_operation == DRIVER_CMD_MEMCPY) {
        uint64_t *src_process_id    = (uintptr_t *) cmd->data[0];
        uintptr_t *src_address      = (uintptr_t *) cmd->data[1];
        uint64_t *dest_process_id   = (uintptr_t *) cmd->data[2];
        uintptr_t *dest_address     = (uintptr_t *) cmd->data[3];
        uint64_t size               =               cmd->data[4];
        uintptr_t *result_addr      = (uintptr_t *) cmd->data[5];
        int *status_ret             = (int *)       cmd->data[6];

        if (src_process_id == (uintptr_t *) WIN_PROCESSID_SYSTEM) {
            CopyMem(dest_address, src_address, size);
        } else {
            struct _KPROCESS *src_processs = NULL;
            struct _KPROCESS *dest_process = NULL;
            SIZE_T outsz = 0;
            int status = STATUS_SUCCESS;

            status = get_process_by_pid(src_process_id, &src_processs);
            if (status != STATUS_SUCCESS) {
                *result_addr = 0;
                *status_ret = status;
                return EFI_SUCCESS;
            }

            status = get_process_by_pid(dest_process_id, &dest_process);
            if (status != STATUS_SUCCESS) {
                *result_addr = 0;
                *status_ret = status;
                return EFI_SUCCESS;
            }

            *result_addr = copy_virtual_memory(src_processs, src_address, dest_process, dest_address, size, 1, &outsz);
        }

        return EFI_SUCCESS;
    } else {
        return EFI_UNSUPPORTED;
    }
}


EFI_STATUS EFIAPI hooked_set_variable(IN CHAR16 *variable_name, IN EFI_GUID *vendor_guid, IN UINT32 attributes, IN UINTN datasz, IN VOID *data) {
    if (virtual && runtime) {
        if (variable_name != NULL && variable_name[0] != CHAR_NULL && vendor_guid != NULL) {
            if (StrnCmp(variable_name, LAZER_EFI_VARIABLE_NAME, (sizeof(LAZER_EFI_VARIABLE_NAME) / sizeof(CHAR16)) - 1) == EFI_SUCCESS) {
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

    //if (image_handle == NULL || system_table == NULL)

    static EFI_LOADED_IMAGE *loaded_image = NULL;
    EFI_STATUS status = BS->OpenProtocol(image_handle, &LoadedImageProtocol, (void **) &loaded_image, image_handle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);

    if (EFI_ERROR(status)) {
        Print(L"Cannot open protocol: %d\n", status);
        return status;
    }

    EFI_DEVICE_PATH_PROTOCOL *wboot_path = FileDevicePath(loaded_image->DeviceHandle, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
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
    EFI_HANDLE wimage;
    status = BS->LoadImage(FALSE, image_handle, wboot_path, NULL, 0, &wimage);

    if (EFI_ERROR(status)) {
        Print(L"Failed to load Windows 10 boot image [bootmgfw.efi]: %d\n", status);
        return status;
    }

    status = BS->StartImage(wimage, NULL, NULL);

    if (EFI_ERROR(status)) {
        Print(L"Failed to start Windows 10 boot image [bootmgfw.efi]: %d\n", status);
        return status;
    }

    return EFI_SUCCESS;
}

void printeye(void) {
	const unsigned int char_count = 49;
	const unsigned int line_count = 26;
	char sigaint[][49] = {
		"              XXAA1XXE1XXA0OOR0O                ",
		"         1OXXEXA0OAOXXE0EEEAX1AO0RR0A           ",
		"      X1OXXX       BORRAXXOX1       WRAOOA      ",
		"    0X0AA        B0AXXXEO1RRXOR         WXXX    ",
		"  XRAX          BXXXA0O1EAOAOE1E          WXR0  ",
		"CXXA            RXER1XAOAOR0OX1A            W1RR",
		"CRE0            0E0ORXER1EEAXXA1            OXER",
		"  0REA01         01E11EXAOXE0X1         011EER  ",
		"   XXXOXEX0RRX     RAXA1AREXO     10XXEOOAOXE   ",
		"     R0XAXXRORXR0ROOAA0EAOX0XXRXXXAAXRXEORE     ",
		"      0EXXX0ER0XRROE1R01EXAE0AAX0REROXAX        ",
		"      EO        1XARX110OO1OR0OX    OXX         ",
		"      1X          XAXOR1X10ARX1     1OA         ",
		"     AAX1          OR     1XXX      1RX         ",
		"      RX           OA      XAR      EAE         ",
		"                  0OX      ARE     ORXEX        ",
		"                  EAOE      0E      000         ",
		"                 A1RRXE    0XA       X          ",
		"                  EO1O    XEX0X                 ",
		"                   A0      XOR                  ",
        "                                                ",
        "    ____ _       ____    ___ _____   __________ ",
        "   / __ \\ |     / / /   /   /__  /  / ____/ __ \\",
        "  / /_/ / | /| / / /   / /| | / /  / __/ / /_/ /",
        " / _, _/| |/ |/ / /___/ ___ |/ /__/ /___/ _, _/ ",
        "/_/ |_| |__/|__/_____/_/  |_/____/_____/_/ |_|  "
	};

	ST->ConOut->SetAttribute(ST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);
	const char sig_red = 'C';
	const char sig_blue = 'B';
	const char sig_white = 'W';

	for (unsigned int i = 0; i < line_count; i++) {
		for (unsigned int j = 0; j < char_count; j++) {
			if (sigaint[i][j] == sig_white) {
				ST->ConOut->SetAttribute(ST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);
				sigaint[i][j] = 'X';
			}
			else if (sigaint[i][j] == sig_red) {
				ST->ConOut->SetAttribute(ST->ConOut, EFI_RED | EFI_BACKGROUND_BLACK);
				sigaint[i][j] = 'X';
			}
			else if (sigaint[i][j] == sig_blue) {
				ST->ConOut->SetAttribute(ST->ConOut, EFI_BLUE | EFI_BACKGROUND_BLACK);
				sigaint[i][j] = 'X';
			}

			Print(L"%c", sigaint[i][j]);
		}
		Print(L"\n");
	}

	Print(L"\n");
}