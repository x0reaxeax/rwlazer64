#include "driverctl.h"

#include <intrin.h>

uintptr_t g_lazer_process_id	= WIN_PROCESSID_INVALID;
HANDLE g_driver_handle			= DRIVER_HANDLE_UNINITIALIZED;
GUID EFI_GUID					= { 0x31c0 };

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

	procinfo.process_id = WIN_PROCESSID_SYSTEM;
	procinfo.base_address = LAZER_ADDRESS_INVALID;
	
	if (!NT_SUCCESS(driver_read_memory(&procinfo, kernel_module_base, (byte*)&dos_header, sizeof(dos_header)))) {
		return 0; 
	}

	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
		return 0; 
	}

	if (!NT_SUCCESS(driver_read_memory(&procinfo, kernel_module_base + dos_header.e_lfanew, (byte*)&nt_headers, sizeof(nt_headers)))) { return 0; }

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

	if (!NT_SUCCESS(driver_read_memory(&procinfo, kernel_module_base + export_base, (byte*)export_data, export_base_size))) { 
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
			uintptr_t function_address = kernel_module_base + functions_table[ordinals_table[i]];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
				function_address = 0;
			}
			
			VirtualFree(export_data, 0, MEM_RELEASE);
			return function_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
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
		if (NULL == system_information_buffer) { return 0; }

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
		char* current_module_name = (char *) (proc_modules->Modules[i].FullPathName + proc_modules->Modules[i].OffsetToFileName);

		if (strncmp(current_module_name, module_name, MAXIMUM_FILENAME_LENGTH) == EXIT_SUCCESS) {
			result_address = (uintptr_t) (proc_modules->Modules[i].ImageBase);
			break;
		}
	}

	VirtualFree(system_information_buffer, 0, MEM_RELEASE);
	return result_address;
}

bool driver_initialize(void) {
	bool se_sysenv_enabled = false;
	uintptr_t result = 0;
	NTSTATUS status = STATUS_SUCCESS;
	uintptr_t ntoskrnl_address = 0;
	uintptr_t pslprocbypid_address = 0;
	uintptr_t psgetbaseaddr_address = 0;
	uintptr_t mmcpvirtualmem_address = 0;

	byte ntoskrnl_exe[]		= "ntoskrnl.exe";
	byte pslprocbypid[]		= "PsLookupProcessByProcessId";
	byte psgetbaseaddr[]	= "PsGetProcessSectionBaseAddress";
	byte mmcpvirtualmem[]	= "MmCopyVirtualMemory";

	memory_command cmd;

	g_lazer_process_id = GetCurrentProcessId();

	status = SetSystemEnvironmentPrivilege(true, &se_sysenv_enabled);

	if (!NT_SUCCESS(status)) { return false; }


	ntoskrnl_address = GetKernelModuleAddress(ntoskrnl_exe);
	pslprocbypid_address = GetKernelModuleExport(ntoskrnl_address, pslprocbypid);
	psgetbaseaddr_address = GetKernelModuleExport(ntoskrnl_address, psgetbaseaddr);
	mmcpvirtualmem_address = GetKernelModuleExport(ntoskrnl_address, mmcpvirtualmem);

	cmd.driver_operation = DRIVER_CMD_GETPROC;
	cmd.data[0] = pslprocbypid_address;
	cmd.data[1] = psgetbaseaddr_address;
	cmd.data[2] = mmcpvirtualmem_address;
	cmd.data[3] = (uintptr_t) &result;

	status = driver_sendcommand(&cmd);

	if (!NT_SUCCESS(status)) { return false; }

	return result;
}

bool driver_checkefi(process_info *procinfo) {
	if (NULL == procinfo) {
		return false;
	}
	
	uint pid = WIN_PROCESSID_INVALID;
	NTSTATUS status = STATUS_SUCCESS;
	uintptr_t base_address = 0;

	procinfo->process_id = GetCurrentProcessId();

	base_address = driver_get_base_address(procinfo);

	if (base_address != procinfo->base_address) {
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
	UNICODE_STRING variable_name = RTL_CONSTANT_STRING(ENV_VARIABLE_NAME);
	NTSTATUS status = NtSetSystemEnvironmentValueEx(&variable_name, &EFI_GUID, cmd, sizeof(memory_command), EFI_ATTRIBUTES);

	return status;
}

NTSTATUS driver_readmsr(uint64_t cpureg) {
	NTSTATUS status = STATUS_SUCCESS;
	uintptr_t regvalue = 0;
	memory_command cmd;

	cmd.driver_operation = DRIVER_CMD_RDMSR;
	cmd.data[0] = cpureg;
	cmd.data[1] = (uintptr_t) &regvalue;
	status = driver_sendcommand(&cmd);

	return status;
}

NTSTATUS driver_writemsr(uint64_t cpureg, int64_t value) {
	NTSTATUS status = STATUS_SUCCESS;
	memory_command cmd;

	cmd.driver_operation = DRIVER_CMD_WRMSR;
	cmd.data[0] = cpureg;
	cmd.data[1] = value;
	status = driver_sendcommand(&cmd);

	return status;
}

NTSTATUS driver_copy_memory(uint64_t dest_process_id, uintptr_t dest_address, uint64_t src_process_id, uintptr_t src_address, size_t size) {
	NTSTATUS status = STATUS_SUCCESS;
	uintptr_t op_result = 0;
	memory_command cmd;

	cmd.driver_operation = DRIVER_CMD_MEMCPY;
	cmd.data[0] = dest_process_id;
	cmd.data[1] = dest_address;
	cmd.data[2] = src_process_id;
	cmd.data[3] = src_address;
	cmd.data[4] = size;
	cmd.data[5] = (uintptr_t)&op_result;
	status = driver_sendcommand(&cmd);

	if (NT_SUCCESS(status)) {
		return (NTSTATUS) op_result;
	}

	return status;
}

uintptr_t driver_get_base_address(process_info* procinfo) {
	if (NULL == procinfo) { return LAZER_ERROR_NULLPTR; }
	NTSTATUS status = STATUS_SUCCESS;

	memory_command cmd;
	cmd.driver_operation = DRIVER_CMD_GETBADDR;
	cmd.data[0] = procinfo->process_id;
	cmd.data[1] = (uintptr_t)(&(procinfo->base_address));
	if (!NT_SUCCESS(driver_sendcommand(&cmd))) {
		/* you sure? */
		return 0;
	}

	return procinfo->base_address;
}

uintptr_t driver_get_physical_address(process_info* procinfo, uintptr_t virtual_address) {
	return 0x0;
}

NTSTATUS driver_read_memory(process_info* procinfo, uintptr_t address, byte* outbuf, size_t size) {
	if (NULL == procinfo || NULL == outbuf) { return LAZER_ERROR_NULLPTR; }
	return driver_copy_memory(g_lazer_process_id, (uintptr_t) outbuf, procinfo->process_id, address, size);
}

NTSTATUS driver_write_memory(process_info* procinfo, uintptr_t address, byte* inputbuf, size_t size) {
	if (NULL == procinfo || NULL == inputbuf) { return LAZER_ERROR_NULLPTR; }
	return driver_copy_memory(procinfo->process_id, address, g_lazer_process_id, (uintptr_t) inputbuf, size);
}