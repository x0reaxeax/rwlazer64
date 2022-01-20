#ifndef _RWLAZER_EFIDRIVER_CTL_H_
#define _RWLAZER_EFIDRIVER_CTL_H_

#include "lazer64.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS										0x00000000
#endif

#define WIN_PROCESSID_INVALID								0xFFFFFFFF	/* 0xFFFFFFFC is max valid procid */
#define WIN_PROCESSID_SYSTEM								0x4ULL

#define LAZER_EFI_VARIABLE_NAME								L"rwlazer64"

#define DRIVER_HANDLE_UNINITIALIZED							0

#define DRIVER_CMD_GETBADDR									0x300
#define DRIVER_CMD_GETPROC									0x310
#define DRIVER_CMD_RDMSR									0x320
#define DRIVER_CMD_WRMSR									0x330
#define DRIVER_CMD_MEMCPY									0x340
#define DRIVER_CMD_VTOPHYSADDR								0x350

typedef struct __memory_command {
	unsigned int		driver_operation;
	unsigned int		exit_status;
	unsigned long long	data[16];
} memory_command;

typedef struct __proc_info {
	unsigned long long	process_id;
	unsigned long long	base_address;
} process_info;

#if !defined(LAZER_EFI_ONLY) && defined(WIN32)

#include <winnt.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

/**
 * https://uefi.org/sites/default/files/resources/UEFI%20Spec%202_6.pdf
*/
#define EFI_VARIABLE_NON_VOLATILE							0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS						0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS							0x00000004
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD					0x00000008
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS				0x00000010
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS	0x00000020
#define EFI_VARIABLE_APPEND_WRITE							0x00000040
#define EFI_ATTRIBUTES										(EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS)

#define MAXIMUM_FILENAME_LENGTH								255

#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)
#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), (PWSTR)s }

#define STATUS_INFO_LENGTH_MISMATCH							0xC0000004

extern GUID EFI_GUID;
extern HANDLE g_driver_handle;
extern uint64_t g_lazer_process_id;

NTSYSAPI NTSTATUS NTAPI RtlAdjustPrivilege(_In_ unsigned long privilege, _In_ bool enable, _In_ bool client, _Out_ bool* was_enabled);
NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemEnvironmentValueEx(	_In_ UNICODE_STRING* variable_name,
															_In_ GUID* vendor_guid,
															_In_reads_bytes_opt_(value_length) void* value,
															_In_ size_t value_length,
															_In_ unsigned long attributes);

/**
* https://processhacker.sourceforge.io/doc/struct___r_t_l___p_r_o_c_e_s_s___m_o_d_u_l_e___i_n_f_o_r_m_a_t_i_o_n.html
*/
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE	Section;
	PVOID	MappedBase;
	PVOID	ImageBase;
	ULONG	ImageSize;
	ULONG	Flags;
	USHORT	LoadOrderIndex;
	USHORT	InitOrderIndex;
	USHORT	LoadCount;
	USHORT	OffsetToFileName;
	UCHAR	FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

#ifdef LAZER_FUTURE
/**
* http://undocumented.ntinternals.net/index.html
*/
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
	ULONG                   HandleCount;
	ULONG                   Reserved2[2];
	ULONG                   PrivatePageCount;
	VM_COUNTERS             VirtualMemoryCounters;
	IO_COUNTERS             IoCounters;
	SYSTEM_THREAD           Threads[0];

} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
#endif

/**
* https://processhacker.sourceforge.io/doc/struct___s_y_s_t_e_m___h_a_n_d_l_e___t_a_b_l_e___e_n_t_r_y___i_n_f_o.html
*/
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT	UniqueProcessId;
	USHORT	CreatorBackTraceIndex;
	UCHAR	ObjectTypeIndex;
	UCHAR	HandleAttributes;
	USHORT	HandleValue;
	PVOID	Object;
	ULONG	GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_MODULE {
	ULONG	Reserved1;						/* Reserved (always 0xBAADF00D) */
	ULONG	Reserved2;						/* Reserved (always 0) */
	PVOID	ImageBaseAddress;				/* Module address in virtual address space */
	ULONG	ImageSize;						/* Size of module in virtual address space */
	ULONG	Flags;							/* ??? */
	WORD	Id;								/* 0-based counter of results */
	WORD	Rank;							/* The same as Id (in global enumeration with NtQuerySystemInformation), or unknown */
	WORD	w018;							/* In process module enumeration with LdrQueryProcessModuleInformation always 0xFFFF, in other - unknown */
	WORD	NameOffset;						/* Offset in Name table to first char of module name */
	BYTE	Name[MAXIMUM_FILENAME_LENGTH];	/* Path to module */
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG ModulesCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum __ENUMTYPE_SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11,
	SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION;

uintptr_t	GetKernelModuleAddress(char* module_name);
uintptr_t	GetKernelModuleExport(uintptr_t kernel_module_base, char* function_name);
NTSTATUS	SetSystemEnvironmentPrivilege(bool enable, bool* was_enabled);

bool driver_initialize(void);
bool driver_checkefi(process_info* procinfo);
NTSTATUS driver_sendcommand(memory_command* cmd);
NTSTATUS driver_copy_memory(uint64_t dest_process_id, uintptr_t dest_address, uint64_t src_process_id, uintptr_t src_address, size_t size);
NTSTATUS driver_read_memory(process_info* procinfo, uintptr_t address, byte* outbuf, size_t size);
NTSTATUS driver_write_memory(process_info* procinfo, uintptr_t address, byte* inputbuf, size_t size);
NTSTATUS driver_readmsr(uint64_t cpureg);
NTSTATUS driver_writemsr(uint64_t cpureg, int64_t value);
uintptr_t driver_get_base_address(process_info *procinfo);
uintptr_t driver_get_physical_address(process_info* procinfo, uintptr_t virtual_address);

#endif

#endif