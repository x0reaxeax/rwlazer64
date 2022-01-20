#ifndef _RWLAZER_DRIVER_USERCTL_H_
#define _RWLAZER_DRIVER_USERCTL_H_

#include "lazer64.h"
#include "driver_userctl.h"

bool driver_initialize(void);
bool driver_checkefi(process_info* procinfo);
NTSTATUS driver_sendcommand(memory_command* cmd);
NTSTATUS driver_copy_memory(uint64_t dest_process_id, uintptr_t dest_address, uint64_t src_process_id, uintptr_t src_address, size_t size);
NTSTATUS driver_read_memory(process_info* procinfo, uintptr_t address, byte* outbuf, size_t size);
NTSTATUS driver_write_memory(process_info* procinfo, uintptr_t address, byte* inputbuf, size_t size);
NTSTATUS driver_readmsr(uint64_t cpureg);
NTSTATUS driver_writemsr(uint64_t cpureg, int64_t value);
uintptr_t driver_get_base_address(process_info* procinfo);
uintptr_t driver_get_physical_address(process_info* procinfo, uintptr_t virtual_address);

#endif