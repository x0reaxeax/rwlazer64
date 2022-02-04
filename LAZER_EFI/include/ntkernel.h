#ifndef _LAZER64_NTKERNEL_EXTERNALS_H_
#define _LAZER64_NTKERNEL_EXTERNALS_H_

#include "rst_hooks.h"

#define OBJ_CASE_INSENSITIVE                0x00000040L
#define SECTION_MAP_READ                    0x0004

#define STATUS_INVALID_HANDLE               0xC0000008

typedef char                CCHAR;
typedef signed char         CHAR;
typedef unsigned char       UCHAR;

typedef unsigned short      WORD;
typedef unsigned int        DWORD;

typedef signed int          LONG;
typedef unsigned int        ULONG;

typedef unsigned long long  ULONG_PTR;
typedef unsigned long long  LAZER_UINT64;
typedef ULONG_PTR           SIZE_T;

typedef void *              PVOID;
typedef void *              HANDLE;

typedef LONG KPRIORITY;
typedef UCHAR KIRQL, *PKIRQL;
typedef ULONG_PTR KSPIN_LOCK, *PKSPIN_LOCK;
typedef ULONG KAFFINITY, *PKAFFINITY;
typedef CCHAR KPROCESSOR_MODE;
typedef DWORD ACCESS_MASK;

typedef enum _MODE {
  KernelMode,
  UserMode,
  MaximumMode
} MODE;

typedef struct _UNICODE_STRING {
  unsigned short Length;
  unsigned short MaximumLength;
  WCHAR         *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
}

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        long  HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        long  HighPart;
    } u;
    long long QuadPart;
} LARGE_INTEGER;

typedef LARGE_INTEGER PHYSICAL_ADDRESS;

typedef struct _KGDTENTRY {
    WORD LimitLow;
    WORD BaseLow;
    ULONG HighWord;
} KGDTENTRY, *PKGDTENTRY;

typedef struct _DISPATCHER_HEADER {
    union {
        struct {
            UCHAR Type;
            union {
                UCHAR Abandoned;
                UCHAR Absolute;
                UCHAR NpxIrql;
                UCHAR Signalling;
            };
            union {
                UCHAR Size;
                UCHAR Hand;
            };
            union {
                UCHAR Inserted;
                UCHAR DebugActive;
                UCHAR DpcActive;
            };
        };
        LONG Lock;
    };
    LONG SignalState;
    LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, *PDISPATCHER_HEADER;

typedef struct _KIDTENTRY {
    WORD Offset;
    WORD Selector;
    WORD Access;
    WORD ExtendedOffset;
} KIDTENTRY, *PKIDTENTRY;

typedef struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY* Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;

typedef struct _KEXECUTE_OPTIONS {
    ULONG ExecuteDisable: 1;
    ULONG ExecuteEnable: 1;
    ULONG DisableThunkEmulation: 1;
    ULONG Permanent: 1;
    ULONG ExecuteDispatchEnable: 1;
    ULONG ImageDispatchEnable: 1;
    ULONG Spare: 2;
} KEXECUTE_OPTIONS, *PKEXECUTE_OPTIONS;

typedef struct _KPROCESS {
    DISPATCHER_HEADER Header;
    LIST_ENTRY ProfileListHead;
    ULONG DirectoryTableBase;
    ULONG Unused0;
    KGDTENTRY LdtDescriptor;
    KIDTENTRY Int21Descriptor;
    WORD IopmOffset;
    UCHAR Iopl;
    UCHAR Unused;
    ULONG ActiveProcessors;
    ULONG KernelTime;
    ULONG UserTime;
    LIST_ENTRY ReadyListHead;
    SINGLE_LIST_ENTRY SwapListEntry;
    PVOID VdmTrapcHandler;
    LIST_ENTRY ThreadListHead;
    ULONG ProcessLock;
    ULONG Affinity;
    union {
         ULONG AutoAlignment: 1;
         ULONG DisableBoost: 1;
         ULONG DisableQuantum: 1;
         ULONG ReservedFlags: 29;
         LONG ProcessFlags;
    };
    CHAR BasePriority;
    CHAR QuantumReset;
    UCHAR State;
    UCHAR ThreadSeed;
    UCHAR PowerState;
    UCHAR IdealNode;
    UCHAR Visited;
    union {
         KEXECUTE_OPTIONS Flags;
         UCHAR ExecuteOptions;
    };
    ULONG StackCount;
    LIST_ENTRY ProcessListEntry;
    UINT64 CycleTime;
} KPROCESS, *PKPROCESS, *PRKPROCESS, *PEPROCESS;

#endif