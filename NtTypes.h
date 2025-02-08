#pragma once

#include "ntstatus.h"
#include "winbase.h"
#include "winver.h"
#include "Winternl.h"

typedef struct _NTTYPES_RTL_PROCESS_MODULE_INFORMATION
{
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} NTTYPES_RTL_PROCESS_MODULE_INFORMATION, * NTTYPES_PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _NTTYPES_RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    _Field_size_(NumberOfModules) NTTYPES_RTL_PROCESS_MODULE_INFORMATION Modules[1];
} NTTYPES_RTL_PROCESS_MODULES, * NTTYPES_PRTL_PROCESS_MODULES;

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;         // The value of the handle.
    SIZE_T HandleCount;         // The number of references to the handle.
    SIZE_T PointerCount;        // The number of pointers to the handle.
    ACCESS_MASK GrantedAccess;  // The access rights granted to the handle.
    ULONG ObjectTypeIndex;      // The index of the object type.
    ULONG HandleAttributes;     // The attributes of the handle.
    ULONG Reserved;             // Reserved for future use.
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    _Field_size_(NumberOfHandles) PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef struct _NTTYPES_PROCESS_HANDLE_INFORMATION
{
    ULONG HandleCount;
    ULONG HandleCountHighWatermark;
} NTTYPES_PROCESS_HANDLE_INFORMATION, *NTTYPES_PPROCESS_HANDLE_INFORMATION;
typedef struct _NTTYPES_RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} NTTYPES_RTL_USER_PROCESS_PARAMETERS, *NTTYPES_PRTL_USER_PROCESS_PARAMETERS;
typedef struct _NTTYPES_PAGE_PRIORITY_INFORMATION
{
    ULONG PagePriority;
} NTTYPES_PAGE_PRIORITY_INFORMATION, *NTTYPES_PPAGE_PRIORITY_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION
{
    UNICODE_STRING Name; // The object name (when present) includes a NULL-terminator and all path separators "\" in the name.
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;
typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex; // since WINBLUE
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _NTTYPES_LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} NTTYPES_LDR_DATA_TABLE_ENTRY, * NTTYPES_PLDR_DATA_TABLE_ENTRY;

typedef enum _NTTYPES_IO_PRIORITY_HINT
{
    IoPriorityVeryLow = 0,
    IoPriorityLow,
    IoPriorityNormal,
    IoPriorityHigh,
    IoPriorityCritical,
    MaxIoPriorityTypes
} NTTYPES_IO_PRIORITY_HINT;


typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
);
typedef NTSTATUS(NTAPI* _LdrQueryProcessModuleInformation)(
    _In_opt_ NTTYPES_PRTL_PROCESS_MODULES ModuleInformation,
    _In_opt_ ULONG Size,
    _Out_ PULONG ReturnedSize
);
typedef NTSTATUS(NTAPI* _NtQueryObject)(
    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
);
