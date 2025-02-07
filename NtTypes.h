#pragma once

#include "ntstatus.h"
#include "winbase.h"
#include "winver.h"
#include "Winternl.h"

typedef struct _RTL_PROCESS_MODULE_INFORMATION
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
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    _Field_size_(NumberOfModules) RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

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
    _In_opt_ PRTL_PROCESS_MODULES ModuleInformation,
    _In_opt_ ULONG Size,
    _Out_ PULONG ReturnedSize
);
