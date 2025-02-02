#pragma once

#include "ntstatus.h"
#include "winbase.h"
#include "winver.h"
#include "Winternl.h"

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
);

typedef struct _NTTYPES_PROCESS_HANDLE_INFORMATION
{
    ULONG HandleCount;
    ULONG HandleCountHighWatermark;
} NTTYPES_PROCESS_HANDLE_INFORMATION, *NTTYPES_PPROCESS_HANDLE_INFORMATION;