#pragma once

#include <windows.h>

typedef struct _CPUNT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
} CPUNT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, * CPUNT_PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _CPUNT_SYSTEM_PROCESSOR_INFORMATION
{
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    USHORT MaximumProcessors;
    ULONG ProcessorFeatureBits;
} CPUNT_SYSTEM_PROCESSOR_INFORMATION, * CPUNT_PSYSTEM_PROCESSOR_INFORMATION;

typedef BOOL(WINAPI* LPFN_GLPI)(
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION,
    PDWORD);