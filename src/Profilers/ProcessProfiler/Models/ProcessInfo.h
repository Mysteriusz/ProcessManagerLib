#ifndef PROCESS_INFO_H
#define PROCESS_INFO_H

// LIBS
#include "windows.h"
#include <string>
#include "ntstatus.h"
#include "winbase.h"
#include "winver.h"
#include "Winternl.h"

struct ProcessHandleInfo {
    char* type = nullptr;
    char* name = nullptr;
    UINT64 handle = 0;
};
struct ProcessTimesInfo {
    FILETIME creationTime = { 0 };
    FILETIME kernelTime = { 0 };
    FILETIME exitTime = { 0 };
    FILETIME userTime = { 0 };
    FILETIME totalTime = { 0 };
};
struct ProcessMemoryInfo {
    UINT privateBytes = 0;
    UINT peakPrivateBytes = 0;
    UINT virtualBytes = 0;
    UINT peakVirtualBytes = 0;
    UINT pageFaults = 0;
    UINT workingBytes = 0;
    UINT peakWorkingBytes = 0;
    UINT64 pagePriority = 0;
};
struct ProcessIOInfo {
    UINT64 reads = 0;
    UINT64 readBytes = 0;
    UINT64 writes = 0;
    UINT64 writeBytes = 0;
    UINT64 other = 0;
    UINT64 otherBytes = 0;
    UINT ioPriority = 0;
};
struct ProcessCPUInfo {
    DOUBLE usage = 0;
    UINT64 cycles = 0;
    UINT64 affinity = 0;
};
struct ProcessModuleInfo {
    char* name = nullptr;
    char* path = nullptr;
    char* description = nullptr;
    UINT64 address = 0;
    UINT64 size = 0;
};
struct ProcessThreadInfo {
    UINT64 priority = 0;
    UINT64 tid = 0;
    UINT64 startAddress = 0;
    UINT64 cyclesDelta = 0;
};
struct ProcessInfo {
    char* name = nullptr;
    char* parentProcessName = nullptr;
    char* user = nullptr;
    char* imageName = nullptr;
    char* fileVersion = nullptr;
    char* integrityLevel = nullptr;
    char* architectureType = nullptr;
    char* cmd = nullptr;
    char* description = nullptr;

    UINT64 peb = 0;
    UINT pid = 0;
    UINT ppid = 0;
    UINT priority = 0;

    ProcessTimesInfo timesInfo;
    ProcessMemoryInfo memoryInfo;
    ProcessIOInfo ioInfo;
    ProcessCPUInfo cpuInfo;

    UINT moduleCount = 0;
    ProcessModuleInfo* modules = nullptr;

    UINT handleCount = 0;
    UINT handlePeakCount = 0;
    UINT gdiCount = 0;
    UINT userCount = 0;
    ProcessHandleInfo* handles = nullptr;

    UINT threadCount = 0;
    ProcessThreadInfo* threads = nullptr;
};

#endif 