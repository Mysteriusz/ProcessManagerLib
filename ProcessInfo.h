#ifndef PROCESS_INFO_H
#define PROCESS_INFO_H

// LIBS
#include "windows.h"
#include <string>
#include "ntstatus.h"
#include "winbase.h"
#include "winver.h"
#include "Winternl.h"

struct ProcessHandlesInfo {
    UINT count = 0;
    UINT peakCount = 0;
    UINT gdiCount = 0;
    UINT userCount = 0;
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
struct ProcessInfo {
    char* name = strdup("N/A");
    char* parentProcessName = strdup("N/A");
    char* user = strdup("N/A");
    char* imageName = strdup("N/A");
    char* priority = strdup("N/A");
    char* fileVersion = strdup("N/A");
    char* integrityLevel = strdup("N/A");
    char* architectureType = strdup("N/A");
    char* cmd = strdup("N/A");
    char* description = strdup("N/A");

    UINT pid = 0;
    UINT ppid = 0;
    UINT64 peb = 0;
    UINT64 cycles = 0;

    ProcessTimesInfo timesInfo;
    ProcessHandlesInfo handlesInfo;
    ProcessMemoryInfo memoryInfo;
    ProcessIOInfo ioInfo;
};

#endif 