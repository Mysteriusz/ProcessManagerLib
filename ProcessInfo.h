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

    FILETIME creationTime = {0};
    FILETIME kernelTime = {0};
    FILETIME exitTime = {0};
    FILETIME userTime = {0};
    FILETIME totalTime = {0};

    ProcessHandlesInfo handlesInfo;
};

#endif 