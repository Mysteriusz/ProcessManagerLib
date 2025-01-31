#ifndef PROCESS_STATE_H
#define PROCESS_STATE_H

#include "ProcessCpuInfo.h"
#include "ProcessMemoryInfo.h"

struct ProcessState {
    HANDLE pHandle;

    ProcessCpuInfo cpuInfo;
    ProcessMemoryInfo memInfo;
};

#endif