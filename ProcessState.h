#ifndef PROCESS_STATE_H
#define PROCESS_STATE_H

#include "windows.h"
#include <string>
#include <ctime>

struct ProcessState {
    HANDLE pHandle;

    ULARGE_INTEGER lastCPU;
    ULARGE_INTEGER lastUserCPU;
    ULARGE_INTEGER lastSysCPU;

    int numProcessors;
    double smoothedCpuUsage;
};

#endif