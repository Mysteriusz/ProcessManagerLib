#ifndef P_CPU_INFO_H
#define P_CPU_INFO_H

// LIBS
#include "Windows.h"

struct ProcessCpuInfo {
    ULARGE_INTEGER lastCPU;
    ULARGE_INTEGER lastUserCPU;
    ULARGE_INTEGER lastSysCPU;

    int numProcessors;

    double usagePercent;
};

#endif 