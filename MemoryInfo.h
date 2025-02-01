#ifndef MEM_INFO_H
#define MEM_INFO_H

#include "Windows.h"

struct MemoryInfo {
    DWORDLONG* sysTotalPhysMem;
    DWORDLONG* sysAvailPhysMem; 
    DWORDLONG* sysUsedPhysMem;

    DWORDLONG* sysTotalVirtMem;
    DWORDLONG* sysAvailVirtMem;
    DWORDLONG* sysUsedVirtMem;

    DWORDLONG* sysTotalPageFile;
    DWORDLONG* sysAvailPageFile;
    DWORDLONG* sysUsedPageFile;
    
    double* sysMemoryLoad;
};

#endif 