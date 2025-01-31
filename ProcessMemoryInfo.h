#ifndef P_MEM_INFO_H
#define P_MEM_INFO_H

#include "Windows.h"
#include "psapi.h"

struct ProcessMemoryInfo {
    PROCESS_MEMORY_COUNTERS_EX pmc;
};

#endif 