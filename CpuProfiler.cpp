#include "ProcessCpuInfo.h"
#include "ProcessInfo.h"
#include "CpuInfo.h"

#include "CpuProfiler.h"

#include "windows.h"

#pragma comment(lib, "Pdh.lib")

using namespace ProfilingLib::Profilers;

void CpuProfiler::InitializeCpuProfiler() {
    
    // --------------------- INITIALIZE CPU USAGE COUNTER ---------------------
    PdhOpenQuery(NULL, NULL, &query);
    PdhAddEnglishCounter(query, L"\\Processor Information(_Total)\\% Processor Utility", NULL, &counter);
    PdhCollectQueryData(query);
}

double CpuProfiler::GetCpuUsage() {
    PDH_FMT_COUNTERVALUE counterVal;
    PdhCollectQueryData(query);
    PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, NULL, &counterVal);

    return counterVal.doubleValue;
}

CpuInfo CpuProfiler::GetCpuInfo() {
    CpuInfo ci;

    InitializeCpuProfiler();
    ci.cpuSysUsage = GetCpuUsage();

    return ci;
}
