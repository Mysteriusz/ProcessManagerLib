#include "ProcessInfo.h"
#include "CpuProfiler.h"
#include "CpuInfo.h"
#include "ProcessState.h"
#include "pdh.h"
#include "iostream"
#include "thread"

#include "windows.h"

#pragma comment(lib, "Pdh.lib")

using namespace ProfilingLib::Profilers;

void CpuProfiler::InitializeCpuProfiler() {
    
    // --------------------- INITIALIZE CPU USAGE COUNTER ---------------------
    PdhOpenQuery(NULL, NULL, &query);
    PdhAddEnglishCounter(query, L"\\Processor Information(_Total)\\% Processor Utility", NULL, &counter);
    PdhCollectQueryData(query);
}
void CpuProfiler::InitializeProcessCpuProfiler(DWORD pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    SYSTEM_INFO sysInfo;
    FILETIME ftime, fsys, fuser;

    GetSystemInfo(&sysInfo);
    Profiler::processStates[pid].cpuInfo.numProcessors = sysInfo.dwNumberOfProcessors;

    GetSystemTimeAsFileTime(&ftime);
    memcpy(&Profiler::processStates[pid].cpuInfo.lastCPU, &ftime, sizeof(FILETIME));

    GetProcessTimes(pHandle, &ftime, &ftime, &fsys, &fuser);
    memcpy(&Profiler::processStates[pid].cpuInfo.lastSysCPU, &fsys, sizeof(FILETIME));
    memcpy(&Profiler::processStates[pid].cpuInfo.lastUserCPU, &fuser, sizeof(FILETIME));
}

double CpuProfiler::GetCpuUsage() {
    PDH_FMT_COUNTERVALUE counterVal;
    PdhCollectQueryData(query);
    PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, NULL, &counterVal);

    return counterVal.doubleValue;
}
double CpuProfiler::GetProcessCpuUsage(DWORD pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    FILETIME ftime, fsys, fuser;
    ULARGE_INTEGER now, sys, user;
    double percent;

    GetSystemTimeAsFileTime(&ftime);
    memcpy(&now, &ftime, sizeof(FILETIME));

    GetProcessTimes(pHandle, &ftime, &ftime, &fsys, &fuser);
    memcpy(&sys, &fsys, sizeof(FILETIME));
    memcpy(&user, &fuser, sizeof(FILETIME));
    percent = (sys.QuadPart - Profiler::processStates[pid].cpuInfo.lastSysCPU.QuadPart) +
        (user.QuadPart - Profiler::processStates[pid].cpuInfo.lastUserCPU.QuadPart);

    percent /= (now.QuadPart - Profiler::processStates[pid].cpuInfo.lastCPU.QuadPart);
    percent /= Profiler::processStates[pid].cpuInfo.numProcessors;
    
    Profiler::processStates[pid].cpuInfo.lastCPU = now;
    Profiler::processStates[pid].cpuInfo.lastUserCPU = user;
    Profiler::processStates[pid].cpuInfo.lastSysCPU = sys;

    return percent * 100;
}

CpuInfo CpuProfiler::GetCpuInfo() {
    CpuInfo ci;

    InitializeCpuProfiler();
    ci.cpuSysUsage = GetCpuUsage();

    return ci;
}
ProcessCpuInfo CpuProfiler::GetProcessCpuInfo(DWORD pid) {
    ProcessCpuInfo pci;
    
    InitializeProcessCpuProfiler(pid);
    pci.usagePercent = GetProcessCpuUsage(pid);

    return pci;
}
