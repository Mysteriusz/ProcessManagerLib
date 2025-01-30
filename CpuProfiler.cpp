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
    Profiler::processStates[pid].numProcessors = sysInfo.dwNumberOfProcessors;

    GetSystemTimeAsFileTime(&ftime);
    memcpy(&Profiler::processStates[pid].lastCPU, &ftime, sizeof(FILETIME));

    GetProcessTimes(pHandle, &ftime, &ftime, &fsys, &fuser);
    memcpy(&Profiler::processStates[pid].lastSysCPU, &fsys, sizeof(FILETIME));
    memcpy(&Profiler::processStates[pid].lastUserCPU, &fuser, sizeof(FILETIME));
}

double CpuProfiler::GetCpuUsage() {
    PDH_FMT_COUNTERVALUE counterVal;
    PdhCollectQueryData(query);
    PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, NULL, &counterVal);

    return counterVal.doubleValue;
}
double CpuProfiler::GetProcessCpuUsage(DWORD pid) {
    FILETIME ftime, fsys, fuser;
    ULARGE_INTEGER now, sys, user;
    double percent;

    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    GetSystemTimeAsFileTime(&ftime);
    memcpy(&now, &ftime, sizeof(FILETIME));

    GetProcessTimes(pHandle, &ftime, &ftime, &fsys, &fuser);
    memcpy(&sys, &fsys, sizeof(FILETIME));
    memcpy(&user, &fuser, sizeof(FILETIME));
    percent = (sys.QuadPart - Profiler::processStates[pid].lastSysCPU.QuadPart) +
        (user.QuadPart - Profiler::processStates[pid].lastUserCPU.QuadPart);

    percent /= (now.QuadPart - Profiler::processStates[pid].lastCPU.QuadPart);
    percent /= Profiler::processStates[pid].numProcessors;
    
    Profiler::processStates[pid].lastCPU = now;
    Profiler::processStates[pid].lastUserCPU = user;
    Profiler::processStates[pid].lastSysCPU = sys;

    return percent * 100;
}