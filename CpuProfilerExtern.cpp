#include "ProcessProfiler.h"
#include "CpuProfiler.h"
#include "string.h"
#include "psapi.h"

using namespace ProfilingLib::Profilers;

extern "C" _declspec(dllexport) void InitializeCpuProfiler() {
	Profiler::cpuProfiler.InitializeCpuProfiler();
}
extern "C" _declspec(dllexport) void InitializeProcessCpuProfiler(DWORD pid) {
	Profiler::cpuProfiler.InitializeProcessCpuProfiler(pid);
}

extern "C" _declspec(dllexport) const double* GetCpuUsage() {
    double res = Profiler::cpuProfiler.GetCpuUsage();
    static thread_local double staticRes;

    staticRes = res;

    return &staticRes;
}

extern "C" _declspec(dllexport) const double* GetProcessCpuUsage(DWORD pid) {
    double res = Profiler::cpuProfiler.GetProcessCpuUsage(pid);
    static thread_local double staticRes;

    staticRes = res;

    return &staticRes;
}

extern "C" _declspec(dllexport) const CpuInfo* GetCpuInfo(DWORD pid) {
    CpuInfo res = Profiler::cpuProfiler.GetCpuInfo();
    static thread_local CpuInfo staticRes; staticRes = res;

    return &staticRes;
}
extern "C" _declspec(dllexport) const ProcessCpuInfo* GetProcessCpuInfo(DWORD pid) {
    ProcessCpuInfo res = Profiler::cpuProfiler.GetProcessCpuInfo(pid);
    static thread_local ProcessCpuInfo staticRes; staticRes = res;

    return &staticRes;
}

