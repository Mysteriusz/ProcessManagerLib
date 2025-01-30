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
