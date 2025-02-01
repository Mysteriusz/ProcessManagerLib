#include "ProcessInfo.h"
#include "CpuProfiler.h"
#include "MemoryProfiler.h"
#include "CpuInfo.h"
#include "ProcessState.h"
#include "pdh.h"
#include "iostream"
#include "thread"

#include "windows.h"
#include "psapi.h"

using namespace ProfilingLib::Profilers;

DWORDLONG MemoryProfiler::GetTotalPhysicalMemory(MEMORYSTATUSEX memInfo) {
	return memInfo.ullTotalPhys;
}
DWORDLONG MemoryProfiler::GetTotalVirualMemory(MEMORYSTATUSEX memInfo) {
	return memInfo.ullTotalPageFile;
}

DWORDLONG MemoryProfiler::GetPhysicalMemoryUsage(MEMORYSTATUSEX memInfo) {
	return memInfo.ullTotalPhys - memInfo.ullAvailPhys;
}
DWORDLONG MemoryProfiler::GetVritualMemoryUsage(MEMORYSTATUSEX memInfo) {
	return memInfo.ullTotalPageFile - memInfo.ullAvailPageFile;
}

DWORDLONG MemoryProfiler::GetProcessPhysicalMemoryUsage(DWORD pid) {
	GetProcessMemoryInfo(&Profiler::processStates[pid].pHandle, (PROCESS_MEMORY_COUNTERS*)&Profiler::processStates[pid].memInfo.pmc, sizeof(Profiler::processStates[pid].memInfo.pmc));

	return Profiler::processStates[pid].memInfo.pmc.WorkingSetSize;
}