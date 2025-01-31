#include "ProcessInfo.h"
#include "ProcessState.h"
#include "MemoryProfiler.h"
#include "Profiler.h"

#include "windows.h"
#include "psapi.h"

using namespace ProfilingLib::Profilers;

void MemoryProfiler::InitializeMemoryProfiler() {
	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
}
void MemoryProfiler::InitializeProcessMemoryProfiler(DWORD pid) {

}

DWORDLONG MemoryProfiler::GetMemoryUsage() {
	GlobalMemoryStatusEx(&memInfo);
		
	return memInfo.ullTotalPhys;
}
DWORDLONG MemoryProfiler::GetProcessMemoryUsage(DWORD pid) {
	return 0;
}