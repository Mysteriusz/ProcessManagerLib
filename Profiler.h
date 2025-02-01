#pragma once

// STRUCTS
#include "ProcessHolder.h"
#include "CpuInfo.h"
#include "ProcessInfo.h"

// LIBS
#include <unordered_map>
#include "windows.h"
#include "string.h"

namespace ProfilingLib::Profilers {
	class ProcessProfiler;
	class CpuProfiler;
	class Profiler {
	public:
		static HANDLE AddNewProcess(DWORD pid);
		static HANDLE GetProcessHandle(DWORD pid);

		static std::unordered_map<DWORD, ProcessHolder> processStates;
		static ProcessProfiler processProfiler;
		static CpuProfiler cpuProfiler;
	};
}