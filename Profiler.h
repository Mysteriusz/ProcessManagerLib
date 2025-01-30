#pragma once

#include "windows.h"
#include "string.h"

#include "ProcessProfiler.h"
#include "ProcessState.h"

#include <unordered_map>

#include <vector>

namespace ProfilingLib::Profilers {
	class ProcessProfiler;
	class CpuProfiler;
}

namespace ProfilingLib::Profilers {
	class Profiler {
	public:
		static HANDLE AddNewProcess(DWORD pid);
		static HANDLE GetProcessHandle(DWORD pid);

		static std::unordered_map<DWORD, ProcessState> processStates;
		static ProcessProfiler processProfiler;
		static CpuProfiler cpuProfiler;
	};
}