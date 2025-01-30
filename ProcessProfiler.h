#pragma once
#define PROCESS_PROFILER_H

#include "ProcessInfo.h"
#include "Profiler.h"

#include "windows.h"
#include "string.h"
#include <vector>

namespace ProfilingLib::Profilers {
	class ProcessProfiler {
	public:
		std::string GetProcessName(DWORD& pid);
		std::string GetProcessImageName(DWORD& pid);
		std::string GetProcessUser(DWORD& pid);
		std::string GetProcessPriority(DWORD& pid);

		std::vector<ProcessInfo> GetAllProcesses();
	};
}