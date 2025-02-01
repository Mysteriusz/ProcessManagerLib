#pragma once
#define PROCESS_PROFILER_H

// PROFILERS
#include "Profiler.h"

// STRUCTS
#include "ProcessInfo.h"

// LIBS
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
		std::string GetProcessFileVersion(DWORD& pid);
		std::string GetProcessArchitectureType(DWORD& pid);
		std::string GetProcessIntegrityLevel(DWORD& pid);

		DWORD GetProcessPPID(DWORD& pid);

		std::vector<FILETIME> GetProcessCurrentTimes(DWORD& pid);
		
		ProcessInfo GetProcessInfo(DWORD& pid);
		std::vector<ProcessInfo> GetAllProcessInfo();
	};
}