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
		std::string GetProcessName(UINT& pid);
		std::string GetProcessImageName(UINT& pid);
		std::string GetProcessUser(UINT& pid);
		std::string GetProcessPriority(UINT& pid);
		std::string GetProcessFileVersion(UINT& pid);
		std::string GetProcessArchitectureType(UINT& pid);
		std::string GetProcessIntegrityLevel(UINT& pid);
		std::string GetProcessCommandLine(UINT& pid);

		UINT64 GetProcessPEB(UINT& pid);
		UINT GetProcessPPID(UINT& pid);

		std::vector<FILETIME> GetProcessCurrentTimes(UINT& pid);
		
		ProcessInfo GetProcessInfo(UINT& pid);
		std::vector<ProcessInfo> GetAllProcessInfo();
	};
}