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
		std::string GetProcessParentName(UINT& pid);
		std::string GetProcessImageName(UINT& pid);
		std::string GetProcessUser(UINT& pid);
		std::string GetProcessPriority(UINT& pid);
		std::string GetProcessFileVersion(UINT& pid);
		std::string GetProcessArchitectureType(UINT& pid);
		std::string GetProcessIntegrityLevel(UINT& pid);
		std::string GetProcessCommandLine(UINT& pid);
		std::string GetProcessDescription(UINT& pid);
		
		UINT64 GetProcessPEB(UINT& pid);
		UINT64 GetProcessCycleCount(UINT& pid);
		UINT GetProcessPPID(UINT& pid);

		ProcessHandlesInfo GetProcessHandlesInfo(UINT& pid);
		ProcessTimesInfo GetProcessCurrentTimes(UINT& pid);
		ProcessMemoryInfo GetProcessMemoryCurrentInfo(UINT& pid);

		ProcessInfo GetProcessInfo(UINT64 infoFlags, UINT& pid);
		std::vector<ProcessInfo> GetAllProcessInfo(UINT64 infoFlags);
	};
}