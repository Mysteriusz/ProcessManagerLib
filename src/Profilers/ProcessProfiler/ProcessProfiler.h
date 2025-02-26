#pragma once
#define PROCESS_PROFILER_H

// PROFILERS
#include "Profiler.h"

// STRUCTS
#include "ProcessInfo.h"
#include "ProcessFlags.h"

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
		std::string GetProcessFileVersion(UINT& pid);
		std::string GetProcessArchitectureType(UINT& pid);
		std::string GetProcessIntegrityLevel(UINT& pid);
		std::string GetProcessCommandLine(UINT& pid);
		std::string GetProcessDescription(UINT& pid);
		
		UINT64 GetProcessPEB(UINT& pid);
		UINT64 GetProcessCycleCount(UINT& pid);
		UINT64 GetProcessAffinity(UINT& pid);

		UINT GetProcessPPID(UINT& pid);
		UINT GetProcessStatus(UINT& pid);
		UINT GetProcessPriority(UINT& pid);

		ProcessInfo GetProcessInfo(
			PROCESS_PIF_FLAGS pif,
			PROCESS_MIF_FLAGS mif,
			PROCESS_HIF_FLAGS hif,
			PROCESS_RIF_FLAGS rif,
			PROCESS_TIF_FLAGS tif,
			PROCESS_EIF_FLAGS eif,
			PROCESS_CIF_FLAGS cif,
			PROCESS_OIF_FLAGS oif,
			UINT& pid
		);
		ProcessTimesInfo GetProcessCurrentTimes(PROCESS_TIF_FLAGS tif, UINT& pid);
		ProcessMemoryInfo GetProcessCurrentMemoryInfo(PROCESS_EIF_FLAGS eif, UINT& pid);
		ProcessIOInfo GetProcessCurrentIOInfo(PROCESS_OIF_FLAGS oif, UINT& pid);
		ProcessCPUInfo GetProcessCurrentCPUInfo(PROCESS_CIF_FLAGS cif, UINT& pid);
		
		std::vector<ProcessModuleInfo> GetProcessAllModuleInfo(PROCESS_MIF_FLAGS mif, UINT& pid);
		std::vector<ProcessHandleInfo> GetProcessAllHandleInfo(PROCESS_HIF_FLAGS hif, UINT& pid);
		std::vector<ProcessThreadInfo> GetProcessAllThreadInfo(PROCESS_RIF_FLAGS rif, UINT& pid);
		std::vector<ProcessInfo> GetAllProcessInfo(
			PROCESS_PIF_FLAGS pif,
			PROCESS_MIF_FLAGS mif,
			PROCESS_HIF_FLAGS hif,
			PROCESS_RIF_FLAGS rif,
			PROCESS_TIF_FLAGS tif,
			PROCESS_EIF_FLAGS eif,
			PROCESS_CIF_FLAGS cif,
			PROCESS_OIF_FLAGS oif
		);
	};
}