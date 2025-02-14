#pragma once
#define CPU_PROFILER_H

// PROFILERS
#include "Profiler.h"

// STRUCTS
#include "CpuInfo.h"

// LIBS
#include "windows.h"
#include "string.h"
#include <vector>

namespace ProfilingLib::Profilers {
	class CpuProfiler {
	public:
		std::string GetCpuName();
		std::string GetCpuVendor();
		std::string GetCpuArchitecture();

		UINT GetCpuModel();
		UINT GetCpuFamily();
		UINT GetCpuStepping();

		DOUBLE GetCpuUsage();
		DOUBLE GetCpuBaseFrequency();
		DOUBLE GetCpuMaxFrequency();

		UINT GetCpuThreadCount();
		UINT GetCpuHandleCount();

		BOOL IsCpuVirtualization();
		BOOL IsCpuHyperThreading();

		std::vector<CpuCacheInfo> GetCpuAllLevelsCacheInfo();

		CpuSystemInfo GetCpuSystemInfo();
		CpuModelInfo GetCpuModelInfo();
		CpuTimesInfo GetCpuTimesInfo();
	};
};