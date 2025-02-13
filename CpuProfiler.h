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

		UINT GetCpuLevel1CacheSize();
		UINT GetCpuLevel2CacheSize();
		UINT GetCpuLevel3CacheSize();

		DOUBLE GetCpuUsage();

		CpuDeviceInfo GetCpuDeviceInfo();
		CpuTimesInfo GetCpuTimes();
	};
};