#pragma once
#define CPU_PROFILER_H

// PROFILERS
#include "Profiler.h"

// STRUCTS
#include "CpuInfo.h"

// LIBS
#include "CpuFlags.h"
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

		CpuInfo GetCpuInfo(CPU_CIF_FLAGS cif, CPU_SIF_FLAGS sif, CPU_MIF_FLAGS mif, CPU_TIF_FLAGS tif, CPU_HIF_FLAGS hif);
		CpuSystemInfo GetCpuSystemInfo(CPU_SIF_FLAGS sif);
		CpuModelInfo GetCpuModelInfo(CPU_MIF_FLAGS mif);
		CpuTimesInfo GetCpuTimesInfo(CPU_TIF_FLAGS tif);
		
		std::vector<CpuCacheInfo> GetCpuAllLevelsCacheInfo(CPU_HIF_FLAGS hif);
	};
};