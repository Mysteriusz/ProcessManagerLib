#pragma once
#define GPU_PROFILER_H

// PROFILERS
#include "Profiler.h"

// STRUCTS
#include "GpuInfo.h"

// LIBS
#include "GpuFlags.h"
#include "windows.h"
#include "string.h"
#include <vector>

namespace ProfilingLib::Profilers {
	class GpuProfiler {
	public:
		std::string GetGpuName();
		std::string GetGpuVendor();
		std::string GetGpuDriverName();
		std::string GetGpuDXVersion();

		UINT64 GetGpuDriverVersion();

		DOUBLE GetGpuVRamSize();
		DOUBLE GetGpuVRamUsage();

		UINT GetGpuID();
		UINT GetGpuRevision();
		
		GpuPhysicalInfo GetGpuPhysicalInfo();
		GpuModelInfo GetGpuModelInfo();
		GpuUtilizationInfo GetGpuUtilizationInfo();
		GpuResolutionInfo GetGpuMaxResolutionInfo();
		GpuResolutionInfo GetGpuMinResolutionInfo();
	};
}