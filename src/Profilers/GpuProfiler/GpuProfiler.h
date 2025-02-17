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
		
		GpuInfo GetGpuInfo(GPU_GIF_FLAGS gif, GPU_MIF_FLAGS mif, GPU_UIF_FLAGS uif, GPU_PIF_FLAGS pif, GPU_RIF_FLAGS rif);
		GpuPhysicalInfo GetGpuPhysicalInfo(GPU_PIF_FLAGS pif);
		GpuModelInfo GetGpuModelInfo(GPU_MIF_FLAGS mif);
		GpuUtilizationInfo GetGpuUtilizationInfo(GPU_UIF_FLAGS uif);
		GpuResolutionInfo GetGpuMaxResolutionInfo(GPU_RIF_FLAGS rif);
		GpuResolutionInfo GetGpuMinResolutionInfo(GPU_RIF_FLAGS rif);
	};
}