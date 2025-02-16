#pragma once
#define GPU_PROFILER_H

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
	class GpuProfiler {
	public:
		std::string GetGpuName();
		std::string GetGpuVendor();
		std::string GetGpuDriverName();

		UINT64 GetGpuDriverVersion();
		UINT64 GetGpuVRamSize();
		UINT64 GetGpuVRamUsage();

		UINT GetGpuID();
		UINT GetGpuRevision();
	};
}