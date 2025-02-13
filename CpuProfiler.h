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
		DOUBLE GetCpuUsage();
		CpuTimesInfo GetCpuTimes();
	};
};