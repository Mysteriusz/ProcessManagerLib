#pragma once
#define CPU_PROFILER_H

// PROFILERS
#include "Profiler.h"

// STRUCTS
#include "ProcessInfo.h"
#include "CpuInfo.h"

// LIBS
#include "windows.h"
#include "string.h"
#include "TCHAR.h"
#include "pdh.h"

#pragma comment(lib, "Pdh.lib")

namespace ProfilingLib::Profilers {
	class CpuProfiler {
	public:
		void InitializeCpuProfiler();

		double GetCpuUsage();

		CpuInfo GetCpuInfo();
	private:
		PDH_HQUERY query = nullptr;
		PDH_HCOUNTER counter = nullptr;
	};
}