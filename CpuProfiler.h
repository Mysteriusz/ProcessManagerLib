#pragma once
#define CPU_PROFILER_H

#include "ProcessInfo.h"
#include "CpuInfo.h"
#include "ProcessState.h"

#include "Profiler.h"

#include "windows.h"
#include "string.h"
#include "TCHAR.h"
#include "pdh.h"

#pragma comment(lib, "Pdh.lib")

namespace ProfilingLib::Profilers {
	class CpuProfiler {
	public:
		void InitializeCpuProfiler();
		void InitializeProcessCpuProfiler(DWORD pid);

		double GetCpuUsage();
		double GetProcessCpuUsage(DWORD pid);

		CpuInfo GetCpuInfo();
		ProcessCpuInfo GetProcessCpuInfo(DWORD pid);
	private:
		PDH_HQUERY query = nullptr;
		PDH_HCOUNTER counter = nullptr;
	};
}