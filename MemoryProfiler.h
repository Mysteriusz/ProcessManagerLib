#pragma once
#define MEM_PROFILER_H

#include "ProcessInfo.h"
#include "MemoryInfo.h"
#include "CpuInfo.h"

#include "Profiler.h"

#include "windows.h"
#include "string.h"
#include "TCHAR.h"
#include "pdh.h"

#pragma comment(lib, "Pdh.lib")

namespace ProfilingLib::Profilers {
	class MemoryProfiler {
	};
}