// PROFILERS
#include "ProcessProfiler.h"

// STRUCTS

// LIBS
#include "psapi.h"
#include "string.h"

using namespace ProfilingLib::Profilers;

extern "C" __declspec(dllexport) void EnableDebugPrivilages() {
	Profiler::EnableDebugPrivilages();
}