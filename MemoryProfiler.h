#pragma once
#define MEM_PROFILER_H

namespace ProfilingLib::Profilers {
	class MemoryProfiler {
	public:
		void InitializeMemoryProfiler();
		void InitializeProcessMemoryProfiler(DWORD pid);

		DWORDLONG GetMemoryUsage();
		DWORDLONG GetProcessMemoryUsage(DWORD pid);
	private:
		MEMORYSTATUSEX memInfo;
	};
}