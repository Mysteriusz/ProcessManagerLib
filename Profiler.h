#pragma once

// STRUCTS
#include "ProcessHolder.h"
#include "ProcessInfo.h"

// LIBS
#include <unordered_map>
#include "windows.h"
#include "string.h"

namespace ProfilingLib::Profilers {
	class ProcessProfiler;
	class Profiler {
	public:
		static HANDLE AddNewProcess(DWORD pid);
		static HANDLE GetProcessHandle(DWORD pid);

		static std::string WideStringToString(std::wstring& str);
		static std::wstring StringToWideString(std::string& str);

		static std::unordered_map<DWORD, ProcessHolder> processStates;
		static ProcessProfiler processProfiler;
	};
}