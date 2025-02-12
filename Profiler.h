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
		static HANDLE* AddNewProcess(DWORD pid);
		static HANDLE* GetProcessHandle(DWORD pid);

		static ProcessHolder* GetProcessHolder(DWORD pid);

		static BOOL EnableDebugPrivilages();

		static std::string WideStringToString(const wchar_t* str);
		static std::wstring StringToWideString(const char* str);

		static std::string GetFileDescription(const wchar_t* path);

		static std::unordered_map<DWORD, ProcessHolder> processStates;
		static ProcessProfiler processProfiler;
	};
}