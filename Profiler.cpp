#pragma once

// PROFILERS
#include "ProcessProfiler.h"
#include "Profiler.h"

// STRUCTS

// LIBS
#include <unordered_map>

using namespace ProfilingLib::Profilers;

ProcessProfiler Profiler::processProfiler;
std::unordered_map<DWORD, ProcessHolder> Profiler::processStates;

HANDLE Profiler::AddNewProcess(DWORD pid) {
	ProcessHolder state;

    state.pHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    processStates[pid] = state;

    return processStates[pid].pHandle;
}
HANDLE Profiler::GetProcessHandle(DWORD pid) {
    if (processStates.find(pid) == processStates.end()) {
        return AddNewProcess(pid);
    }

    return processStates[pid].pHandle;
}

std::string Profiler::WideStringToString(std::wstring& str) {
    int mlen = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string multiStr(mlen, 0);
    WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, &multiStr[0], mlen, nullptr, nullptr);

    return multiStr;
}
std::wstring Profiler::StringToWideString(std::string& str) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring widestr(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &widestr[0], wlen);

    return widestr;
}