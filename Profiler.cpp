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