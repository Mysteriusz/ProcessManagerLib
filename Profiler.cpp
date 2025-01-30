#pragma once

#include "CpuInfo.h"
#include "ProcessState.h"

#include "ProcessProfiler.h"
#include "CpuProfiler.h"
#include "Profiler.h"

#include <unordered_map>

using namespace ProfilingLib::Profilers;

ProcessProfiler Profiler::processProfiler;
CpuProfiler Profiler::cpuProfiler;
std::unordered_map<DWORD, ProcessState> Profiler::processStates;

HANDLE Profiler::AddNewProcess(DWORD pid) {
    ProcessState state;

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