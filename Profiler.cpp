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

std::string Profiler::WideStringToString(const wchar_t* str) {
    int mlen = WideCharToMultiByte(CP_UTF8, 0, str, -1, nullptr, 0, nullptr, nullptr);
    std::string multiStr(mlen, 0);
    WideCharToMultiByte(CP_UTF8, 0, str, -1, &multiStr[0], mlen, nullptr, nullptr);

    return multiStr;
}
std::wstring Profiler::StringToWideString(const char* str) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
    std::wstring widestr(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, str, -1, &widestr[0], wlen);

    return widestr;
}

BOOL Profiler::EnableDebugPrivilages() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    // Open current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    // Get LUID for SeDebugPrivilege
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    // Set up privilege adjustment
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Adjust token privileges
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}
