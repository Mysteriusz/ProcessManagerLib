#pragma once

// PROFILERS
#include "ProcessProfiler.h"
#include "CpuProfiler.h"
#include "GpuProfiler.h"
#include "Profiler.h"

// STRUCTS

// LIBS
#include <unordered_map>

using namespace ProfilingLib::Profilers;

ProcessProfiler Profiler::processProfiler;
CpuProfiler Profiler::cpuProfiler;
GpuProfiler Profiler::gpuProfiler;

std::unordered_map<DWORD, ProcessHolder> Profiler::processStates;

HANDLE* Profiler::AddNewProcess(DWORD pid) {
	ProcessHolder* state = new ProcessHolder();

    state->pHandle = (HANDLE*)OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    processStates[pid] = *state;

    return state->pHandle;
}
HANDLE* Profiler::GetProcessHandle(DWORD pid) {
    if (processStates.find(pid) == processStates.end()) {
        return AddNewProcess(pid);
    }

    return processStates[pid].pHandle;
}

ProcessHolder* Profiler::GetProcessHolder(DWORD pid) {
    return &processStates[pid];
}

FILETIME Profiler::AddTimes(FILETIME t1, FILETIME t2) {
    FILETIME totalTime;
    LARGE_INTEGER tl, tu, tr;

    tl.LowPart = t1.dwLowDateTime;
    tl.HighPart = t1.dwHighDateTime;

    tu.LowPart = t2.dwLowDateTime;
    tu.HighPart = t2.dwHighDateTime;

    tr.QuadPart = tl.QuadPart + tu.QuadPart;

    totalTime.dwLowDateTime = tr.LowPart;
    totalTime.dwHighDateTime = tr.HighPart;

    return totalTime;
}
FILETIME Profiler::SubtractTimes(FILETIME t1, FILETIME t2) {
    FILETIME totalTime;
    LARGE_INTEGER tl, tu, tr;

    tl.LowPart = t1.dwLowDateTime;
    tl.HighPart = t1.dwHighDateTime;

    tu.LowPart = t2.dwLowDateTime;
    tu.HighPart = t2.dwHighDateTime;

    tr.QuadPart = tl.QuadPart - tu.QuadPart;

    totalTime.dwLowDateTime = tr.LowPart;
    totalTime.dwHighDateTime = tr.HighPart;

    return totalTime;
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

std::string Profiler::GetFileDescription(const wchar_t* path) {
    DWORD len = 0;
    BYTE* buffer = nullptr;

    DWORD size = GetFileVersionInfoSize(path, NULL);
    if (size == 0) {
        return "N/A";
    }

    buffer = new BYTE[size];
    if (!GetFileVersionInfo(path, 0, size, buffer)) {
        delete[] buffer;
        return "N/A";
    }

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;

    UINT cbTranslate = 0;
    if (!VerQueryValue(buffer, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
        delete[] buffer;
        return "N/A";
    }

    LPVOID lpBuffer = nullptr;
    UINT lpLen;

    for (unsigned int i = 0; i < (cbTranslate / sizeof(LANGANDCODEPAGE)); i++) {
        wchar_t block[256];

        swprintf_s(block, L"\\StringFileInfo\\%04x%04x\\FileDescription", lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);

        if (!VerQueryValue(buffer, block, &lpBuffer, &lpLen)) {
            delete[] buffer;
            return "N/A";
        }
    }

    std::string desc = Profiler::WideStringToString((LPWSTR)lpBuffer);

    delete[] buffer;
    return desc;
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
