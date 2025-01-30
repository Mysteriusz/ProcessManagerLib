#pragma once

#include "ProcessInfo.h"
#include "ProcessProfiler.h"
#include "ProfilerHelpers.h"

#include "windows.h"
#include "Tlhelp32.h"

#include "processthreadsapi.h"
#include "winternl.h"
#include "ntstatus.h"
#include "winbase.h"

#include <filesystem>

using namespace ProfilingLib::Profilers;

std::string ProcessProfiler::GetProcessName(DWORD& pid) {
    wchar_t processName[MAX_PATH] = { 0 };
    PDWORD plen = new DWORD(MAX_PATH);

    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    if (!QueryFullProcessImageName(pHandle, NULL, processName, plen)) {
        if (GetLastError() == 31) {
            QueryFullProcessImageName(pHandle, PROCESS_NAME_NATIVE, processName, plen);
        }
        else {
            return std::to_string(GetLastError());
        }
    }

    return std::filesystem::path(processName).filename().string();
}
std::string ProcessProfiler::GetProcessImageName(DWORD& pid) {
    wchar_t processName[MAX_PATH] = { 0 };  
    PDWORD plen = new DWORD(MAX_PATH);

    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    if (!QueryFullProcessImageName(pHandle, NULL, processName, plen)) {
        if (GetLastError() == 31) {
            QueryFullProcessImageName(pHandle, PROCESS_NAME_NATIVE, processName, plen);
        }
        else {
            return "";
        }
    }

    return ConvertFromWideString(processName);
}
std::string ProcessProfiler::GetProcessUser(DWORD& pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    HANDLE hToken;
    OpenProcessToken(pHandle, TOKEN_QUERY, &hToken);
    
    DWORD hTokenSize = 0;

    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &hTokenSize)) {
        if (GetLastError() != 122) {
            return "";
        }
    }

    BYTE* buffer = new BYTE[hTokenSize];

    if (!GetTokenInformation(hToken, TokenUser, buffer, hTokenSize, &hTokenSize)) {
        if (GetLastError() != 122) {
            return "";
        }
    }

    TOKEN_USER* pUser = (TOKEN_USER*)buffer;
    PSID pSid = pUser->User.Sid;

    DWORD nameSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE sidName;

    LookupAccountSid(NULL, pSid, NULL, &nameSize, NULL, &domainSize, &sidName);

    wchar_t* name = new wchar_t[nameSize];
    wchar_t* domain = new wchar_t[domainSize];

    LookupAccountSid(NULL, pSid, name, &nameSize, domain, &domainSize, &sidName);

    std::wstring user = std::wstring(domain) + L"\\" + std::wstring(name);

    return ConvertFromWideString(user);
}
std::string ProcessProfiler::GetProcessPriority(DWORD& pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    switch (GetPriorityClass(pHandle)) {
        case 0x00000100:
            return "Read Time";
        case 0x00000080:
            return "High Priority";
        case 0x00008000:
            return "Above Normal";
        case 0x00000020:
            return "Normal";
        case 0x00004000:
            return "Below Normal";
        case 0x00000040:
            return "Idle";
        default:
            return "";
    }
}

std::vector<ProcessInfo> ProcessProfiler::GetAllProcesses() {
    std::vector<ProcessInfo> infos;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
        if (Process32First(snapshot, &pe32))
        {
            while (Process32Next(snapshot, &pe32))
            {
                ProcessInfo info;

                info.SetName(GetProcessName(pe32.th32ProcessID));
                info.SetUser(GetProcessUser(pe32.th32ProcessID));
                info.SetImageName(GetProcessImageName(pe32.th32ProcessID));
                info.SetPriority(GetProcessPriority(pe32.th32ProcessID));

                info.pid = pe32.th32ProcessID;

                infos.push_back(info);
            }
        }
        CloseHandle(snapshot);
    }
    return infos;
}
