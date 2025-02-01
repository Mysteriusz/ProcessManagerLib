#pragma once

// PROFILERS
#include "ProcessProfiler.h"

// STRUCTS
#include "ProcessInfo.h"

// LIBS
#include "windows.h"
#include "Tlhelp32.h"
#include "processthreadsapi.h"
#include "ntstatus.h"
#include "winbase.h"
#include "winver.h"
#include "Winternl.h"
#include <sstream>
#include <filesystem>
#include <memory>
#include <codecvt>

#pragma comment(lib, "Version.lib")

using namespace ProfilingLib::Profilers;

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
);

std::string ProcessProfiler::GetProcessName(UINT& pid) {
    wchar_t processName[MAX_PATH] = { 0 };
    PDWORD plen = new DWORD(MAX_PATH);

    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    if (!QueryFullProcessImageName(pHandle, NULL, processName, plen)) {
        if (GetLastError() == 31) {
            QueryFullProcessImageName(pHandle, PROCESS_NAME_NATIVE, processName, plen);
        }
        else {
            return "0 N/A";
        }
    }

    return std::filesystem::path(processName).filename().string();
}
std::string ProcessProfiler::GetProcessImageName(UINT& pid) {
    wchar_t processName[MAX_PATH] = { 0 };  
    PDWORD plen = new DWORD(MAX_PATH);

    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    if (!QueryFullProcessImageName(pHandle, NULL, processName, plen)) {
        if (GetLastError() == 31) {
            QueryFullProcessImageName(pHandle, PROCESS_NAME_NATIVE, processName, plen);
        }
        else {
            return "1 N/A";
        }
    }

    std::wstring str = processName;

    int len = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string multiStr(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, &multiStr[0], len, nullptr, nullptr);
    
    return multiStr;
}
std::string ProcessProfiler::GetProcessUser(UINT& pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    HANDLE hToken;
    OpenProcessToken(pHandle, TOKEN_QUERY, &hToken);
    
    DWORD hTokenSize = 0;

    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &hTokenSize)) {
        if (GetLastError() != 122) {
            CloseHandle(hToken);
            return "0 N/A";
        }
    }

    BYTE* buffer = new BYTE[hTokenSize];

    if (!GetTokenInformation(hToken, TokenUser, buffer, hTokenSize, &hTokenSize)) {
        if (GetLastError() != 122) {
            CloseHandle(hToken);
            return "1 N/A";
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

    std::wstring str = user;

    int len = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string multiStr(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, &multiStr[0], len, nullptr, nullptr);
    return multiStr;
}
std::string ProcessProfiler::GetProcessPriority(UINT& pid) {
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
            return "0 N/A";
    }
}
std::string ProcessProfiler::GetProcessFileVersion(UINT& pid) {
    std::string imageName = Profiler::processProfiler.GetProcessImageName(pid);
    LPSTR processPath = const_cast<LPSTR>(imageName.c_str());

    DWORD len = 0;
    BYTE* buffer = nullptr;

    DWORD size = GetFileVersionInfoSizeA(processPath, NULL);
    if (size == 0) {
        return "0 N/A";
    }
    buffer = new BYTE[size];
    if (!GetFileVersionInfoA(processPath, 0, size, buffer)) {
        delete[] buffer;
        return "1 N/A";
    }
    LPVOID lpBuffer;
    UINT lpLen;
    if (!VerQueryValueA(buffer, "", &lpBuffer, &lpLen)) {
        delete[] buffer;
        return "2 N/A";
    }

    VS_FIXEDFILEINFO* verInfo = (VS_FIXEDFILEINFO*)lpBuffer;

    std::string ver = std::to_string((verInfo->dwFileVersionMS >> 16) & 0xffff) + "."
        + std::to_string((verInfo->dwFileVersionMS >> 0) & 0xffff) + "."
        + std::to_string((verInfo->dwFileVersionLS >> 16) & 0xffff) + "."
        + std::to_string((verInfo->dwFileVersionLS >> 0) & 0xffff);

    delete[] buffer;
    return ver;
}
std::string ProcessProfiler::GetProcessArchitectureType(UINT& pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);
    BOOL isWow64 = FALSE;

    if (IsWow64Process(pHandle, &isWow64)) {
        if (isWow64)
            return "x86";
        else
            return "x64";
    }
    else
        return "ARM";
}
std::string ProcessProfiler::GetProcessIntegrityLevel(UINT& pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);
    
    HANDLE hToken;
    DWORD hTokenSize;

    OpenProcessToken(pHandle, TOKEN_QUERY, &hToken);

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &hTokenSize)) {
        if (GetLastError() != 122) {
            CloseHandle(hToken);
            return "0 N/A";
        }
    }
    
    TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)malloc(hTokenSize);

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, tml, hTokenSize, &hTokenSize)) {
        free(tml);
        CloseHandle(hToken);
        return "1 N/A";
    }

    DWORD intLevel = *GetSidSubAuthority(tml->Label.Sid, (DWORD)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1));

    switch (intLevel)
    {
        case SECURITY_MANDATORY_LOW_RID:
            return "Low Integrity";
        case SECURITY_MANDATORY_MEDIUM_RID:
            return "Medium Integrity";
        case SECURITY_MANDATORY_HIGH_RID:
            return "High Integrity";
        case SECURITY_MANDATORY_SYSTEM_RID:
            return "System Integrity";
        default:
            return "Unknown Integrity Level";
    }
}
std::string ProcessProfiler::GetProcessCommandLine(UINT& pid) {
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) return "0 N/A";

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) return "1 N/A";

    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS s = NtQueryInformationProcess(pHandle, 0, &pbi, sizeof(pbi), NULL);
    if (s != 0) return "2 N/A";

    PEB peb;
    if (!ReadProcessMemory(pHandle, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL))
        return "3 N/A" + std::to_string(GetLastError());

    RTL_USER_PROCESS_PARAMETERS params;
    if (!ReadProcessMemory(pHandle, peb.ProcessParameters, &params, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
        return "4 N/A " + std::to_string(GetLastError());
    }

    UNICODE_STRING str = params.CommandLine;
    WCHAR* buffer = new WCHAR[(str.Length / 2) + 1]();

    if (!ReadProcessMemory(pHandle, str.Buffer, buffer, str.Length, NULL)) {
        delete[] buffer;
        return "5 N/A";
    }

    std::wstring wstr(buffer);

    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string multiStr(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &multiStr[0], len, nullptr, nullptr);
    
    delete[] buffer;
    CloseHandle(pHandle);

    return multiStr;
}

UINT64 ProcessProfiler::GetProcessPEB(UINT& pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) return 0;

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) return 0;

    PROCESS_BASIC_INFORMATION pbi;

    NtQueryInformationProcess(pHandle, 0, &pbi, sizeof(pbi), NULL);

    return reinterpret_cast<UINT64>(pbi.PebBaseAddress);
}
UINT ProcessProfiler::GetProcessPPID(UINT& pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
        if (Process32First(snapshot, &pe32))
        {
            while (Process32Next(snapshot, &pe32))
            {
                if (pe32.th32ProcessID == pid)
                    return pe32.th32ParentProcessID;
            }

        }
        CloseHandle(snapshot);
    }
    return 0;
}

std::vector<FILETIME> ProcessProfiler::GetProcessCurrentTimes(UINT& pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);
    FILETIME creationTime, exitTime, kernelTime, userTime;
    std::vector<FILETIME> processTimes;
    
    GetProcessTimes(pHandle, &creationTime, &exitTime, &kernelTime, &userTime);
    
    processTimes.push_back(creationTime);
    processTimes.push_back(userTime);
    processTimes.push_back(kernelTime);
    processTimes.push_back(exitTime);

    FILETIME totalTime;

    ULARGE_INTEGER tu, tl, tr;
    tl.LowPart = userTime.dwLowDateTime;
    tl.HighPart = userTime.dwHighDateTime;

    tu.LowPart = kernelTime.dwLowDateTime;
    tu.HighPart = kernelTime.dwHighDateTime;

    tr.QuadPart = tl.QuadPart + tu.QuadPart;

    totalTime.dwLowDateTime = tr.LowPart;
    totalTime.dwHighDateTime = tr.HighPart;

    processTimes.push_back(totalTime);

    return processTimes;
}

ProcessInfo ProcessProfiler::GetProcessInfo(UINT& pid) {
    ProcessInfo info;
    
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");

    const std::string& name = GetProcessName(pid);
    const std::string& user = GetProcessUser(pid);
    const std::string& imageName = GetProcessImageName(pid);
    const std::string& priority = GetProcessPriority(pid);
    const std::string& fileVersion = GetProcessFileVersion(pid);
    const std::string& architectureType = GetProcessArchitectureType(pid);
    const std::string& integrityLevel = GetProcessIntegrityLevel(pid);
    const std::string& cmd = GetProcessCommandLine(pid);
    const std::vector<FILETIME> times = GetProcessCurrentTimes(pid);
    const UINT ppid = GetProcessPPID(pid);
    const UINT64 peb = GetProcessPEB(pid);

    strcpy_s(info.name, name.length() + 1, name.c_str());
    strcpy_s(info.user, user.length() + 1, user.c_str());
    strcpy_s(info.imageName, imageName.length() + 1, imageName.c_str());
    strcpy_s(info.priority, priority.length() + 1, priority.c_str());
    strcpy_s(info.fileVersion, fileVersion.length() + 1, fileVersion.c_str());
    strcpy_s(info.architectureType, architectureType.length() + 1, architectureType.c_str());
    strcpy_s(info.integrityLevel, integrityLevel.length() + 1, integrityLevel.c_str());
    strcpy_s(info.cmd, cmd.length() + 1, cmd.c_str());

    info.creationTime = times[0];
    info.userTime = times[1];
    info.kernelTime = times[2];
    info.exitTime = times[3];
    info.totalTime = times[4];
    
    info.ppid = ppid;
    info.pid = pid;
    info.peb = peb;

    return info;
}
std::vector<ProcessInfo> ProcessProfiler::GetAllProcessInfo() {
    std::vector<ProcessInfo> infos;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
        if (Process32First(snapshot, &pe32))
        {
            while (Process32Next(snapshot, &pe32))
            {
                ProcessInfo info = GetProcessInfo((UINT&)pe32.th32ProcessID);
                infos.push_back(info);
            }
        }
        CloseHandle(snapshot);
    }
    return infos;
}