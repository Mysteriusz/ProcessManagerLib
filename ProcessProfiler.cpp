#pragma once

// PROFILERS
#include "ProcessProfiler.h"

// STRUCTS
#include "ProcessInfo.h"

// LIBS
#include "windows.h"
#include "processFlags.h"
#include "Tlhelp32.h"
#include "processthreadsapi.h"
#include "ntstatus.h"
#include "winbase.h"
#include "NtTypes.h"
#include "winver.h"
#include "Winternl.h"
#include <sstream>
#include <filesystem>
#include <iostream>
#include <memory>
#include <codecvt>

#pragma comment(lib, "Version.lib")

using namespace ProfilingLib::Profilers;

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

    std::wstring strW = processName;
    std::string str = Profiler::WideStringToString(strW);

    return str;
}
std::string ProcessProfiler::GetProcessUser(UINT& pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    HANDLE hToken;
    if (pid == 4) {
        return "SYSTEM";
    }

    if (!OpenProcessToken(pHandle, TOKEN_QUERY, &hToken)) {
        return "0 N/A";
    }

    DWORD hTokenSize = 0;

    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &hTokenSize)) {
        if (GetLastError() != 122) {
            CloseHandle(hToken);
            return "1 N/A";
        }
    }

    BYTE* buffer = new BYTE[hTokenSize];

    if (!GetTokenInformation(hToken, TokenUser, buffer, hTokenSize, &hTokenSize)) {
        if (GetLastError() != 122) {
            CloseHandle(hToken);
            return "2 N/A";
        }
    }

    TOKEN_USER* pUser = (TOKEN_USER*)buffer;
    PSID pSid = pUser->User.Sid;

    DWORD nameSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE sidName;

    if (!LookupAccountSid(NULL, pSid, NULL, &nameSize, NULL, &domainSize, &sidName)) {
        if (GetLastError() != 122) {
            CloseHandle(hToken);
            return "3 N/A";
        }
    }

    wchar_t* name = new wchar_t[nameSize];
    wchar_t* domain = new wchar_t[domainSize];

    if (!LookupAccountSid(NULL, pSid, name, &nameSize, domain, &domainSize, &sidName)) {
        if (GetLastError() != 122) {
            CloseHandle(hToken);
            return "4 N/A";
        }
    }

    std::wstring user = std::wstring(domain) + L"\\" + std::wstring(name);

    std::wstring strW = user;
    std::string str = Profiler::WideStringToString(strW);

    return str;
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
    std::string imgName = GetProcessImageName(pid);
    std::wstring imgNameW = Profiler::StringToWideString(imgName);

    DWORD len = 0;
    BYTE* buffer = nullptr;

    DWORD size = GetFileVersionInfoSize(imgNameW.c_str(), NULL);
    if (size == 0) {
        return "0 N/A";
    }
    buffer = new BYTE[size];
    if (!GetFileVersionInfo(imgNameW.c_str(), 0, size, buffer)) {
        delete[] buffer;
        return "1 N/A";
    }
    LPVOID lpBuffer;
    UINT lpLen;
    if (!VerQueryValue(buffer, L"", &lpBuffer, &lpLen)) {
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

    if (pid == 4) {
        return "System Integrity";
    }

    if (!OpenProcessToken(pHandle, TOKEN_QUERY, &hToken)) {
        return "0 N/A";
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &hTokenSize)) {
        if (GetLastError() != 122) {
            CloseHandle(hToken);
            return "1 N/A";
        }
    }
    
    TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)malloc(hTokenSize);

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, tml, hTokenSize, &hTokenSize)) {
        free(tml);
        CloseHandle(hToken);
        return "2 N/A";
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
        return "3 N/A";

    RTL_USER_PROCESS_PARAMETERS params;
    if (!ReadProcessMemory(pHandle, peb.ProcessParameters, &params, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
        return "4 N/A";
    }

    UNICODE_STRING cmdStr = params.CommandLine;
    WCHAR* buffer = new WCHAR[(cmdStr.Length / 2) + 1]();

    if (!ReadProcessMemory(pHandle, cmdStr.Buffer, buffer, cmdStr.Length, NULL)) {
        delete[] buffer;
        return "5 N/A";
    }

    std::wstring wstr(buffer);
    std::string str = Profiler::WideStringToString(wstr);

    delete[] buffer;
    CloseHandle(pHandle);

    return "str";
}
std::string ProcessProfiler::GetProcessDescription(UINT& pid) {
    std::string imgName = GetProcessImageName(pid);
    std::wstring imgNameW = Profiler::StringToWideString(imgName);

    DWORD len = 0;
    BYTE* buffer = nullptr;

    DWORD size = GetFileVersionInfoSize(imgNameW.c_str(), NULL);
    if (size == 0) {
        return "0 N/A";
    }
    
    buffer = new BYTE[size];
    if (!GetFileVersionInfo(imgNameW.c_str(), 0, size, buffer)) {
        delete[] buffer;
        return "1 N/A";
    }

    LPVOID lpBuffer;
    UINT lpLen;
    if (!VerQueryValue(buffer, L"\\StringFileInfo\\040904b0\\FileDescription", (LPVOID*)&lpBuffer, &lpLen)) {
        delete[] buffer;
        return "2 N/A";
    }

    std::wstring descW = (LPWSTR)lpBuffer;
    std::string desc = Profiler::WideStringToString(descW);

    delete[] buffer;
    return desc;
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

ProcessInfo ProcessProfiler::GetProcessInfo(UINT64 infoFlags, UINT& pid) {
    ProcessInfo info;
    
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");

    if (infoFlags == 0)
        goto SKIPALL;

    if (infoFlags & PIF_PROCESS_NAME) {
        const std::string& name = GetProcessName(pid);
        info.name = new char[256];
        strcpy_s(info.name, name.length() + 1, name.c_str());
    }
    if (infoFlags & PIF_PROCESS_IMAGE_NAME) {
        const std::string& imageName = GetProcessImageName(pid);
        info.imageName = new char[256];
        strcpy_s(info.imageName, imageName.length() + 1, imageName.c_str());
    }
    if (infoFlags & PIF_PROCESS_USER) {
        const std::string& user = GetProcessUser(pid);
        info.user = new char[256];
        strcpy_s(info.user, user.length() + 1, user.c_str());
    }
    if (infoFlags & PIF_PROCESS_PRIORITY) {
        const std::string& priority = GetProcessPriority(pid);
        info.priority = new char[256];
        strcpy_s(info.priority, priority.length() + 1, priority.c_str());
    }
    if (infoFlags & PIF_PROCESS_FILE_VERSION) {
        const std::string& fileVersion = GetProcessFileVersion(pid);
        info.fileVersion = new char[256];
        strcpy_s(info.fileVersion, fileVersion.length() + 1, fileVersion.c_str());
    }
    if (infoFlags & PIF_PROCESS_ARCHITECTURE_TYPE) {
        const std::string& architectureType = GetProcessArchitectureType(pid);
        info.architectureType = new char[64];
        strcpy_s(info.architectureType, architectureType.length() + 1, architectureType.c_str());
    }
    if (infoFlags & PIF_PROCESS_INTEGRITY_LEVEL) {
        const std::string& integrityLevel = GetProcessIntegrityLevel(pid);
        info.integrityLevel = new char[64];
        strcpy_s(info.integrityLevel, integrityLevel.length() + 1, integrityLevel.c_str());
    }
    if (infoFlags & PIF_PROCESS_COMMAND_LINE) {
        const std::string& cmd = GetProcessCommandLine(pid);
        info.cmd = new char[16];
        strcpy_s(info.cmd, cmd.length() + 1, cmd.c_str());
    }
    if (infoFlags & PIF_PROCESS_DESCRIPTION) {
        const std::string& description = GetProcessDescription(pid);
        info.description = new char[4096];
        strcpy_s(info.description, description.length() + 1, description.c_str());
    }
    if (infoFlags & PIF_PROCESS_TIMES) {
        const std::vector<FILETIME> times = GetProcessCurrentTimes(pid);
        info.creationTime = times[0];
        info.userTime = times[1];
        info.kernelTime = times[2];
        info.exitTime = times[3];
        info.totalTime = times[4];
    }
    if (infoFlags & PIF_PROCESS_PPID) {
        const UINT ppid = GetProcessPPID(pid);
        info.ppid = ppid;
    }
    if (infoFlags & PIF_PROCESS_PEB) {
        const UINT64 peb = GetProcessPEB(pid);
        info.peb = peb;
    }
    if (infoFlags & PIF_PROCESS_HANDLES_INFO) {
        const ProcessHandlesInfo phi = GetProcessHandlesInfo(pid);
        info.handlesInfo = phi;
    }
    
    SKIPALL:
    info.pid = pid;

    return info;
}
ProcessHandlesInfo ProcessProfiler::GetProcessHandlesInfo(UINT& pid) {
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    ProcessHandlesInfo info;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) return info;

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) return info;

    NTTYPES_PROCESS_HANDLE_INFORMATION ntphi;
    NTSTATUS status = NtQueryInformationProcess(pHandle, 20, &ntphi, sizeof(ntphi), NULL);
    if (status != 0) return info;

    info.count = ntphi.HandleCount;
    info.peakCount = ntphi.HandleCountHighWatermark;

    return info;
}

std::vector<ProcessInfo> ProcessProfiler::GetAllProcessInfo(UINT64 infoFlags) {
    std::vector<ProcessInfo> infos;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
        if (Process32First(snapshot, &pe32))
        {
            while (Process32Next(snapshot, &pe32))
            {
                ProcessInfo info = GetProcessInfo(infoFlags, (UINT&)pe32.th32ProcessID);
                infos.push_back(info);
            }
        }
        CloseHandle(snapshot);
    }
    return infos;
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
