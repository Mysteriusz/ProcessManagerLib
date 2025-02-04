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
#include "psapi.h"
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
            return "N/A";
        }
    }

    return std::filesystem::path(processName).filename().string();
}
std::string ProcessProfiler::GetProcessParentName(UINT& pid) {
    UINT pPid = GetProcessPPID(pid);
    return GetProcessName(pPid);
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
            return "N/A";
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
        return "N/A";
    }

    DWORD hTokenSize = 0;

    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &hTokenSize)) {
        if (GetLastError() != 122) {
            CloseHandle(hToken);
            return "N/A";
        }
    }

    BYTE* buffer = new BYTE[hTokenSize];

    if (!GetTokenInformation(hToken, TokenUser, buffer, hTokenSize, &hTokenSize)) {
        if (GetLastError() != 122) {
            CloseHandle(hToken);
            delete[] buffer;
            return "N/A";
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
            delete[] buffer;
            return "N/A";
        }
    }

    wchar_t* name = new wchar_t[nameSize];
    wchar_t* domain = new wchar_t[domainSize];

    if (!LookupAccountSid(NULL, pSid, name, &nameSize, domain, &domainSize, &sidName)) {
        if (GetLastError() != 122) {
            CloseHandle(hToken);
            delete[] buffer;
            delete[] name;
            delete[] domain;
            return "N/A";
        }
    }

    std::wstring user = std::wstring(domain) + L"\\" + std::wstring(name);

    std::wstring strW = user;
    std::string str = Profiler::WideStringToString(strW);

    CloseHandle(hToken);
    delete[] buffer;
    delete[] name;
    delete[] domain;
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
            return "N/A";
    }
}
std::string ProcessProfiler::GetProcessFileVersion(UINT& pid) {
    std::string imgName = GetProcessImageName(pid);
    std::wstring imgNameW = Profiler::StringToWideString(imgName);

    DWORD len = 0;
    BYTE* buffer = nullptr;

    DWORD size = GetFileVersionInfoSize(imgNameW.c_str(), NULL);
    if (size == 0) {
        return "N/A";
    }
    buffer = new BYTE[size];
    if (!GetFileVersionInfo(imgNameW.c_str(), 0, size, buffer)) {
        delete[] buffer;
        return "N/A";
    }
    LPVOID lpBuffer;
    UINT lpLen;
    if (!VerQueryValue(buffer, L"", &lpBuffer, &lpLen)) {
        delete[] buffer;
        return "N/A";
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
        return "N/A";
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &hTokenSize)) {
        if (GetLastError() != 122) {
            CloseHandle(hToken);
            return "N/A";
        }
    }
    
    TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)malloc(hTokenSize);

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, tml, hTokenSize, &hTokenSize)) {
        free(tml);
        CloseHandle(hToken);
        return "N/A";
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
    if (ntdll == NULL) return "N/A";

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) return "N/A";

    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS s = NtQueryInformationProcess(pHandle, 0, &pbi, sizeof(pbi), NULL);
    if (s != 0) return "N/A";

    PEB peb;
    if (!ReadProcessMemory(pHandle, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL))
        return "N/A";

    NTTYPES_RTL_USER_PROCESS_PARAMETERS params;
    if (!ReadProcessMemory(pHandle, peb.ProcessParameters, &params, sizeof(NTTYPES_RTL_USER_PROCESS_PARAMETERS), NULL)) {
        return "N/A";
    }

    UNICODE_STRING cmdStr = params.CommandLine;
    WCHAR* buffer = new WCHAR[(cmdStr.Length / 2) + 1]();

    if (!ReadProcessMemory(pHandle, cmdStr.Buffer, buffer, cmdStr.Length, NULL)) {
        delete[] buffer;
        return "N/A";
    }

    std::wstring wstr(buffer);
    std::string str = Profiler::WideStringToString(wstr);

    delete[] buffer;
    CloseHandle(pHandle);

    return str;
}
std::string ProcessProfiler::GetProcessDescription(UINT& pid) {
    std::string imgName = GetProcessImageName(pid);
    std::wstring imgNameW = Profiler::StringToWideString(imgName);

    DWORD len = 0;
    BYTE* buffer = nullptr;

    DWORD size = GetFileVersionInfoSize(imgNameW.c_str(), NULL);
    if (size == 0) {
        return "N/A";
    }
    
    buffer = new BYTE[size];
    if (!GetFileVersionInfo(imgNameW.c_str(), 0, size, buffer)) {
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

    LPVOID lpBuffer;
    UINT lpLen;
    std::wstring descW;

    for (unsigned int i = 0; i < (cbTranslate / sizeof(LANGANDCODEPAGE)); i++) {
        wchar_t block[256];

        swprintf_s(block, L"\\StringFileInfo\\%04x%04x\\FileDescription", lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);

        if (!VerQueryValue(buffer, block, &lpBuffer, &lpLen)) {
            delete[] buffer;
            return "N/A";
        }

        descW = (LPWSTR)lpBuffer;
    }

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
UINT64 ProcessProfiler::GetProcessCycleCount(UINT& pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    UINT64 count;
    if (!QueryProcessCycleTime(pHandle, &count))
        return 0;

    return count;
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
    
    if (infoFlags == 0)
        goto SKIPALL;

    if (infoFlags & PIF_PROCESS_NAME) {
        const std::string& name = GetProcessName(pid);
        info.name = new char[name.length() + 1];
        strcpy_s(info.name, name.length() + 1, name.c_str());
    }
    if (infoFlags & PIF_PROCESS_PARENT_NAME) {
        const std::string& pName = GetProcessParentName(pid);
        info.parentProcessName = new char[pName.length() + 1];
        strcpy_s(info.parentProcessName, pName.length() + 1, pName.c_str());
    }
    if (infoFlags & PIF_PROCESS_IMAGE_NAME) {
        const std::string& imageName = GetProcessImageName(pid);
        info.imageName = new char[imageName.length() + 1];
        strcpy_s(info.imageName, imageName.length() + 1, imageName.c_str());
    }
    if (infoFlags & PIF_PROCESS_USER) {
        const std::string& user = GetProcessUser(pid);
        info.user = new char[user.length() + 1];
        strcpy_s(info.user, user.length() + 1, user.c_str());
    }
    if (infoFlags & PIF_PROCESS_PRIORITY) {
        const std::string& priority = GetProcessPriority(pid);
        info.priority = new char[priority.length() + 1];
        strcpy_s(info.priority, priority.length() + 1, priority.c_str());
    }
    if (infoFlags & PIF_PROCESS_FILE_VERSION) {
        const std::string& fileVersion = GetProcessFileVersion(pid);
        info.fileVersion = new char[fileVersion.length() + 1];
        strcpy_s(info.fileVersion, fileVersion.length() + 1, fileVersion.c_str());
    }
    if (infoFlags & PIF_PROCESS_ARCHITECTURE_TYPE) {
        const std::string& architectureType = GetProcessArchitectureType(pid);
        info.architectureType = new char[architectureType.length() + 1];
        strcpy_s(info.architectureType, architectureType.length() + 1, architectureType.c_str());
    }
    if (infoFlags & PIF_PROCESS_INTEGRITY_LEVEL) {
        const std::string& integrityLevel = GetProcessIntegrityLevel(pid);
        info.integrityLevel = new char[integrityLevel.length() + 1];
        strcpy_s(info.integrityLevel, integrityLevel.length() + 1, integrityLevel.c_str());
    }
    if (infoFlags & PIF_PROCESS_COMMAND_LINE) {
        const std::string& cmd = GetProcessCommandLine(pid);
        info.cmd = new char[cmd.length() + 1];
        strcpy_s(info.cmd, cmd.length() + 1, cmd.c_str());
    }
    if (infoFlags & PIF_PROCESS_DESCRIPTION) {
        const std::string& description = GetProcessDescription(pid);
        info.description = new char[description.length() + 1];
        strcpy_s(info.description, description.length() + 1, description.c_str());
    }
    if (infoFlags & PIF_PROCESS_TIMES) {
        info.timesInfo = GetProcessCurrentTimes(pid);
    }
    if (infoFlags & PIF_PROCESS_PPID) {
        info.ppid = GetProcessPPID(pid);
    }
    if (infoFlags & PIF_PROCESS_PEB) {
        info.peb = GetProcessPEB(pid);
    }
    if (infoFlags & PIF_PROCESS_HANDLES_INFO) {
        info.handlesInfo = GetProcessHandlesInfo(pid);
    }
    if (infoFlags & PIF_PROCESS_CYCLE_COUNT) {
        info.cycles = GetProcessCycleCount(pid);
    }
    if (infoFlags & PIF_PROCESS_MEMORY_INFO) {
        info.memoryInfo = GetProcessMemoryCurrentInfo(pid);
    }
    if (infoFlags & PIF_PROCESS_IO_INFO) {
        info.ioInfo = GetProcessIOCurrentInfo(pid);
    }

    SKIPALL:
    info.pid = pid;

    return info;
}
ProcessHandlesInfo ProcessProfiler::GetProcessHandlesInfo(UINT& pid) {
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    ProcessHandlesInfo info = {};

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) return info;

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) return info;

    NTTYPES_PROCESS_HANDLE_INFORMATION ntphi;
    NTSTATUS status = NtQueryInformationProcess(pHandle, 20, &ntphi, sizeof(ntphi), NULL);
    if (status != 0) return info;

    info.count = ntphi.HandleCount;
    info.peakCount = ntphi.HandleCountHighWatermark;
    info.gdiCount = GetGuiResources(pHandle, GR_GDIOBJECTS);
    info.userCount = GetGuiResources(pHandle, GR_USEROBJECTS);

    return info;
}
ProcessTimesInfo ProcessProfiler::GetProcessCurrentTimes(UINT& pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);
    FILETIME creationTime, exitTime, kernelTime, userTime;
    ProcessTimesInfo info = {};

    if (!GetProcessTimes(pHandle, &creationTime, &exitTime, &kernelTime, &userTime))
        return info;

    FILETIME totalTime;

    ULARGE_INTEGER tu, tl, tr;
    tl.LowPart = userTime.dwLowDateTime;
    tl.HighPart = userTime.dwHighDateTime;

    tu.LowPart = kernelTime.dwLowDateTime;
    tu.HighPart = kernelTime.dwHighDateTime;

    tr.QuadPart = tl.QuadPart + tu.QuadPart;

    totalTime.dwLowDateTime = tr.LowPart;
    totalTime.dwHighDateTime = tr.HighPart;

    info.creationTime = creationTime;
    info.exitTime = exitTime;
    info.kernelTime = kernelTime;
    info.userTime = userTime;
    info.totalTime = totalTime;

    return info;
}
ProcessMemoryInfo ProcessProfiler::GetProcessMemoryCurrentInfo(UINT& pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);

    ProcessMemoryInfo info = {};

    PROCESS_MEMORY_COUNTERS_EX pmc;

    if (GetProcessMemoryInfo(pHandle, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        info.pageFaults = (UINT)pmc.PageFaultCount;
        
        info.privateBytes = (UINT)pmc.PagefileUsage;
        info.peakPrivateBytes = (UINT)pmc.PeakPagefileUsage;

        info.workingBytes = (UINT)pmc.WorkingSetSize;
        info.peakWorkingBytes = (UINT)pmc.PeakWorkingSetSize;
        
        info.virtualBytes = (UINT)pmc.PagefileUsage + (UINT)pmc.WorkingSetSize;
        info.peakVirtualBytes = (UINT)pmc.PeakPagefileUsage + (UINT)pmc.PeakWorkingSetSize;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) return info;

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) return info;

    NTTYPES_PAGE_PRIORITY_INFORMATION ppi;
    ULONG len;

    NTSTATUS status = NtQueryInformationProcess(pHandle, 39, &ppi, sizeof(NTTYPES_PAGE_PRIORITY_INFORMATION), &len);
    if (status != 0)
        return info;

    info.pagePriority = ppi.PagePriority;

    return info;
}
ProcessIOInfo ProcessProfiler::GetProcessIOCurrentInfo(UINT& pid) {
    HANDLE pHandle = Profiler::GetProcessHandle(pid);
    ProcessIOInfo info = {};

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) return info;

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) return info;

    NTTYPES_IO_PRIORITY_HINT iph;
    IO_COUNTERS ioc;
    ULONG len;

    NTSTATUS statusIph = NtQueryInformationProcess(pHandle, 33, &iph, sizeof(NTTYPES_IO_PRIORITY_HINT), &len);
    NTSTATUS statusIoc = NtQueryInformationProcess(pHandle, 2, &ioc, sizeof(IO_COUNTERS), &len);
    
    if (statusIph != 0 || statusIoc != 0)
        return info;

    info.reads = ioc.ReadOperationCount;
    info.readBytes = ioc.ReadTransferCount;
    
    info.writes = ioc.WriteOperationCount;
    info.writeBytes = ioc.WriteTransferCount;
    
    info.other = ioc.OtherOperationCount;
    info.otherBytes = ioc.OtherTransferCount;

    switch (iph)
    {
        case IoPriorityVeryLow:
            info.ioPriority = 0;
            break;
        case IoPriorityLow:
            info.ioPriority = 1;
            break;
        case IoPriorityNormal:
            info.ioPriority = 2;
            break;
        case IoPriorityHigh:
            info.ioPriority = 3;
            break;
        case IoPriorityCritical:
            info.ioPriority = 4;
            break;
        case MaxIoPriorityTypes:
            info.ioPriority = 5;
            break;
        default:
            info.ioPriority = 0;
            break;
    }

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