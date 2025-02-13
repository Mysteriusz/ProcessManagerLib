#pragma once

// PROFILERS
#include "ProcessProfiler.h"

// STRUCTS
#include "ProcessInfo.h"

// LIBS
#include "ProcessNt.h"
#include "TypesNt.h"
#include "windows.h"
#include "processFlags.h"
#include "Tlhelp32.h"
#include "processthreadsapi.h"
#include "ntstatus.h"
#include "winbase.h"
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

    HANDLE* pHandle = Profiler::GetProcessHandle(pid);

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

    HANDLE* pHandle = Profiler::GetProcessHandle(pid);

    if (!QueryFullProcessImageName(pHandle, NULL, processName, plen)) {
        if (GetLastError() == 31) {
            QueryFullProcessImageName(pHandle, PROCESS_NAME_NATIVE, processName, plen);
        }
        else {
            return "N/A";
        }
    }

    std::string str = Profiler::WideStringToString(processName);

    return str;
}
std::string ProcessProfiler::GetProcessUser(UINT& pid) {
    HANDLE* pHandle = Profiler::GetProcessHandle(pid);

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
    std::string str = Profiler::WideStringToString(user.c_str());

    CloseHandle(hToken);
    delete[] buffer;
    delete[] name;
    delete[] domain;
    return str;
}
std::string ProcessProfiler::GetProcessPriority(UINT& pid) {
    HANDLE* pHandle = Profiler::GetProcessHandle(pid);

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
    std::wstring imgNameW = Profiler::StringToWideString(imgName.c_str());

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
    HANDLE* pHandle = Profiler::GetProcessHandle(pid);
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
    HANDLE* pHandle = Profiler::GetProcessHandle(pid);
    
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
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) return "N/A";

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) return "N/A";
    
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS s = NtQueryInformationProcess(pHandle, 0, &pbi, sizeof(pbi), NULL);
    if (s != 0) {
        CloseHandle(pHandle);
        return "N/A";
    }

    PEB peb;
    if (!ReadProcessMemory(pHandle, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
        CloseHandle(pHandle);
        return "N/A";
    }

    NTTYPES_RTL_USER_PROCESS_PARAMETERS params;
    if (!ReadProcessMemory(pHandle, peb.ProcessParameters, &params, sizeof(NTTYPES_RTL_USER_PROCESS_PARAMETERS), NULL)) {
        CloseHandle(pHandle);
        return "N/A";
    }

    UNICODE_STRING cmdStr = params.CommandLine;
    WCHAR* buffer = new WCHAR[(cmdStr.Length / 2) + 1]();

    if (!ReadProcessMemory(pHandle, cmdStr.Buffer, buffer, cmdStr.Length, NULL)) {
        delete[] buffer;
        CloseHandle(pHandle);
        return "N/A";
    }

    std::string str = Profiler::WideStringToString(buffer);

    delete[] buffer;
    CloseHandle(pHandle);

    return str;
}
std::string ProcessProfiler::GetProcessDescription(UINT& pid) {
    std::string imgName = GetProcessImageName(pid);

    return Profiler::GetFileDescription(Profiler::StringToWideString(imgName.c_str()).c_str());
}

UINT64 ProcessProfiler::GetProcessPEB(UINT& pid) {
    HANDLE* pHandle = Profiler::GetProcessHandle(pid);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) return 0;

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) return 0;

    PROCESS_BASIC_INFORMATION pbi;

    NtQueryInformationProcess(pHandle, 0, &pbi, sizeof(pbi), NULL);

    return reinterpret_cast<UINT64>(pbi.PebBaseAddress);
}
UINT64 ProcessProfiler::GetProcessCycleCount(UINT& pid) {
    HANDLE* pHandle = Profiler::GetProcessHandle(pid);

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
UINT ProcessProfiler::GetProcessStatus(UINT& pid) {
    HANDLE* pHandle = Profiler::GetProcessHandle(pid);
    
    DWORD exitCode;
    if (!GetExitCodeProcess(pHandle, &exitCode)) {
        return UINT_MAX;
    }

    return exitCode;
}

ProcessInfo ProcessProfiler::GetProcessInfo(UINT64 processInfoFlags, UINT64 moduleInfoFlags, UINT64 handleInfoFlags, UINT64 threadInfoFlags, UINT& pid) {
    ProcessInfo info;
    
    if (processInfoFlags == 0)
        goto SKIPALL;

    if (processInfoFlags & PIF_PROCESS_NAME) {
        const std::string& name = GetProcessName(pid);

        if (info.name != nullptr) {
            delete[] info.name;
        }

        info.name = new char[name.length() + 1];
        strcpy_s(info.name, name.length() + 1, name.c_str());
    }
    if (processInfoFlags & PIF_PROCESS_PARENT_NAME) {
        const std::string& pName = GetProcessParentName(pid);
        
        if (info.parentProcessName != nullptr) {
            delete[] info.parentProcessName;
        }

        info.parentProcessName = new char[pName.length() + 1];
        strcpy_s(info.parentProcessName, pName.length() + 1, pName.c_str());
    }
    if (processInfoFlags & PIF_PROCESS_IMAGE_NAME) {
        const std::string& imageName = GetProcessImageName(pid);

        if (info.imageName != nullptr) {
            delete[] info.imageName;
        }

        info.imageName = new char[imageName.length() + 1];
        strcpy_s(info.imageName, imageName.length() + 1, imageName.c_str());
    }
    if (processInfoFlags & PIF_PROCESS_USER) {
        const std::string& user = GetProcessUser(pid);

        if (info.user != nullptr) {
            delete[] info.user;
        }

        info.user = new char[user.length() + 1];
        strcpy_s(info.user, user.length() + 1, user.c_str());
    }
    if (processInfoFlags & PIF_PROCESS_PRIORITY) {
        const std::string& priority = GetProcessPriority(pid);
        
        if (info.priority != nullptr) {
            delete[] info.priority;
        }

        info.priority = new char[priority.length() + 1];
        strcpy_s(info.priority, priority.length() + 1, priority.c_str());
    }
    if (processInfoFlags & PIF_PROCESS_FILE_VERSION) {
        const std::string& fileVersion = GetProcessFileVersion(pid);
        
        if (info.fileVersion != nullptr) {
            delete[] info.fileVersion;
        }

        info.fileVersion = new char[fileVersion.length() + 1];
        strcpy_s(info.fileVersion, fileVersion.length() + 1, fileVersion.c_str());
    }
    if (processInfoFlags & PIF_PROCESS_ARCHITECTURE_TYPE) {
        const std::string& architectureType = GetProcessArchitectureType(pid);
        
        if (info.architectureType != nullptr) {
            delete[] info.architectureType;
        }
        
        info.architectureType = new char[architectureType.length() + 1];
        strcpy_s(info.architectureType, architectureType.length() + 1, architectureType.c_str());
    }
    if (processInfoFlags & PIF_PROCESS_INTEGRITY_LEVEL) {
        const std::string& integrityLevel = GetProcessIntegrityLevel(pid);
        
        if (info.integrityLevel != nullptr) {
            delete[] info.integrityLevel;
        }

        info.integrityLevel = new char[integrityLevel.length() + 1];
        strcpy_s(info.integrityLevel, integrityLevel.length() + 1, integrityLevel.c_str());
    }
    if (processInfoFlags & PIF_PROCESS_COMMAND_LINE) {
        const std::string& cmd = GetProcessCommandLine(pid);
        
        if (info.cmd != nullptr) {
            delete[] info.cmd;
        }

        info.cmd = new char[cmd.length() + 1];
        strcpy_s(info.cmd, cmd.length() + 1, cmd.c_str());
    }
    if (processInfoFlags & PIF_PROCESS_DESCRIPTION) {
        const std::string& description = GetProcessDescription(pid);
       
        if (info.description != nullptr) {
            delete[] info.description;
        }
        
        info.description = new char[description.length() + 1];
        strcpy_s(info.description, description.length() + 1, description.c_str());
    }
    if (processInfoFlags & PIF_PROCESS_TIMES) {
        info.timesInfo = GetProcessCurrentTimes(pid);
    }
    if (processInfoFlags & PIF_PROCESS_PPID) {
        info.ppid = GetProcessPPID(pid);
    }
    if (processInfoFlags & PIF_PROCESS_PEB) {
        info.peb = GetProcessPEB(pid);
    }
    if (processInfoFlags & PIF_PROCESS_HANDLES_INFO) {
        std::vector<ProcessHandleInfo> res = Profiler::processProfiler.GetProcessAllHandleInfo(handleInfoFlags, pid);
        size_t size = res.size();

        ProcessHandleInfo* arr = new ProcessHandleInfo[size];
        std::copy(res.begin(), res.end(), arr);

        HANDLE* pHandle = Profiler::GetProcessHandle(pid);

        info.handleCount = (UINT)size;
        info.handles = arr;
        info.gdiCount = GetGuiResources(pHandle, GR_GDIOBJECTS);
        info.userCount = GetGuiResources(pHandle, GR_USEROBJECTS);
    }
    if (processInfoFlags & PIF_PROCESS_CPU_INFO) {
        info.cpuInfo = GetProcessCurrentCPUInfo(pid);
    }
    if (processInfoFlags & PIF_PROCESS_MEMORY_INFO) {
        info.memoryInfo = GetProcessCurrentMemoryInfo(pid);
    }
    if (processInfoFlags & PIF_PROCESS_IO_INFO) {
        info.ioInfo = GetProcessCurrentIOInfo(pid);
    }
    if (processInfoFlags & PIF_PROCESS_MODULES_INFO) {
        std::vector<ProcessModuleInfo> res = Profiler::processProfiler.GetProcessAllModuleInfo(moduleInfoFlags, pid);
        size_t size = res.size();

        ProcessModuleInfo* arr = new ProcessModuleInfo[size];
        std::copy(res.begin(), res.end(), arr);

        info.moduleCount = (UINT)size;
        info.modules = arr;
    }
    if (processInfoFlags & PIF_PROCESS_THREADS_INFO) {
        std::vector<ProcessThreadInfo> res = Profiler::processProfiler.GetProcessAllThreadInfo(threadInfoFlags, pid);
        size_t size = res.size();

        ProcessThreadInfo* arr = new ProcessThreadInfo[size];
        std::copy(res.begin(), res.end(), arr);

        info.threadCount = (UINT)size;
        info.threads = arr;
    }

    SKIPALL:
    info.pid = pid;

    return info;
}
ProcessTimesInfo ProcessProfiler::GetProcessCurrentTimes(UINT& pid) {
    HANDLE* pHandle = Profiler::GetProcessHandle(pid);
    FILETIME creationTime, exitTime, kernelTime, userTime;
    ProcessTimesInfo info = {};

    if (!GetProcessTimes(pHandle, &creationTime, &exitTime, &kernelTime, &userTime))
        return info;

    FILETIME totalTime = Profiler::AddTimes(userTime, kernelTime);

    info.creationTime = creationTime;
    info.exitTime = exitTime;
    info.kernelTime = kernelTime;
    info.userTime = userTime;
    info.totalTime = totalTime;

    return info;
}
ProcessMemoryInfo ProcessProfiler::GetProcessCurrentMemoryInfo(UINT& pid) {
    HANDLE* pHandle = Profiler::GetProcessHandle(pid);

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
ProcessIOInfo ProcessProfiler::GetProcessCurrentIOInfo(UINT& pid) {
    HANDLE* pHandle = Profiler::GetProcessHandle(pid);
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

    info.ioPriority = iph;

    return info;
}
ProcessCPUInfo ProcessProfiler::GetProcessCurrentCPUInfo(UINT& pid) {
    ProcessCPUInfo info;

    ProcessHolder* holder = Profiler::GetProcessHolder(pid);
    ProcessTimesInfo times = GetProcessCurrentTimes(pid);

    LARGE_INTEGER now, sys, user, freq;
    QueryPerformanceCounter(&now);
    QueryPerformanceFrequency(&freq);
    
    UINT cpuCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);

    memcpy(&user, &times.userTime, sizeof(FILETIME));
    memcpy(&sys, &times.kernelTime, sizeof(FILETIME));

    DOUBLE totalTimeDelta = (now.QuadPart - holder->prevNow.QuadPart) / (DOUBLE)freq.QuadPart;
    DOUBLE cpuTimeDelta = ((sys.QuadPart - holder->prevSys.QuadPart) + (user.QuadPart - holder->prevUser.QuadPart)) / 10000000.0;

    DOUBLE percent = cpuTimeDelta / totalTimeDelta * 100.0 / cpuCount;

    info.usage = percent;
    info.cycles = GetProcessCycleCount(pid);

    holder->prevNow = now;
    holder->prevSys = sys;
    holder->prevUser = user;

    return info;
}

std::vector<ProcessModuleInfo> ProcessProfiler::GetProcessAllModuleInfo(UINT64 moduleInfoFlags, UINT& pid) {
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    std::vector<ProcessModuleInfo> infos;

    HMODULE modules[1024];
    DWORD cbNeeded;
    if (EnumProcessModulesEx(pHandle, modules, sizeof(modules), &cbNeeded, LIST_MODULES_ALL)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
           
            ProcessModuleInfo info;
            WCHAR modulePath[MAX_PATH];

            if (!GetModuleFileNameExW(pHandle, modules[i], modulePath, MAX_PATH)) {
                continue;
            }

            if (MIF_MODULE_NAME) {
                info.name = _strdup(Profiler::WideStringToString(std::filesystem::path(modulePath).filename().c_str()).c_str());
            }
            if (MIF_MODULE_ADDRESS) {
                info.address = reinterpret_cast<UINT64>(modules[i]);
            }
            if (MIF_MODULE_PATH) {
                info.path = _strdup(Profiler::WideStringToString(modulePath).c_str());
            }
            if (MIF_MODULE_SIZE) {
                MODULEINFO modInfo;
                if (GetModuleInformation(pHandle, modules[i], &modInfo, sizeof(modInfo))) {
                    info.size = modInfo.SizeOfImage;
                }
            }
            if (MIF_MODULE_DESCRIPTION) {
                info.description = _strdup(Profiler::GetFileDescription(modulePath).c_str());
            }

            infos.push_back(info);
        }
    }

    CloseHandle(pHandle);
    return infos;
}
std::vector<ProcessHandleInfo> ProcessProfiler::GetProcessAllHandleInfo(UINT64 handleInfoFlags, UINT& pid) {
    std::vector<ProcessHandleInfo> infos;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) return infos;

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) return infos;
    
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    ULONG bufferSize = sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION);
    PROCESS_HANDLE_SNAPSHOT_INFORMATION* phsi = (PROCESS_HANDLE_SNAPSHOT_INFORMATION*)malloc(bufferSize);
    
    NTSTATUS status = NtQueryInformationProcess(pHandle, 51, phsi, bufferSize, &bufferSize);
    
    PROCESS_HANDLE_SNAPSHOT_INFORMATION* temp = (PROCESS_HANDLE_SNAPSHOT_INFORMATION*)realloc(phsi, bufferSize);

    if (temp == nullptr) {
        free(phsi);
        CloseHandle(pHandle);
        return infos;
    }
    phsi = temp;

    status = NtQueryInformationProcess(pHandle, 51, phsi, bufferSize, &bufferSize);

    if (status == STATUS_INVALID_HANDLE) {
        free(phsi);
        CloseHandle(pHandle);
        return infos;
    }

    for (ULONG i = 0; i < phsi->NumberOfHandles; i++) {
        ProcessHandleInfo info;

        HANDLE hHandle = phsi->Handles[i].HandleValue;
        _NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(ntdll, "NtQueryObject");

        if (handleInfoFlags & HIF_HANDLE_NAME) {
            ULONG oBufferSize = sizeof(OBJECT_NAME_INFORMATION);
            OBJECT_NAME_INFORMATION* oni = (OBJECT_NAME_INFORMATION*)malloc(oBufferSize);

            NTSTATUS oStatus = NtQueryObject(hHandle, (OBJECT_INFORMATION_CLASS)1, oni, oBufferSize, &oBufferSize);

            OBJECT_NAME_INFORMATION* temp = (OBJECT_NAME_INFORMATION*)realloc(oni, oBufferSize);
            
            if (temp == nullptr) {
                free(oni);
                CloseHandle(pHandle);
                return infos;
            }
            oni = temp;

            oStatus = NtQueryObject(hHandle, (OBJECT_INFORMATION_CLASS)1, oni, oBufferSize, &oBufferSize);
            
            UNICODE_STRING name = oni->Name;
            if (!name.Buffer || oStatus == 0xC0000008)
                continue;
            
            const std::string str = Profiler::WideStringToString(name.Buffer);

            info.name = _strdup(str.c_str());

            free(oni);
        }
        if (handleInfoFlags & HIF_HANDLE_TYPE) {
            ULONG oBufferSize = sizeof(OBJECT_TYPE_INFORMATION);
            OBJECT_TYPE_INFORMATION* oti = (OBJECT_TYPE_INFORMATION*)malloc(oBufferSize);

            NTSTATUS oStatus = NtQueryObject(hHandle, ObjectTypeInformation, oti, oBufferSize, &oBufferSize);

            OBJECT_TYPE_INFORMATION* temp = (OBJECT_TYPE_INFORMATION*)realloc(oti, oBufferSize);

            if (temp == nullptr) {
                free(oti);
                CloseHandle(pHandle);
                return infos;
            }
            oti = temp;

            oStatus = NtQueryObject(hHandle, ObjectTypeInformation, oti, oBufferSize, &oBufferSize);
            
            UNICODE_STRING typeName = oti->TypeName;
            if (!typeName.Buffer || oStatus == 0xC0000008)
                continue;

            const std::string str = Profiler::WideStringToString(typeName.Buffer);

            info.type = _strdup(str.c_str());

            free(oti);
        }
        if (handleInfoFlags & HIF_HANDLE_ADDRESS) {
            info.handle = reinterpret_cast<UINT64>(hHandle);
        }
        
        infos.push_back(info);
    }

    free(phsi);
    CloseHandle(pHandle);
    return infos;
}
std::vector<ProcessThreadInfo> ProcessProfiler::GetProcessAllThreadInfo(UINT64 threadInfoFlags, UINT& pid) {
    std::vector<ProcessThreadInfo> infos;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) return infos;

    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (NtQuerySystemInformation == NULL) return infos;

    ULONG bufferSize = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, NULL, bufferSize, &bufferSize);

    NTTYPES_SYSTEM_PROCESS_INFORMATION* spi = (NTTYPES_SYSTEM_PROCESS_INFORMATION*)malloc(bufferSize);

    status = NtQuerySystemInformation(SystemProcessInformation, spi, bufferSize, &bufferSize);
    
    if (status != 0) {
        free(spi);
        return infos;
    }
    NTTYPES_SYSTEM_PROCESS_INFORMATION* current = spi;

    while (current) {
        if (reinterpret_cast<UINT64>(current->UniqueProcessId) == pid) {
            for (ULONG i = 0; i < current->NumberOfThreads; ++i) {
                ProcessThreadInfo info;
                
                if (threadInfoFlags & TIF_THREAD_TID) {
                    info.tid = reinterpret_cast<UINT64>(current->Threads[i].ClientId.UniqueThread);
                }
                if (threadInfoFlags & TIF_THREAD_START_ADDRESS) {
                    info.startAddress = reinterpret_cast<UINT64>(current->Threads[i].StartAddress);
                }
                if (threadInfoFlags & TIF_THREAD_PRIORITY) {
                    info.priority = current->Threads[i].Priority;
                }
                if (threadInfoFlags & TIF_THREAD_CYCLES) {
                    UINT64 id = reinterpret_cast<UINT64>(current->Threads[i].ClientId.UniqueThread);
                    HANDLE threadHandle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, (DWORD)id);

                    if (threadHandle == NULL)
                        continue;

                    UINT64 cycles = 0;

                    QueryThreadCycleTime(threadHandle, &cycles);
                    CloseHandle(threadHandle);

                    info.cyclesDelta = cycles;
                }
                
                infos.push_back(info);
            }
            break;
        }

        if (current->NextEntryOffset == 0) {
            break;
        }

        current = (NTTYPES_SYSTEM_PROCESS_INFORMATION*)((char*)current + current->NextEntryOffset);
    }

    free(spi);
    return infos;
}

std::vector<ProcessInfo> ProcessProfiler::GetAllProcessInfo(UINT64 processInfoFlags, UINT64 moduleInfoFlags, UINT64 handleInfoFlags, UINT64 threadInfoFlags) {
    std::vector<ProcessInfo> infos;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
        if (Process32First(snapshot, &pe32))
        {
            while (Process32Next(snapshot, &pe32))
            {
                ProcessInfo info = GetProcessInfo(processInfoFlags, moduleInfoFlags, handleInfoFlags, threadInfoFlags, (UINT&)pe32.th32ProcessID);
                infos.push_back(info);
            }
        }
        CloseHandle(snapshot);
    }
    return infos;
}