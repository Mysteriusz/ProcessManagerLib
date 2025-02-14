#pragma once

// PROFILERS
#include "CpuProfiler.h"

// STRUCTS
#include "CpuInfo.h"

// LIBS
#include "CpuNt.h"
#include "TypesNt.h"
#include <iostream>
#include <windows.h>
#include <string.h>

using namespace ProfilingLib::Profilers;

std::string CpuProfiler::GetCpuName() {
	char cpuName[0x40] = { 0 };
	int cpuInfo[4] = { 0 };

    __cpuidex(cpuInfo, 0x80000002, 0);
    memcpy(cpuName, cpuInfo, sizeof(cpuInfo));

    __cpuidex(cpuInfo, 0x80000003, 0);
    memcpy(cpuName + 16, cpuInfo, sizeof(cpuInfo));

    __cpuidex(cpuInfo, 0x80000004, 0);
    memcpy(cpuName + 32, cpuInfo, sizeof(cpuInfo));

	return std::string(cpuName);
}
std::string CpuProfiler::GetCpuVendor() {
	char cpuVendor[0x12] = { 0 };
	int cpuInfo[4] = { 0 };

	__cpuidex(cpuInfo, 0, 0);

	memcpy(cpuVendor, &cpuInfo[1], sizeof(int));
	memcpy(cpuVendor + 4, &cpuInfo[3], sizeof(int));
	memcpy(cpuVendor + 8, &cpuInfo[2], sizeof(int));

	return std::string(cpuVendor);
}
std::string CpuProfiler::GetCpuArchitecture() {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) return "N/A";

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) return "N/A";

	ULONG len;
	CPUNT_SYSTEM_PROCESSOR_INFORMATION spi;

	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)1, &spi, sizeof(spi), &len);

	switch (spi.ProcessorArchitecture)
	{
		case 0:
			return "INTEL";
		case 5:
			return "ARM";
		case 6:
			return "IA64";
		case 9:
			return "AMD64";
		case 12:
			return "ARM64";
		case 0xFFFF:
			return "UNKNOWN";
		default:
			return "N/A";
	}
}

UINT CpuProfiler::GetCpuModel() {
	int cpuInfo[4] = { 0 };
	__cpuidex(cpuInfo, 1, 0);

	return (cpuInfo[0] >> 8) && 0x0f;
}
UINT CpuProfiler::GetCpuFamily() {
	int cpuInfo[4] = { 0 };
	__cpuidex(cpuInfo, 1, 0);

	return (cpuInfo[0] >> 4) && 0x0f;
}
UINT CpuProfiler::GetCpuStepping() {
	int cpuInfo[4] = { 0 };
	__cpuidex(cpuInfo, 1, 0);

	return cpuInfo[0] && 0x0f;
}

UINT CpuProfiler::GetCpuThreadCount() {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) return 0;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

	ULONG len;
	NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &len);

	NTTYPES_SYSTEM_PROCESS_INFORMATION* spi = (NTTYPES_SYSTEM_PROCESS_INFORMATION*)malloc(len);

	status = NtQuerySystemInformation(SystemProcessInformation, spi, len, &len);

	UINT threads = 0;

	NTTYPES_SYSTEM_PROCESS_INFORMATION* current = spi;
	while (current) {

		threads += current->NumberOfThreads;

		if (current->NextEntryOffset == 0) {
			break;
		}

		current = (NTTYPES_SYSTEM_PROCESS_INFORMATION*)((char*)current + current->NextEntryOffset);
	}
	
	return threads;
}
UINT CpuProfiler::GetCpuHandleCount() {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) return 0;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

	ULONG len;
	NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &len);

	NTTYPES_SYSTEM_PROCESS_INFORMATION* spi = (NTTYPES_SYSTEM_PROCESS_INFORMATION*)malloc(len);

	status = NtQuerySystemInformation(SystemProcessInformation, spi, len, &len);

	UINT handles = 0;

	NTTYPES_SYSTEM_PROCESS_INFORMATION* current = spi;
	while (current) {

		handles += current->HandleCount;

		if (current->NextEntryOffset == 0) {
			break;
		}

		current = (NTTYPES_SYSTEM_PROCESS_INFORMATION*)((char*)current + current->NextEntryOffset);
	}

	return handles;
}

DOUBLE CpuProfiler::GetCpuUsage() {
	CpuTimesInfo times = GetCpuTimesInfo();
	
	static ULARGE_INTEGER prevIdleTime, prevKernelTime, prevUserTime;
	ULARGE_INTEGER idleTime, kernelTime, userTime;

	UINT cpuCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);

	memcpy(&idleTime, &times.idleTime, sizeof(ULARGE_INTEGER));
	memcpy(&kernelTime, &times.kernelTime, sizeof(ULARGE_INTEGER));
	memcpy(&userTime, &times.userTime, sizeof(ULARGE_INTEGER));

	if (prevIdleTime.QuadPart == 0 && prevKernelTime.QuadPart == 0 && prevUserTime.QuadPart == 0) {
		prevIdleTime = idleTime;
		prevKernelTime = kernelTime;
		prevUserTime = userTime;
		return 0.0;
	}
	
	ULARGE_INTEGER idleTimeDiff, kernelTimeDiff, userTimeDiff;
	idleTimeDiff.QuadPart = idleTime.QuadPart - prevIdleTime.QuadPart;
	kernelTimeDiff.QuadPart = kernelTime.QuadPart - prevKernelTime.QuadPart;
	userTimeDiff.QuadPart = userTime.QuadPart - prevUserTime.QuadPart;

	ULARGE_INTEGER totalTime;
	totalTime.QuadPart = kernelTimeDiff.QuadPart + userTimeDiff.QuadPart;

	DOUBLE usage = (((totalTime.QuadPart - idleTimeDiff.QuadPart) / (DOUBLE)totalTime.QuadPart) * 100.0);
	usage *= cpuCount;

	prevIdleTime = idleTime;
	prevKernelTime = kernelTime;
	prevUserTime = userTime;

	return usage / cpuCount;
}
DOUBLE CpuProfiler::GetCpuBaseFrequency() {
	int freqInfo[4] = {0};
	__cpuidex(freqInfo, 0x16, 0);

	return static_cast<DOUBLE>(freqInfo[0]) / 1000;
}
DOUBLE CpuProfiler::GetCpuMaxFrequency() {
	int freqInfo[4] = { 0 };
	__cpuidex(freqInfo, 0x16, 0);

	return static_cast<DOUBLE>(freqInfo[1]) / 1000;
}

BOOL CpuProfiler::IsCpuVirtualization() {
	int cpuInfo[4] = { 0 };

	__cpuidex(cpuInfo, 0x01, 0);
	
	return (cpuInfo[2] & (1 << 5)) != 0;
}
BOOL CpuProfiler::IsCpuHyperThreading() {
	int cpuInfo[4] = { 0 };

	__cpuidex(cpuInfo, 0x01, 0);

	return (cpuInfo[3] & (1 << 28)) != 0;
}

CpuSystemInfo CpuProfiler::GetCpuSystemInfo() {
	CpuSystemInfo info = {0};
	DWORD len = 0;

	GetLogicalProcessorInformationEx(RelationAll, NULL, &len);
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* slpie = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)malloc(len);
	GetLogicalProcessorInformationEx(RelationAll, slpie, &len);

	DWORD offset = 0;
	while (offset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX) <= len) {
		SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* local = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)((BYTE*)slpie + offset);

		if (local == nullptr)
			break;

		switch (local->Relationship)
		{
			case RelationProcessorCore:
				info.cores++;
				info.threads += __popcnt(static_cast<unsigned int>(local->Processor.GroupMask->Mask));
				break;
			case RelationProcessorPackage:
				info.sockets++;
				break;
			case RelationNumaNode:
				info.numaCount++;
				break;
			default:
				break;
		}

		offset += local->Size;
	}

	free(slpie);

	return info;
}
CpuModelInfo CpuProfiler::GetCpuModelInfo() {
	CpuModelInfo info;

	int cpuInfo[4] = { 0 };
	__cpuidex(cpuInfo, 1, 0);

	info.family = (cpuInfo[0] >> 8) && 0x0f;
	info.model = (cpuInfo[0] >> 4) && 0x0f;
	info.stepping = cpuInfo[0] && 0x0f;

	info.name = _strdup(Profiler::cpuProfiler.GetCpuName().c_str());
	info.vendor = _strdup(Profiler::cpuProfiler.GetCpuVendor().c_str());
	info.architecture = _strdup(Profiler::cpuProfiler.GetCpuArchitecture().c_str());

	return info;
}
CpuTimesInfo CpuProfiler::GetCpuTimesInfo() {
	CpuTimesInfo times;
	
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) return times;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) return times;

	CPUNT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION sppi;
	ULONG len;
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)8, &sppi, sizeof(sppi), &len);

	memcpy(&times.dpcTime, &sppi.DpcTime, sizeof(FILETIME));
	memcpy(&times.idleTime, &sppi.IdleTime, sizeof(FILETIME));
	memcpy(&times.interruptTime, &sppi.InterruptTime, sizeof(FILETIME));
	memcpy(&times.kernelTime, &sppi.KernelTime, sizeof(FILETIME));
	memcpy(&times.userTime, &sppi.UserTime, sizeof(FILETIME));

	FILETIME totalTime = Profiler::AddTimes(times.userTime, times.kernelTime);
	times.workTime = totalTime;

	return times;
}

std::vector<CpuCacheInfo> CpuProfiler::GetCpuAllLevelsCacheInfo() {
	std::vector<CpuCacheInfo> infos;

	int cacheInfo[4] = { 0 };
	int level = 0;

	while (true) {
		__cpuidex(cacheInfo, 0x04, level);

		if (cacheInfo[0] == 0) break;

		CpuCacheInfo info;

		// EAX
		info.type = cacheInfo[0] & 0x0f;
		info.level = (cacheInfo[0] >> 5) & 0x07;
		info.selfInitializing = (cacheInfo[0] >> 8) & 0x01;
		info.associative = (cacheInfo[0] >> 9) & 0x01;
		info.maxThreads = ((cacheInfo[0] >> 14) & 0xfff) + 1;
		info.maxCores = ((cacheInfo[0] >> 26) & 0x3f) + 1;

		// EBX
		info.lineSize = (cacheInfo[1] & 0xfff) + 1;
		info.lineCount = ((cacheInfo[1] >> 12) & 0x3ff) + 1;
		info.ways = ((cacheInfo[1] >> 22) & 0x3ff) + 1;

		// ECX
		info.setCount = (cacheInfo[2] & 0xffffffff) + 1;

		// EDX
		info.wbinvd = cacheInfo[3] & 0x01;
		info.inclusive = (cacheInfo[3] >> 1) & 0x01;
		info.complexIndexing = (cacheInfo[3] >> 2) & 0x01;

		// CUSTOM
		info.size = info.lineSize * info.lineCount * info.ways * info.setCount;

		infos.push_back(info);
		level++;
	}

	return infos;
}