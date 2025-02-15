#pragma once

// PROFILERS
#include "CpuProfiler.h"

// STRUCTS
#include "CpuInfo.h"

// LIBS
#include "CpuNt.h"
#include "CpuFlags.h"
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
	
	free(spi);
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

	free(spi);
	return handles;
}

DOUBLE CpuProfiler::GetCpuUsage() {
	CpuTimesInfo times = GetCpuTimesInfo(CPU_TIF_ALL);
	
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

CpuInfo CpuProfiler::GetCpuInfo(CPU_CIF_FLAGS cif, CPU_SIF_FLAGS sif, CPU_MIF_FLAGS mif, CPU_TIF_FLAGS tif, CPU_HIF_FLAGS hif) {
	CpuInfo info;

	if (cif == 0) {
		return info;
	}

	if (cif & CPU_CIF_USAGE) {
		info.usage = GetCpuUsage();
	}
	if (cif & CPU_CIF_BASE_FREQ) {
		info.baseFreq = GetCpuBaseFrequency();
	}
	if (cif & CPU_CIF_MAX_FREQ) {
		info.maxFreq = GetCpuMaxFrequency();
	}
	if (cif & CPU_CIF_THREADS) {
		info.threads = GetCpuThreadCount();
	}
	if (cif & CPU_CIF_HANDLES) {
		info.handles = GetCpuHandleCount();
	}
	if (cif & CPU_CIF_VIRTUALIZATION) {
		info.virtualization = IsCpuVirtualization();
	}
	if (cif & CPU_CIF_HYPER_THREADING) {
		info.hyperThreading = IsCpuHyperThreading();
	}
	if (cif & CPU_CIF_CACHE_INFO) {
		std::vector<CpuCacheInfo> cacheInfo = GetCpuAllLevelsCacheInfo(hif);
		size_t size = cacheInfo.size();
		info.cacheInfo = new CpuCacheInfo[size];
		info.cacheCount = static_cast<UINT>(size);
		std::copy(cacheInfo.begin(), cacheInfo.end(), info.cacheInfo);
	}
	if (cif & CPU_CIF_SYS_INFO) {
		info.sysInfo = GetCpuSystemInfo(sif);
	}
	if (cif & CPU_CIF_MODEL_INFO) {
		info.modelInfo = GetCpuModelInfo(mif);
	}
	if (cif & CPU_CIF_TIMES_INFO) {
		info.timesInfo = GetCpuTimesInfo(tif);
	}

	return info;
}
CpuSystemInfo CpuProfiler::GetCpuSystemInfo(CPU_SIF_FLAGS sif) {
	CpuSystemInfo info;
	DWORD len = 0;

	if (sif == 0) {
		return info;
	}

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
				if (sif & CPU_SIF_CORES) {
					info.cores++;
				}
				if (sif & CPU_SIF_THREADS) {
					info.threads += __popcnt(static_cast<unsigned int>(local->Processor.GroupMask->Mask));
				}
				break;
			case RelationProcessorPackage:
				if (sif & CPU_SIF_SOCKETS) {
					info.sockets++;
				}
				break;
			case RelationNumaNode:
				if (sif & CPU_SIF_NUMA_COUNT) {
					info.numaCount++;
				}
				break;
			default:
				break;
		}

		offset += local->Size;
	}

	free(slpie);
	return info;
}
CpuModelInfo CpuProfiler::GetCpuModelInfo(CPU_MIF_FLAGS mif) {
	CpuModelInfo info;

	if (mif == 0) {
		return info;
	}

	int cpuInfo[4] = { 0 };
	__cpuidex(cpuInfo, 0x01, 0);

	if (mif & CPU_MIF_NAME) {
		info.name = _strdup(Profiler::cpuProfiler.GetCpuName().c_str());
	}
	if (mif & CPU_MIF_MODEL) {
		info.model = (cpuInfo[0] >> 4) && 0x0f;
	}
	if (mif & CPU_MIF_STEPPING) {
		info.stepping = cpuInfo[0] && 0x0f;
	}
	if (mif & CPU_MIF_FAMILY) {
		info.family = (cpuInfo[0] >> 8) && 0x0f;
	}
	if (mif & CPU_MIF_VENDOR) {
		info.vendor = _strdup(Profiler::cpuProfiler.GetCpuVendor().c_str());
	}
	if (mif & CPU_MIF_ARCHITECTURE) {
		info.architecture = _strdup(Profiler::cpuProfiler.GetCpuArchitecture().c_str());
	}
	
	return info;
}
CpuTimesInfo CpuProfiler::GetCpuTimesInfo(CPU_TIF_FLAGS tif) {
	CpuTimesInfo times;
	
	if (tif == 0) {
		return times;
	}

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) return times;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) return times;

	CPUNT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION sppi;
	ULONG len;
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)8, &sppi, sizeof(sppi), &len);

	if (tif & CPU_TIF_DPC_TIME) {
		memcpy(&times.dpcTime, &sppi.DpcTime, sizeof(FILETIME));
	}
	if (tif & CPU_TIF_IDLE_TIME) {
		memcpy(&times.idleTime, &sppi.IdleTime, sizeof(FILETIME));
	}
	if (tif & CPU_TIF_INTERRUPT_TIME) {
		memcpy(&times.interruptTime, &sppi.InterruptTime, sizeof(FILETIME));
	}
	if (tif & CPU_TIF_KERNEL_TIME) {
		memcpy(&times.kernelTime, &sppi.KernelTime, sizeof(FILETIME));
	}
	if (tif & CPU_TIF_USER_TIME) {
		memcpy(&times.userTime, &sppi.UserTime, sizeof(FILETIME));
	}
	if (tif & CPU_TIF_WORK_TIME) {
		FILETIME totalTime = Profiler::AddTimes(times.userTime, times.kernelTime);
		times.workTime = totalTime;
	}
	
	return times;
}

std::vector<CpuCacheInfo> CpuProfiler::GetCpuAllLevelsCacheInfo(CPU_HIF_FLAGS hif) {
	std::vector<CpuCacheInfo> infos;

	if (hif == 0) {
		return infos;
	}

	int cacheInfo[4] = { 0 };
	int level = 0;


	while (true) {
		__cpuidex(cacheInfo, 0x04, level);

		if (cacheInfo[0] == 0) {
			break;
		}

		CpuCacheInfo info;

		// EAX
		if (hif & CPU_HIF_TYPE) {
			info.type = cacheInfo[0] & 0x0f;
		}
		if (hif & CPU_HIF_LEVEL) {
			info.level = (cacheInfo[0] >> 5) & 0x07;
		}
		if (hif & CPU_HIF_SELF_INITIALIZING) {
			info.selfInitializing = (cacheInfo[0] >> 8) & 0x01;
		}
		if (hif & CPU_HIF_ASSOCIATIVE) {
			info.associative = (cacheInfo[0] >> 9) & 0x01;
		}
		if (hif & CPU_HIF_MAX_THREADS) {
			info.maxThreads = ((cacheInfo[0] >> 14) & 0xfff) + 1;
		}
		if (hif & CPU_HIF_MAX_CORES) {
			info.maxCores = ((cacheInfo[0] >> 26) & 0x3f) + 1;
		}

		// EBX
		if (hif & CPU_HIF_LINE_SIZE) {
			info.lineSize = (cacheInfo[1] & 0xfff) + 1;
		}
		if (hif & CPU_HIF_LINE_COUNT) {
			info.lineCount = ((cacheInfo[1] >> 12) & 0x3ff) + 1;
		}
		if (hif & CPU_HIF_WAYS) {
			info.ways = ((cacheInfo[1] >> 22) & 0x3ff) + 1;
		}

		// ECX
		if (hif & CPU_HIF_SET_COUNT) {
			info.setCount = (cacheInfo[2] & 0xffffffff) + 1;
		}

		// EDX
		if (hif & CPU_HIF_WBINVD) {
			info.wbinvd = cacheInfo[3] & 0x01;
		}
		if (hif & CPU_HIF_INCLUSIVE) {
			info.inclusive = (cacheInfo[3] >> 1) & 0x01;
		}
		if (hif & CPU_HIF_COMPLEX_INDEXING) {
			info.complexIndexing = (cacheInfo[3] >> 2) & 0x01;
		}

		// CUSTOM
		if (hif & CPU_HIF_SIZE) {
			info.size = info.lineSize * info.lineCount * info.ways * info.setCount;
		}

		infos.push_back(info);
		level++;
	}

	return infos;
}