#pragma once

// PROFILERS
#include "CpuProfiler.h"

// STRUCTS
#include "CpuInfo.h"

// LIBS
#include "CpuNt.h"
#include "TypesNt.h"
#include <windows.h>
#include <pdh.h>
#include <iostream>

#pragma comment(lib, "pdh.lib")

using namespace ProfilingLib::Profilers;

DOUBLE CpuProfiler::GetCpuUsage() {

	CpuTimesInfo times = GetCpuTimes();
	
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

CpuTimesInfo CpuProfiler::GetCpuTimes() {
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