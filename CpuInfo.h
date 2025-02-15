#pragma once

// LIBS
#include "windows.h"
#include "string.h"
#include <vector>

struct CpuModelInfo {
	char* name = nullptr;
	char* vendor = nullptr;
	char* architecture = nullptr;
	
	UINT model = 0;
	UINT family = 0;
	UINT stepping = 0;
};
struct CpuTimesInfo {
	FILETIME workTime = {0};
	FILETIME kernelTime = {0};
	FILETIME idleTime = {0};
	FILETIME dpcTime = {0};
	FILETIME interruptTime = {0};
	FILETIME userTime = {0};
};
struct CpuCacheInfo {
	// EAX
	UINT maxCores = 0;
	UINT maxThreads = 0;
	BOOL associative = 0;
	BOOL selfInitializing = 0;
	UINT level = 0;
	UINT type = 0;
	
	// EBX
	UINT ways = 0;
	UINT lineCount = 0;
	UINT lineSize = 0;

	// ECX
	UINT setCount = 0;

	// EDX
	BOOL complexIndexing = 0;
	BOOL inclusive = 0;
	BOOL wbinvd = 0;

	// CUSTOM
	UINT size = 0;
};
struct CpuSystemInfo {
	UINT sockets = 0;
	UINT cores = 0;
	UINT threads = 0;
	UINT numaCount = 0;
};
struct CpuInfo {
	DOUBLE usage = 0;
	DOUBLE baseFreq = 0;
	DOUBLE maxFreq = 0;

	UINT threads = 0;
	UINT handles = 0;
	
	BOOL virtualization = 0;
	BOOL hyperThreading = 0;

	CpuSystemInfo sysInfo;
	CpuModelInfo modelInfo;
	CpuTimesInfo timesInfo;
	
	UINT cacheCount = 0;
	CpuCacheInfo* cacheInfo = nullptr;
};