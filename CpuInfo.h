#pragma once

// LIBS
#include "windows.h"
#include "string.h"
#include <vector>

struct CpuTimesInfo {
	FILETIME workTime = {0};
	FILETIME kernelTime = {0};
	FILETIME idleTime = {0};
	FILETIME dpcTime = {0};
	FILETIME interruptTime = {0};
	FILETIME userTime = {0};
};
struct CpuModelInfo {
	char* name;
	char* vendor;
	char* architecture;
	
	UINT model;
	UINT family;
	UINT stepping;
};
struct CpuCacheInfo {
	// EAX
	UINT maxCores;
	UINT maxThreads;
	BOOL associative;
	BOOL selfInitializing;
	UINT level;
	UINT type;
	
	// EBX
	UINT ways;
	UINT lineCount;
	UINT lineSize;

	// ECX
	UINT setCount;

	// EDX
	BOOL complexIndexing;
	BOOL inclusive;
	BOOL wbinvd;

	// CUSTOM
	UINT size;
};
struct CpuSystemInfo {
	UINT sockets;
	UINT cores;
	UINT threads;
	UINT numaCount;
};
struct CpuInfo {
	DOUBLE usage;
	DOUBLE baseFreq;
	DOUBLE maxFreq;

	UINT threads;
	UINT handles;
	
	BOOL virtualization;
	BOOL hyperThreading;
	
	CpuSystemInfo sysInfo;
	CpuCacheInfo cacheInfo;
	CpuModelInfo modelInfo;
	CpuTimesInfo times;
};