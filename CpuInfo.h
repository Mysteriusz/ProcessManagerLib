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
struct CpuDeviceInfo {
	char* name;
	char* vendor;
	char* architecture;
	
	UINT model;
	UINT family;
	UINT stepping;

	UINT lv1mem;
	UINT lv2mem;
	UINT lv3mem;
};
struct CpuInfo {
	DOUBLE usage;
	DOUBLE currentfreq;
	DOUBLE baseFreq;
	DOUBLE maxFreq;
	DOUBLE temp;
	
	UINT sockets;
	UINT cores;
	UINT processors;
	UINT threads;
	UINT entries;
	
	BOOL virtualization;
	BOOL hyperThreading;

	CpuDeviceInfo deviceInfo;
	CpuTimesInfo times;
};