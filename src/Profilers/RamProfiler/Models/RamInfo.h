#pragma once

#include "windows.h"

struct RamUtilizationInfo {
	UINT64 totalPhysicalMemory = 0;
	UINT64 totalVirtualMemory = 0;
	UINT64 totalPageMemory = 0;

	UINT64 availablePhysicalMemory = 0;
	UINT64 availableVirtualMemory = 0;
	UINT64 availablePageMemory = 0;
	
	UINT memoryLoad = 0;
};
struct RamBlockInfo {
	char* deviceLocator = nullptr;
	char* bankLocator= nullptr;
	char* vendor = nullptr;

	USHORT arrHandle = 0;
	USHORT errInfoHandle = 0;
	USHORT totalWidth = 0;
	USHORT dataWidth = 0;
	USHORT typeDetail = 0;
	USHORT size = 0;
	USHORT speed = 0;

	USHORT minVoltage = 0;
	USHORT maxVoltage = 0;
	USHORT configVoltage = 0;

	BYTE formFactor = 0;
	BYTE deviceSet = 0;
	BYTE memoryType = 0;

	UINT extendedSize = 0;
};
struct RamInfo {
	BYTE location = 0;
	BYTE use = 0;
	BYTE memCorrectionError = 0; 
	
	USHORT memErrorInfoHandle = 0;
	USHORT deviceCount = 0;
	
	UINT maxCapacity = 0; 
	UINT64 extMaxCapacity = 0;

	RamUtilizationInfo utilizationInfo;

	UINT blockCount = 0;
	RamBlockInfo* blocks = nullptr;
};