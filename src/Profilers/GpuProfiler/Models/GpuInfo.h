#pragma once

#include <windows.h>

struct GpuResolutionInfo {
	UINT width = 0;
	UINT height = 0;
};
struct GpuModelInfo {
	char* name = nullptr;
	char* vendor = nullptr;
	char* driverName = nullptr;
	
	UINT64 driverVersion = 0;
	
	UINT id = 0;
	UINT revision = 0;
};
struct GpuUtilizationInfo{
	DOUBLE utilization = 0.0;
	DOUBLE videoEncode = 0.0;
	DOUBLE videoDecode = 0.0;
	DOUBLE copy = 0.0;
};
struct GpuPhysicalInfo {
	char* busId = nullptr;
	char* legacyBusId = nullptr;
	
	UINT bus = 0;
	UINT domain = 0;
	UINT deviceId = 0;
	UINT pciDeviceId = 0;
	UINT subSysDeviceId = 0;
};
struct GpuInfo {
	char* dxSupport = 0;

	DOUBLE vRamUsage = 0;
	DOUBLE vRamSize = 0;

	GpuUtilizationInfo utilInfo;
	GpuResolutionInfo maxResInfo;
	GpuResolutionInfo minResInfo;
	GpuModelInfo modelInfo;
};