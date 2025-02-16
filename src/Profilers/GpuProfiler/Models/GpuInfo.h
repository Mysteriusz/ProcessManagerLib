#pragma once

#include <windows.h>

struct GpuModelInfo {
	char* name = nullptr;
	char* vendor = nullptr;
	char* driverName = nullptr;
	
	UINT64 driverVersion = 0;
	
	UINT id = 0;
	UINT revision = 0;
};
struct GpuInfo {
	UINT64 vRamUsage = 0;
	UINT64 vRamSize = 0;

	UINT shaderModel = 0;
	UINT dxSupport = 0;
	UINT maxResolutionWidth = 0;
	UINT maxResolutionHeight = 0;

	GpuModelInfo modelInfo;
};