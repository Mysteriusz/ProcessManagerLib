#pragma once

// PROFILERS
#include "GpuProfiler.h"

// STRUCTS

// LIBS
#include "psapi.h"
#include "string.h"
#include <memory>

using namespace ProfilingLib::Profilers;

extern "C" _declspec(dllexport) const char* GetGpuName() {
	std::string res = Profiler::gpuProfiler.GetGpuName();
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetGpuVendor() {
	std::string res = Profiler::gpuProfiler.GetGpuVendor();
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetGpuDriverName() {
	std::string res = Profiler::gpuProfiler.GetGpuDriverName();
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetGpuDXVersion() {
	std::string res = Profiler::gpuProfiler.GetGpuDXVersion();
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}

extern "C" _declspec(dllexport) const UINT64* GetGpuDriverVersion() {
	UINT64 res = Profiler::gpuProfiler.GetGpuDriverVersion();
	static UINT64 staticRes; staticRes = res;

	return &staticRes;
}

extern "C" _declspec(dllexport) const DOUBLE* GetGpuVRamSize() {
	DOUBLE res = Profiler::gpuProfiler.GetGpuVRamSize();
	static DOUBLE staticRes; staticRes = res;

	return &staticRes;
}
extern "C" _declspec(dllexport) const DOUBLE* GetGpuVRamUsage() {
	DOUBLE res = Profiler::gpuProfiler.GetGpuVRamUsage();
	static DOUBLE staticRes; staticRes = res;

	return &staticRes;
}

extern "C" _declspec(dllexport) const UINT* GetGpuID() {
	UINT res = Profiler::gpuProfiler.GetGpuID();
	static UINT staticRes; staticRes = res;

	return &staticRes;
}
extern "C" _declspec(dllexport) const UINT* GetGpuRevision() {
	UINT res = Profiler::gpuProfiler.GetGpuRevision();
	static UINT staticRes; staticRes = res;

	return &staticRes;
}

extern "C" _declspec(dllexport) const GpuInfo* GetGpuInfo(GPU_GIF_FLAGS gif, GPU_MIF_FLAGS mif, GPU_UIF_FLAGS uif, GPU_PIF_FLAGS pif, GPU_RIF_FLAGS rif) {
	GpuInfo* res = new GpuInfo();
	*res = Profiler::gpuProfiler.GetGpuInfo(gif, mif, uif, pif, rif);
	return res;
}
extern "C" _declspec(dllexport) const GpuPhysicalInfo* GetGpuPhysicalInfo(GPU_PIF_FLAGS pif) {
	GpuPhysicalInfo* res = new GpuPhysicalInfo();
	*res = Profiler::gpuProfiler.GetGpuPhysicalInfo(pif);
	return res;
}
extern "C" _declspec(dllexport) const GpuModelInfo* GetGpuModelInfo(GPU_MIF_FLAGS mif) {
	GpuModelInfo* res = new GpuModelInfo();
	*res = Profiler::gpuProfiler.GetGpuModelInfo(mif);
	return res;
}
extern "C" _declspec(dllexport) const GpuUtilizationInfo* GetGpuUtilizationInfo(GPU_UIF_FLAGS uif) {
	GpuUtilizationInfo* res = new GpuUtilizationInfo();
	*res = Profiler::gpuProfiler.GetGpuUtilizationInfo(uif);
	return res;
}
extern "C" _declspec(dllexport) const GpuResolutionInfo* GetGpuMaxResolutionInfo(GPU_RIF_FLAGS rif) {
	GpuResolutionInfo* res = new GpuResolutionInfo();
	*res = Profiler::gpuProfiler.GetGpuMaxResolutionInfo(rif);
	return res;
}
extern "C" _declspec(dllexport) const GpuResolutionInfo* GetGpuMinResolutionInfo(GPU_RIF_FLAGS rif) {
	GpuResolutionInfo* res = new GpuResolutionInfo();
	*res = Profiler::gpuProfiler.GetGpuMinResolutionInfo(rif);
	return res;
}