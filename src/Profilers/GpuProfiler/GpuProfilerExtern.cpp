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

extern "C" _declspec(dllexport) const UINT64* GetGpuDriverVersion() {
	UINT64 res = Profiler::gpuProfiler.GetGpuDriverVersion();
	static UINT64 staticRes; staticRes = res;

	return &staticRes;
}
extern "C" _declspec(dllexport) const UINT64* GetGpuVRamSize() {
	UINT64 res = Profiler::gpuProfiler.GetGpuVRamSize();
	static UINT64 staticRes; staticRes = res;

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
