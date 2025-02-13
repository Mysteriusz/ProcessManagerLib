// PROFILERS
#include "ProcessProfiler.h"
#include "CpuProfiler.h";

// STRUCTS
#include "CpuInfo.h";

// LIBS

using namespace ProfilingLib::Profilers;

extern "C" _declspec(dllexport) const char* GetCpuName() {
	std::string res = Profiler::cpuProfiler.GetCpuName();
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetCpuVendor() {
	std::string res = Profiler::cpuProfiler.GetCpuVendor();
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetCpuArchitecture() {
	std::string res = Profiler::cpuProfiler.GetCpuArchitecture();
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}

extern "C" _declspec(dllexport) const UINT* GetCpuModel() {
	UINT res = Profiler::cpuProfiler.GetCpuModel();
	static UINT staticRes; staticRes = res;
	
	return &staticRes;
}
extern "C" _declspec(dllexport) const UINT* GetCpuFamily() {
	UINT res = Profiler::cpuProfiler.GetCpuFamily();
	static UINT staticRes; staticRes = res;

	return &staticRes;
}
extern "C" _declspec(dllexport) const UINT* GetCpuStepping() {
	UINT res = Profiler::cpuProfiler.GetCpuStepping();
	static UINT staticRes; staticRes = res;

	return &staticRes;
}

extern "C" _declspec(dllexport) const UINT* GetCpuLevel1CacheSize() {
	UINT res = Profiler::cpuProfiler.GetCpuLevel1CacheSize();
	static UINT staticRes; staticRes = res;

	return &staticRes;
}
extern "C" _declspec(dllexport) const UINT* GetCpuLevel2CacheSize() {
	UINT res = Profiler::cpuProfiler.GetCpuLevel2CacheSize();
	static UINT staticRes; staticRes = res;

	return &staticRes;
}
extern "C" _declspec(dllexport) const UINT* GetCpuLevel3CacheSize() {
	UINT res = Profiler::cpuProfiler.GetCpuLevel3CacheSize();
	static UINT staticRes; staticRes = res;

	return &staticRes;
}

extern "C" _declspec(dllexport) const DOUBLE* GetCpuUsage() {
	DOUBLE res = Profiler::cpuProfiler.GetCpuUsage();
	static DOUBLE staticRes; staticRes = res;

	return &staticRes;
}

extern "C" _declspec(dllexport) const CpuTimesInfo* GetCpuTimes() {
	CpuTimesInfo* res = new CpuTimesInfo();
	*res = Profiler::cpuProfiler.GetCpuTimes();
	return res;
}