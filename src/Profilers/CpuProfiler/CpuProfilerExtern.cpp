// PROFILERS
#include "ProcessProfiler.h"
#include "CpuProfiler.h"
#include "CpuFlags.h"
#include "Profiler.h"

// STRUCTS
#include "CpuInfo.h"

// LIBS
#include <string>

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

extern "C" _declspec(dllexport) const DOUBLE* GetCpuUsage() {
	DOUBLE res = Profiler::cpuProfiler.GetCpuUsage();
	static DOUBLE staticRes; staticRes = res;

	return &staticRes;
}
extern "C" _declspec(dllexport) const DOUBLE* GetCpuBaseFrequency() {
	DOUBLE res = Profiler::cpuProfiler.GetCpuBaseFrequency();
	static DOUBLE staticRes; staticRes = res;

	return &staticRes;
}
extern "C" _declspec(dllexport) const DOUBLE* GetCpuMaxFrequency() {
	DOUBLE res = Profiler::cpuProfiler.GetCpuMaxFrequency();
	static DOUBLE staticRes; staticRes = res;

	return &staticRes;
}

extern "C" _declspec(dllexport) const UINT* GetCpuThreadCount() {
	UINT res = Profiler::cpuProfiler.GetCpuThreadCount();
	static UINT staticRes; staticRes = res;
	
	return &staticRes;
}
extern "C" _declspec(dllexport) const UINT* GetCpuHandleCount() {
	UINT res = Profiler::cpuProfiler.GetCpuHandleCount();
	static UINT staticRes; staticRes = res;

	return &staticRes;
}

extern "C" _declspec(dllexport) const BOOL* IsCpuVirtualization() {
	BOOL res = Profiler::cpuProfiler.IsCpuVirtualization();
	static BOOL staticRes; staticRes = res;
	return &staticRes;
}
extern "C" _declspec(dllexport) const BOOL* IsCpuHyperThreading() {
	BOOL res = Profiler::cpuProfiler.IsCpuHyperThreading();
	static BOOL staticRes; staticRes = res;
	return &staticRes;

}

extern "C" _declspec(dllexport) const CpuInfo* GetCpuInfo(CPU_CIF_FLAGS cif, CPU_SIF_FLAGS sif, CPU_MIF_FLAGS mif, CPU_TIF_FLAGS tif, CPU_HIF_FLAGS hif) {
	CpuInfo* res = new CpuInfo();
	*res = Profiler::cpuProfiler.GetCpuInfo(cif, sif, mif, tif, hif);
	return res;
}
extern "C" _declspec(dllexport) const CpuTimesInfo* GetCpuTimesInfo(CPU_TIF_FLAGS tif) {
	CpuTimesInfo* res = new CpuTimesInfo();
	*res = Profiler::cpuProfiler.GetCpuTimesInfo(tif);
	return res;
}
extern "C" _declspec(dllexport) const CpuModelInfo* GetCpuModelInfo(CPU_MIF_FLAGS mif) {
	CpuModelInfo* res = new CpuModelInfo();
	*res = Profiler::cpuProfiler.GetCpuModelInfo(mif);
	return res;
}
extern "C" _declspec(dllexport) const CpuSystemInfo* GetCpuSystemInfo(CPU_SIF_FLAGS sif) {
	CpuSystemInfo* res = new CpuSystemInfo();
	*res = Profiler::cpuProfiler.GetCpuSystemInfo(sif);
	return res;
}
extern "C" _declspec(dllexport) const CpuCacheInfo* GetCpuAllLevelsCacheInfo(CPU_HIF_FLAGS hif, size_t* size) {
	std::vector<CpuCacheInfo> res = Profiler::cpuProfiler.GetCpuAllLevelsCacheInfo(hif);
	*size = res.size();

	CpuCacheInfo* arr = new CpuCacheInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}

extern "C" _declspec(dllexport) void FreeCpuInfo(CpuInfo* info) {
	if (!info) return;
	
	delete[] info->cacheInfo;

	delete[] info->modelInfo.name;
	delete[] info->modelInfo.vendor;
	delete[] info->modelInfo.architecture;

	delete info;
}