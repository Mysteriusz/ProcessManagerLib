#include "CpuProfiler.h";
#include "CpuInfo.h";

using namespace ProfilingLib::Profilers;

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