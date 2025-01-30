#include "ProcessProfiler.h"
#include "string.h"
#include "psapi.h"

using namespace ProfilingLib::Profilers;

extern "C" _declspec(dllexport) const char* GetProcessName(DWORD pid) {
	std::string res = Profiler::processProfiler.GetProcessName(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessImageName(DWORD pid) {
	std::string res = Profiler::processProfiler.GetProcessImageName(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessUser(DWORD pid) {
	std::string res = Profiler::processProfiler.GetProcessUser(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessPriority(DWORD pid) {
	std::string res = Profiler::processProfiler.GetProcessPriority(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" __declspec(dllexport) ProcessInfo* GetAllProcesses(size_t* size) {
    std::vector<ProcessInfo> res = Profiler::processProfiler.GetAllProcesses();
    *size = res.size();

    ProcessInfo* arr = new ProcessInfo[*size];
    std::copy(res.begin(), res.end(), arr);

    return arr;
}