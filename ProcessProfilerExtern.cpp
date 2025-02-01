// PROFILERS
#include "ProcessProfiler.h"

// STRUCTS

// LIBS
#include "psapi.h"
#include "string.h"

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
extern "C" _declspec(dllexport) const char* GetProcessPriority(DWORD pid) {
	std::string res = Profiler::processProfiler.GetProcessPriority(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessUser(DWORD pid) {
	std::string res = Profiler::processProfiler.GetProcessUser(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessFileVersion(DWORD pid) {
	std::string res = Profiler::processProfiler.GetProcessFileVersion(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessArchitectureType(DWORD pid) {
	std::string res = Profiler::processProfiler.GetProcessArchitectureType(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessIntegrityLevel(DWORD pid) {
	std::string res = Profiler::processProfiler.GetProcessIntegrityLevel(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}

extern "C" _declspec(dllexport) const FILETIME* GetProcessCurrentTimes(DWORD pid, size_t* size) {
	std::vector<FILETIME> res = Profiler::processProfiler.GetProcessCurrentTimes(pid);

	*size = res.size();

	FILETIME* arr = new FILETIME[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}

extern "C" __declspec(dllexport) const ProcessInfo* GetProcessInfo(DWORD pid) {
	ProcessInfo* res = new ProcessInfo();
	*res = Profiler::processProfiler.GetProcessInfo(pid);
	return res;
}
extern "C" __declspec(dllexport) const ProcessInfo* GetAllProcessInfo(size_t* size) {
	std::vector<ProcessInfo> res = Profiler::processProfiler.GetAllProcessInfo();
	*size = res.size();

	ProcessInfo* arr = new ProcessInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}