// PROFILERS
#include "ProcessProfiler.h"

// STRUCTS

// LIBS
#include "psapi.h"
#include "string.h"

using namespace ProfilingLib::Profilers;

extern "C" _declspec(dllexport) const char* GetProcessName(UINT pid) {
	std::string res = Profiler::processProfiler.GetProcessName(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessImageName(UINT pid) {
	std::string res = Profiler::processProfiler.GetProcessImageName(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessPriority(UINT pid) {
	std::string res = Profiler::processProfiler.GetProcessPriority(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessUser(UINT pid) {
	std::string res = Profiler::processProfiler.GetProcessUser(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessFileVersion(UINT pid) {
	std::string res = Profiler::processProfiler.GetProcessFileVersion(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessArchitectureType(UINT pid) {
	std::string res = Profiler::processProfiler.GetProcessArchitectureType(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessIntegrityLevel(UINT pid) {
	std::string res = Profiler::processProfiler.GetProcessIntegrityLevel(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessCommandLine(UINT pid) {
	std::string res = Profiler::processProfiler.GetProcessCommandLine(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}
extern "C" _declspec(dllexport) const char* GetProcessDescription(UINT pid) {
	std::string res = Profiler::processProfiler.GetProcessDescription(pid);
	static std::string staticRes; staticRes = res;

	return staticRes.c_str();
}

extern "C" _declspec(dllexport) const UINT64* GetProcessPEB(UINT pid) {
	UINT64 res = Profiler::processProfiler.GetProcessPEB(pid);
	static UINT64 staticRes; staticRes = res;

	return &staticRes;
}
extern "C" _declspec(dllexport) const UINT* GetProcessPPID(UINT pid) {
	UINT res = Profiler::processProfiler.GetProcessPPID(pid);
	static UINT staticRes; staticRes = res;

	return &staticRes;
}
extern "C" _declspec(dllexport) const ProcessHandlesInfo* GetProcessHandlesInfo(UINT pid) {
	ProcessHandlesInfo* res = new ProcessHandlesInfo();
	*res = Profiler::processProfiler.GetProcessHandlesInfo(pid);
	return res;
}
extern "C" _declspec(dllexport) const FILETIME* GetProcessCurrentTimes(UINT pid, size_t* size) {
	std::vector<FILETIME> res = Profiler::processProfiler.GetProcessCurrentTimes(pid);
	*size = res.size();

	FILETIME* arr = new FILETIME[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}

extern "C" __declspec(dllexport) const ProcessInfo* GetProcessInfo(UINT64 flags, UINT pid) {
	ProcessInfo* res = new ProcessInfo();
	*res = Profiler::processProfiler.GetProcessInfo(flags, pid);
	return res;
}
extern "C" __declspec(dllexport) const ProcessInfo* GetAllProcessInfo(UINT64 flags, size_t* size) {
	std::vector<ProcessInfo> res = Profiler::processProfiler.GetAllProcessInfo(flags);
	*size = res.size();

	ProcessInfo* arr = new ProcessInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}