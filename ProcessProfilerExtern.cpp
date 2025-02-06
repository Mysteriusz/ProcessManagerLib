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
extern "C" _declspec(dllexport) const char* GetProcessParentName(UINT pid) {
	std::string res = Profiler::processProfiler.GetProcessParentName(pid);
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
extern "C" _declspec(dllexport) const UINT64* GetProcessCycleCount(UINT pid) {
	UINT64 res = Profiler::processProfiler.GetProcessCycleCount(pid);
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
extern "C" _declspec(dllexport) const ProcessTimesInfo* GetProcessCurrentTimes(UINT pid) {
	ProcessTimesInfo* res = new ProcessTimesInfo();
	*res = Profiler::processProfiler.GetProcessCurrentTimes(pid);
	return res;
}
extern "C" _declspec(dllexport) const ProcessMemoryInfo* GetProcessMemoryCurrentInfo(UINT pid) {
	ProcessMemoryInfo* res = new ProcessMemoryInfo();
	*res = Profiler::processProfiler.GetProcessMemoryCurrentInfo(pid);
	return res;
}
extern "C" _declspec(dllexport) const ProcessIOInfo* GetProcessIOCurrentInfo(UINT pid) {
	ProcessIOInfo* res = new ProcessIOInfo();
	*res = Profiler::processProfiler.GetProcessIOCurrentInfo(pid);
	return res;
}

extern "C" _declspec(dllexport) const ProcessModuleInfo* GetProcessAllModuleInfo(UINT pid, size_t* size) {
	std::vector<ProcessModuleInfo> res = Profiler::processProfiler.GetProcessAllModuleInfo(pid);
	*size = res.size();

	ProcessModuleInfo* arr = new ProcessModuleInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}

extern "C" __declspec(dllexport) const ProcessInfo* GetProcessInfo(UINT64 flags, UINT pid) {
	ProcessInfo* res = new ProcessInfo();
	*res = Profiler::processProfiler.GetProcessInfo(flags, pid);

	return res;
}
extern "C" __declspec(dllexport) void FreeProcessInfo(ProcessInfo* info) {
	delete[] info->name;
	delete[] info->parentProcessName;
	delete[] info->user;
	delete[] info->imageName;
	delete[] info->priority;
	delete[] info->fileVersion;
	delete[] info->integrityLevel;
	delete[] info->architectureType;
	delete[] info->cmd;
	delete[] info->description;
	delete[] info->modules;
}


extern "C" __declspec(dllexport) const ProcessInfo* GetAllProcessInfo(UINT64 flags, size_t* size) {
	std::vector<ProcessInfo> res = Profiler::processProfiler.GetAllProcessInfo(flags);
	*size = res.size();

	ProcessInfo* arr = new ProcessInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}