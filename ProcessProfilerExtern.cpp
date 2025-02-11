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

extern "C" _declspec(dllexport) const ProcessTimesInfo* GetProcessCurrentTimes(UINT pid) {
	ProcessTimesInfo* res = new ProcessTimesInfo();
	*res = Profiler::processProfiler.GetProcessCurrentTimes(pid);
	return res;
}
extern "C" _declspec(dllexport) const ProcessMemoryInfo* GetProcessCurrentMemoryInfo(UINT pid) {
	ProcessMemoryInfo* res = new ProcessMemoryInfo();
	*res = Profiler::processProfiler.GetProcessCurrentMemoryInfo(pid);
	return res;
}
extern "C" _declspec(dllexport) const ProcessIOInfo* GetProcessCurrentIOInfo(UINT pid) {
	ProcessIOInfo* res = new ProcessIOInfo();
	*res = Profiler::processProfiler.GetProcessCurrentIOInfo(pid);
	return res;
}
extern "C" _declspec(dllexport) const ProcessCPUInfo* GetProcessCurrentCPUInfo(UINT pid) {
	ProcessCPUInfo* res = new ProcessCPUInfo();
	*res = Profiler::processProfiler.GetProcessCurrentCPUInfo(pid);
	return res;
}

extern "C" _declspec(dllexport) const ProcessModuleInfo* GetProcessAllModuleInfo(UINT64 moduleFlags, UINT pid, size_t* size) {
	std::vector<ProcessModuleInfo> res = Profiler::processProfiler.GetProcessAllModuleInfo(moduleFlags, pid);
	*size = res.size();

	ProcessModuleInfo* arr = new ProcessModuleInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}
extern "C" _declspec(dllexport) const ProcessHandleInfo* GetProcessAllHandleInfo(UINT64 handleFlags, UINT pid, size_t* size) {
	std::vector<ProcessHandleInfo> res = Profiler::processProfiler.GetProcessAllHandleInfo(handleFlags, pid);
	*size = res.size();

	ProcessHandleInfo* arr = new ProcessHandleInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}
extern "C" _declspec(dllexport) const ProcessThreadInfo* GetProcessAllThreadInfo(UINT64 handleFlags, UINT pid, size_t* size) {
	std::vector<ProcessThreadInfo> res = Profiler::processProfiler.GetProcessAllThreadInfo(handleFlags, pid);
	*size = res.size();

	ProcessThreadInfo* arr = new ProcessThreadInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}

extern "C" __declspec(dllexport) const ProcessInfo* GetProcessInfo(UINT64 processFlag, UINT64 moduleFlags, UINT64 handleFlags, UINT64 threadFlags, UINT pid) {
	ProcessInfo* res = new ProcessInfo();
	*res = Profiler::processProfiler.GetProcessInfo(processFlag, moduleFlags, handleFlags, threadFlags, pid);

	return res;
}
extern "C" __declspec(dllexport) void FreeProcessInfo(ProcessInfo* info) {
	if (!info) return;

	delete[] info->name; info->name = nullptr;
	delete[] info->parentProcessName; info->parentProcessName = nullptr;
	delete[] info->user; info->user = nullptr;
	delete[] info->imageName; info->imageName = nullptr;
	delete[] info->priority; info->priority = nullptr;
	delete[] info->fileVersion; info->fileVersion = nullptr;
	delete[] info->integrityLevel; info->integrityLevel = nullptr;
	delete[] info->architectureType; info->architectureType = nullptr;
	delete[] info->cmd; info->cmd = nullptr;
	delete[] info->description; info->description = nullptr;

	for (UINT i = 0; i < info->moduleCount; ++i) {
		delete[] info->modules[i].name; info->modules[i].name = nullptr;
		delete[] info->modules[i].path; info->modules[i].path = nullptr;
		delete[] info->modules[i].description; info->modules[i].description = nullptr;
	}

	for (UINT i = 0; i < info->handleCount; ++i) {
		delete[] info->handles[i].name; info->handles[i].name = nullptr;
		delete[] info->handles[i].type; info->handles[i].type = nullptr;
	}

	delete[] info->handles; info->handles = nullptr;
	delete[] info->modules; info->modules = nullptr;

	delete info;
}

extern "C" __declspec(dllexport) const ProcessInfo* GetAllProcessInfo(UINT64 processFlags, UINT64 moduleFlags, UINT64 handleFlags, UINT64 threadFlags, size_t* size) {
	std::vector<ProcessInfo> res = Profiler::processProfiler.GetAllProcessInfo(processFlags, moduleFlags, handleFlags, threadFlags);
	*size = res.size();

	ProcessInfo* arr = new ProcessInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}