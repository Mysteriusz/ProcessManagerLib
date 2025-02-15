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
extern "C" _declspec(dllexport) const UINT* GetProcessStatus(UINT pid) {
	UINT res = Profiler::processProfiler.GetProcessStatus(pid);
	static UINT staticRes; staticRes = res;

	return &staticRes;
}

extern "C" _declspec(dllexport) const ProcessTimesInfo* GetProcessCurrentTimes(PROCESS_TIF_FLAGS tif, UINT pid) {
	ProcessTimesInfo* res = new ProcessTimesInfo();
	*res = Profiler::processProfiler.GetProcessCurrentTimes(tif, pid);
	return res;
}
extern "C" _declspec(dllexport) const ProcessMemoryInfo* GetProcessCurrentMemoryInfo(PROCESS_EIF_FLAGS eif, UINT pid) {
	ProcessMemoryInfo* res = new ProcessMemoryInfo();
	*res = Profiler::processProfiler.GetProcessCurrentMemoryInfo(eif, pid);
	return res;
}
extern "C" _declspec(dllexport) const ProcessIOInfo* GetProcessCurrentIOInfo(PROCESS_OIF_FLAGS oif, UINT pid) {
	ProcessIOInfo* res = new ProcessIOInfo();
	*res = Profiler::processProfiler.GetProcessCurrentIOInfo(oif, pid);
	return res;
}
extern "C" _declspec(dllexport) const ProcessCPUInfo* GetProcessCurrentCPUInfo(PROCESS_CIF_FLAGS cif, UINT pid) {
	ProcessCPUInfo* res = new ProcessCPUInfo();
	*res = Profiler::processProfiler.GetProcessCurrentCPUInfo(cif, pid);
	return res;
}
extern "C" _declspec(dllexport) const ProcessModuleInfo* GetProcessAllModuleInfo(PROCESS_MIF_FLAGS mif, UINT pid, size_t* size) {
	std::vector<ProcessModuleInfo> res = Profiler::processProfiler.GetProcessAllModuleInfo(mif, pid);
	*size = res.size();

	ProcessModuleInfo* arr = new ProcessModuleInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}
extern "C" _declspec(dllexport) const ProcessHandleInfo* GetProcessAllHandleInfo(PROCESS_HIF_FLAGS hif, UINT pid, size_t* size) {
	std::vector<ProcessHandleInfo> res = Profiler::processProfiler.GetProcessAllHandleInfo(hif, pid);
	*size = res.size();

	ProcessHandleInfo* arr = new ProcessHandleInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}
extern "C" _declspec(dllexport) const ProcessThreadInfo* GetProcessAllThreadInfo(PROCESS_RIF_FLAGS rif, UINT pid, size_t* size) {
	std::vector<ProcessThreadInfo> res = Profiler::processProfiler.GetProcessAllThreadInfo(rif, pid);
	*size = res.size();

	ProcessThreadInfo* arr = new ProcessThreadInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}

extern "C" __declspec(dllexport) const ProcessInfo* GetProcessInfo(PROCESS_PIF_FLAGS pif,
	PROCESS_MIF_FLAGS mif,
	PROCESS_HIF_FLAGS hif,
	PROCESS_RIF_FLAGS rif,
	PROCESS_TIF_FLAGS tif,
	PROCESS_EIF_FLAGS eif,
	PROCESS_CIF_FLAGS cif,
	PROCESS_OIF_FLAGS oif, UINT pid) {
	ProcessInfo* res = new ProcessInfo();
	*res = Profiler::processProfiler.GetProcessInfo(pif, mif, hif, rif, tif, eif, cif, oif, pid);

	return res;
}
extern "C" __declspec(dllexport) const ProcessInfo* GetAllProcessInfo(
	PROCESS_PIF_FLAGS pif,
	PROCESS_MIF_FLAGS mif,
	PROCESS_HIF_FLAGS hif,
	PROCESS_RIF_FLAGS rif,
	PROCESS_TIF_FLAGS tif,
	PROCESS_EIF_FLAGS eif,
	PROCESS_CIF_FLAGS cif,
	PROCESS_OIF_FLAGS oif,
	size_t* size) {
	std::vector<ProcessInfo> res = Profiler::processProfiler.GetAllProcessInfo(pif, mif, hif, rif, tif, eif, cif, oif);
	*size = res.size();

	ProcessInfo* arr = new ProcessInfo[*size];
	std::copy(res.begin(), res.end(), arr);

	return arr;
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