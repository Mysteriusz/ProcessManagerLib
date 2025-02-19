
// PROFILERS
#include "RamProfiler.h"

// STRUCTS
#include "RamFlags.h"

// LIBS
#include "psapi.h"
#include "string.h"
#include <memory>

using namespace ProfilingLib::Profilers;

extern "C" _declspec(dllexport) const RamInfo* GetRamInfo(RAM_RIF_FLAGS rif, RAM_UIF_FLAGS uif, RAM_BIF_FLAGS bif) {
	RamInfo res = Profiler::ramProfiler.GetRamInfo(rif, uif, bif);
	static RamInfo staticRes; staticRes = res;

	return &staticRes;
}
extern "C" _declspec(dllexport) const RamUtilizationInfo* GetRamUtilizationInfo(RAM_UIF_FLAGS uif) {
	RamUtilizationInfo res = Profiler::ramProfiler.GetRamUtilizationInfo(uif);
	static RamUtilizationInfo staticRes; staticRes = res;

	return &staticRes;
}
extern "C" _declspec(dllexport) const RamBlockInfo* GetAllRamBlockInfo(RAM_BIF_FLAGS bif, size_t* size) {
	std::vector<RamBlockInfo> res = Profiler::ramProfiler.GetAllRamBlockInfo(bif);
	*size = res.size();

	RamBlockInfo* arr = new RamBlockInfo[res.size()];
	std::copy(res.begin(), res.end(), arr);

	return arr;
}

extern "C" _declspec(dllexport) void FreeRamInfo(RamInfo* info) {
	for (UINT i = 0; i < info->blockCount; ++i) {
		delete[] info->blocks[i].vendor;
		delete[] info->blocks[i].deviceLocator;
		delete[] info->blocks[i].bankLocator;
	}

	delete[] info->blocks;
	//delete info;
}
