// PROFILERS
#include "Profiler.h"

// STRUCTS
#include "RamInfo.h"

// LIBS
#include "RamFlags.h"
#include "windows.h"
#include "string.h"
#include <vector>

namespace ProfilingLib::Profilers {
	class RamProfiler {
	public:
		RamInfo GetRamInfo(RAM_RIF_FLAGS rif, RAM_UIF_FLAGS uif, RAM_BIF_FLAGS bif);
		RamUtilizationInfo GetRamUtilizationInfo(RAM_UIF_FLAGS uif);
		std::vector<RamBlockInfo> GetAllRamBlockInfo(RAM_BIF_FLAGS bif);
	};
}