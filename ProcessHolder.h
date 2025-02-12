#pragma once

// PROFILERS
#include "ProcessProfiler.h"

// STRUCTS
#include "ProcessInfo.h"

struct ProcessHolder {
	HANDLE* pHandle = nullptr;

    LARGE_INTEGER prevNow = { 0 };
    LARGE_INTEGER prevSys = { 0 };
    LARGE_INTEGER prevUser = { 0 };
};