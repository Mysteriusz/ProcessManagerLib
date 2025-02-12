#pragma once

// PROFILERS
#include "ProcessProfiler.h"

// STRUCTS
#include "ProcessInfo.h"

struct ProcessHolder {
	HANDLE* pHandle = nullptr;

    ULARGE_INTEGER prevNow = { 0 };
    ULARGE_INTEGER prevSys = { 0 };
    ULARGE_INTEGER prevUser = { 0 };
};