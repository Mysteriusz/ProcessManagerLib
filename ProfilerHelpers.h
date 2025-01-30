#pragma once

#include "windows.h"
#include "string.h"

#include "ProcessProfiler.h"
#include "CpuProfiler.h"

#include <vector>

namespace ProfilingLib::Profilers {
	BOOL SetPrivilages(HANDLE hToken, LPCTSTR privilage, BOOL enable, INT& c) {
		TOKEN_PRIVILEGES tp;
		LUID luid;

		if (!LookupPrivilegeValue(NULL, privilage, &luid)) {
			c = 0;
			return FALSE;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;

		if (enable)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
			c = 1;
			return FALSE;
		}

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
			c = 2;
			return FALSE;
		}

		return TRUE;
	}

	std::wstring ConvertToWideString(const std::string& str) {
		int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
		std::wstring wideStr(len, 0);
		MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wideStr[0], len);
		return wideStr;
	}
	std::string ConvertFromWideString(const std::wstring& str) {
		int len = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
		std::string multiStr(len, 0);
		WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, &multiStr[0], len, nullptr, nullptr);
		return multiStr;
	}
}