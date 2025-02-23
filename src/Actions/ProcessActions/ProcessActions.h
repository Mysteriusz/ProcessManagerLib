#pragma once

#include "Windows.h"
#include <string>

namespace ProfilingLib::Actions {
	class ProcessActions {
	public:
		static void StartProcess(const std::string& exePath, const std::string& commandLine);
		static void KillProcess(UINT pid);
		static void SuspendProcess(UINT pid);
		static void ResumeProcess(UINT pid);

		static void InjectModule(UINT pid, const std::string& modulePath);

		static void SetAffinity(UINT pid, UINT affinity);
		static void SetPriority(UINT pid, UINT priority);
	private:
		static std::string WideStringToString(const wchar_t* str) {
			int mlen = WideCharToMultiByte(CP_UTF8, 0, str, -1, nullptr, 0, nullptr, nullptr);
			std::string multiStr(mlen, 0);
			WideCharToMultiByte(CP_UTF8, 0, str, -1, &multiStr[0], mlen, nullptr, nullptr);

			return multiStr;
		}
		static std::wstring StringToWideString(const char* str) {
			int wlen = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
			std::wstring widestr(wlen, 0);
			MultiByteToWideChar(CP_UTF8, 0, str, -1, &widestr[0], wlen);

			return widestr;
		}
	};
}