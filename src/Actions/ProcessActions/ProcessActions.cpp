#pragma once

#include "ProcessActions.h"

#include "Windows.h"
#include <string>

using namespace ProfilingLib::Actions;

void ProcessActions::StartProcess(const std::string& exePath, const std::string& commandLine) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	
	std::wstring wExePath = ProcessActions::StringToWideString(exePath.c_str());
	std::wstring wCommandLine = ProcessActions::StringToWideString(commandLine.c_str());

	std::wstring fullCommandLine = wExePath + L" " + wCommandLine;

	if (CreateProcess(wExePath.c_str(), &fullCommandLine[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
}
void ProcessActions::KillProcess(UINT pid) {
	HANDLE pHandle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

	TerminateProcess(pHandle, 0);

	CloseHandle(pHandle);
}
void ProcessActions::SuspendProcess(UINT pid) {
	HANDLE pHandle = OpenProcess(THREAD_SUSPEND_RESUME, FALSE, pid);
	
	SuspendThread(pHandle);

	CloseHandle(pHandle);
}
void ProcessActions::ResumeProcess(UINT pid) {
	HANDLE pHandle = OpenProcess(THREAD_SUSPEND_RESUME, FALSE, pid);

	ResumeThread(pHandle);

	CloseHandle(pHandle);
}
void ProcessActions::InjectModule(UINT pid, const std::string& modulePath) {
	HANDLE pHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);

	void* remoteMem = VirtualAllocEx(pHandle, nullptr, modulePath.size() * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (remoteMem == nullptr) {
		return;
	}

	WriteProcessMemory(pHandle, remoteMem, modulePath.c_str(), modulePath.size() * sizeof(wchar_t), nullptr);

	HMODULE mod = GetModuleHandle(L"kernel32.dll");
	if (mod == 0) {
		return;
	}

	LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(mod, "LoadLibraryW");

	HANDLE pThread = CreateRemoteThread(pHandle, nullptr, 0, pLoadLibrary, remoteMem, 0, nullptr);

	if (pThread == nullptr) {
		return;
	}

	WaitForSingleObject(pThread, INFINITE);
	VirtualFreeEx(pHandle, remoteMem, 0, MEM_RELEASE);
	CloseHandle(pThread);
	CloseHandle(pHandle);
}
void ProcessActions::SetAffinity(UINT pid, UINT affinity) {
	HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	SetProcessAffinityMask(pHandle, affinity);

	CloseHandle(pHandle);
}
void ProcessActions::SetPriority(UINT pid, UINT priority) {
	HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	SetPriorityClass(pHandle, priority);

	CloseHandle(pHandle);
}