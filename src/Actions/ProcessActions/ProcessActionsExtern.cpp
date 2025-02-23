#include "ProcessActions.h"

#include "Windows.h"
#include <string>

using namespace ProfilingLib::Actions;

extern "C" _declspec(dllexport) void StartProcess(const char* path, const char* commandLine) {
	ProcessActions::StartProcess(path, commandLine);
}
extern "C" _declspec(dllexport) void KillProcess(UINT pid) {
	ProcessActions::KillProcess(pid);
}
extern "C" _declspec(dllexport) void SuspendProcess(UINT pid) {
	ProcessActions::SuspendProcess(pid);
}
extern "C" _declspec(dllexport) void ResumeProcess(UINT pid) {
	ProcessActions::ResumeProcess(pid);
}
extern "C" _declspec(dllexport) void InjectModule(UINT pid, const char* modulePath) {
	ProcessActions::InjectModule(pid, modulePath);
}
extern "C" _declspec(dllexport) void SetAffinity(UINT pid, UINT affinity) {
	ProcessActions::SetAffinity(pid, affinity);
}
extern "C" _declspec(dllexport) void SetPriority(UINT pid, UINT priority) {
	ProcessActions::SetPriority(pid, priority);
}