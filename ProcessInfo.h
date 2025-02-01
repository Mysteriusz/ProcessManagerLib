#ifndef PROCESS_INFO_H
#define PROCESS_INFO_H

// LIBS
#include "windows.h"
#include <string>
    
struct ProcessInfo {
    char* name = new char[256];
    char* user = new char[256];
    char* imageName = new char[256];
    char* priority = new char[256];
    char* fileVersion = new char[64];
    char* integrityLevel = new char[64];
    char* architectureType = new char[16];

    UINT pid = 0;
    UINT ppid = 0;

    FILETIME creationTime = {0};
    FILETIME kernelTime = {0};
    FILETIME exitTime = {0};
    FILETIME userTime = {0};
    FILETIME totalTime = {0};
};

#endif 