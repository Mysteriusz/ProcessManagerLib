#ifndef PROCESS_INFO_H
#define PROCESS_INFO_H

#include "windows.h"
#include <string>
#include <ctime>

struct ProcessInfo {
    char* name = nullptr;
    char* user = nullptr;
    char* imageName = nullptr;
    char* priority = nullptr;

    UINT pid = 0;
};

#endif 