#ifndef PROCESS_INFO_H
#define PROCESS_INFO_H

#include "windows.h"
#include <string>
#include <ctime>

struct ProcessInfo {
    char* name = { 0 };
    char* user = { 0 };
    char* imageName = { 0 };
    char* priority = { 0 };

    UINT pid = 0;

    void SetName(const std::string& processName) {
        name = new char[processName.length() + 1];
        strcpy_s(name, processName.length() + 1, processName.c_str());
    }
    void SetUser(const std::string& processUser) {
        user = new char[processUser.length() + 1];
        strcpy_s(user, processUser.length() + 1, processUser.c_str());
    }
    void SetImageName(const std::string& image) {
        imageName = new char[image.length() + 1];
        strcpy_s(imageName, image.length() + 1, image.c_str());
    }
    void SetPriority(const std::string& processPriority) {
        priority = new char[processPriority.length() + 1];
        strcpy_s(priority, processPriority.length() + 1, processPriority.c_str());
    }
};

#endif 