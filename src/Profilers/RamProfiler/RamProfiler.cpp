#pragma once

// PROFILERS
#include "RamProfiler.h"

// STRUCTS
#include "RamInfo.h"

// LIBS
#include "RamFlags.h"
#include "string.h"

using namespace ProfilingLib::Profilers;

struct SMBIOSHeader {
	uint8_t type;
	uint8_t length;
	uint16_t handle;
};

#pragma pack(push, 1)  
struct SMBIOSPhysicalMemoryArray{
	SMBIOSHeader header;
	uint8_t location;
	uint8_t use;
	uint8_t memErrCorrection;
	uint32_t maxCapacity;
	uint16_t memErrInfoHandle;
	uint16_t numOfDevices;
	uint64_t extMaxCapacity;
};
struct SMBIOSMemoryDevice {
	SMBIOSHeader header;
	uint16_t physMemArryHandle;
	uint16_t memErrInfoHandle;
	uint16_t totalWidth;
	uint16_t dataWidth;
	uint16_t size;
	uint8_t formFactor;
	uint8_t deviceSet;
	uint8_t deviceLocator;
	uint8_t bankLocator;
	uint8_t memType;
	uint16_t typeDetail;

	// 2.3+
	uint16_t speed;
	uint8_t manufacturer;
	uint8_t serialNumber;
	uint8_t assetTag;
	uint8_t partNumber;
	
	// 2.6+
	uint8_t attributes;
	
	// 2.7+
	uint32_t extendedSize;
	uint16_t configMemorySpeed;
	
	// 2.8+
	uint16_t minVoltage;
	uint16_t maxVoltage;
	uint16_t configVoltage;
};
#pragma pack(pop)

RamInfo RamProfiler::GetRamInfo(RAM_RIF_FLAGS rif, RAM_UIF_FLAGS uif, RAM_BIF_FLAGS bif) {
	RamInfo info;

	DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
	BYTE* buffer = (BYTE*)malloc(size);
	size = GetSystemFirmwareTable('RSMB', 0, buffer, size);

	BYTE* ptr = buffer;
	BYTE* end = buffer + size;

	while (ptr < end) {
		SMBIOSHeader* header = (SMBIOSHeader*)ptr;
		
		if (header->type == 16) {
			SMBIOSPhysicalMemoryArray* physArr = (SMBIOSPhysicalMemoryArray*)ptr;

			if (rif & RAM_RIF_LOCATION) {
				info.location = physArr->location;
			}
			if (rif & RAM_RIF_USE) {
				info.use = physArr->use;
			}
			if (rif & RAM_RIF_MEM_CORRECTION_ERROR) {
				info.memCorrectionError = physArr->memErrCorrection;
			}
			if (rif & RAM_RIF_MEM_ERROR_INFO_HANDLE) {
				info.memErrorInfoHandle = physArr->memErrInfoHandle;
			}
			if (rif & RAM_RIF_DEVICE_COUNT) {
				info.blockCount = physArr->numOfDevices;
			}
			if (rif & RAM_RIF_MAX_CAPACITY) {
				info.maxCapacity = physArr->maxCapacity;
			}
			if (rif & RAM_RIF_EXT_MAX_CAPACITY) {
				info.extMaxCapacity = physArr->extMaxCapacity;
			}
		}

		ptr += header->length;
		while (ptr < end && (*ptr || *(ptr + 1))) ptr++;
		ptr += 2;
	}
	if (rif & RAM_RIF_BLOCK_INFOS) {
		std::vector<RamBlockInfo> infos = GetAllRamBlockInfo(bif);
		RamBlockInfo* blocks = new RamBlockInfo[infos.size()];
		std::copy(infos.begin(), infos.end(), blocks);
		info.blocks = blocks;
	}
	if (rif & RAM_RIF_UTILIZATION_INFO) {
		info.utilizationInfo = GetRamUtilizationInfo(uif);
	}

	return info;
}
RamUtilizationInfo RamProfiler::GetRamUtilizationInfo(RAM_UIF_FLAGS uif) {
	RamUtilizationInfo info;

	MEMORYSTATUSEX mse = {0};
	mse.dwLength = sizeof(MEMORYSTATUSEX);
	
	GlobalMemoryStatusEx(&mse);

	if (uif & RAM_UIF_TOTAL_PHYSICAL_MEMORY) {
		info.totalPhysicalMemory = mse.ullTotalPhys;
	}
	if (uif & RAM_UIF_TOTAL_VIRTUAL_MEMORY) {
		info.totalVirtualMemory = mse.ullTotalVirtual;
	}
	if (uif & RAM_UIF_TOTAL_PAGE_MEMORY) {
		info.totalPageMemory = mse.ullTotalPageFile;
	}
	if (uif & RAM_UIF_AVAILABLE_PHYSICAL_MEM) {
		info.availablePhysicalMemory = mse.ullAvailPhys;
	}
	if (uif & RAM_UIF_AVAILABLE_VIRTUAL_MEM) {
		info.availableVirtualMemory = mse.ullAvailVirtual;
	}
	if (uif & RAM_UIF_AVAILABLE_PAGE_MEM) {
		info.availablePageMemory = mse.ullAvailPageFile;
	}
	if (uif & RAM_UIF_MEMORY_LOAD) {
		info.memoryLoad = mse.dwMemoryLoad;
	}

	return info;
}
std::vector<RamBlockInfo> RamProfiler::GetAllRamBlockInfo(RAM_BIF_FLAGS bif) {
	std::vector<RamBlockInfo> infos;

	DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
	BYTE* buffer = (BYTE*)malloc(size);
	GetSystemFirmwareTable('RSMB', 0, buffer, size);

	BYTE* ptr = buffer;
	BYTE* end = buffer + size;

	DWORD deviceNum;

	while (ptr < end) {
		SMBIOSHeader* header = (SMBIOSHeader*)ptr;
	
		if (header->type == 16) {
			SMBIOSPhysicalMemoryArray* physArr = (SMBIOSPhysicalMemoryArray*)ptr;
			deviceNum = physArr->numOfDevices;
		}

		if (header->type == 17) {
			for (UINT i = 0; i < deviceNum; i++){
				RamBlockInfo info;
				SMBIOSMemoryDevice* device = (SMBIOSMemoryDevice*)ptr;

				if (bif & RAM_BIF_ARR_HANDLE) {
					info.arrHandle = device->physMemArryHandle;
				}
				if (bif & RAM_BIF_ERR_INFO_HANDLE) {
					info.errInfoHandle = device->memErrInfoHandle;
				}
				if (bif & RAM_BIF_TOTAL_WIDTH) {
					info.totalWidth = device->totalWidth;
				}
				if (bif & RAM_BIF_DATA_WIDTH) {
					info.dataWidth = device->dataWidth;
				}
				if (bif & RAM_BIF_TYPE_DETAIL) {
					info.typeDetail = device->typeDetail;
				}
				if (bif & RAM_BIF_SIZE) {
					info.size = device->size;
				}
				if (bif & RAM_BIF_SPEED) {
					info.speed = device->speed;
				}
				if (bif & RAM_BIF_MIN_VOLTAGE) {
					info.minVoltage = device->minVoltage;
				}
				if (bif & RAM_BIF_MAX_VOLTAGE) {
					info.maxVoltage = device->maxVoltage;
				}
				if (bif & RAM_BIF_CONFIG_VOLTAGE) {
					info.configVoltage = device->configVoltage;
				}
				if (bif & RAM_BIF_FORM_FACTOR) {
					info.formFactor = device->formFactor;
				}
				if (bif & RAM_BIF_MEMORY_TYPE) {
					info.memoryType = device->memType;
				}
				if (bif & RAM_BIF_DEVICE_SET) {
					info.deviceSet = device->deviceSet;
				}
				if (bif & RAM_BIF_EXTENDED_SIZE) {
					info.extendedSize = device->extendedSize;
				}

				const char* offsetPtr = (const char*)(ptr + header->length);

				if (bif & RAM_BIF_DEVICE_LOCATOR) {
					std::string deviceLocatorStr;
					while (*offsetPtr != '\0') {
						deviceLocatorStr += *offsetPtr;
						offsetPtr++;
					}
					info.deviceLocator = _strdup(deviceLocatorStr.c_str());
					offsetPtr++;
				}
				if (bif & RAM_BIF_BANK_LOCATOR) {
					std::string bankLocatorStr;
					while (*offsetPtr != '\0') {
						bankLocatorStr += *offsetPtr;
						offsetPtr++;
					}
					info.bankLocator = _strdup(bankLocatorStr.c_str());
					offsetPtr++;
				}
				if (bif & RAM_BIF_VENDOR) {
					std::string vendorStr;
					while (*offsetPtr != '\0') {
						vendorStr += *offsetPtr;
						offsetPtr++;
					}
					info.vendor = _strdup(vendorStr.c_str());
				}

				infos.push_back(info);
			
				ptr += header->length;
				while (ptr < end && (*ptr || *(ptr + 1))) ptr++;
				ptr += 2;
			}

			free(buffer);
			return infos;
		}

		ptr += header->length;
		while (ptr < end && (*ptr || *(ptr + 1))) ptr++;
		ptr += 2;
	}

	free(buffer);
	return infos;
}