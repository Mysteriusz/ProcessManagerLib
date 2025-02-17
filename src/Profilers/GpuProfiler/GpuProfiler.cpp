#pragma once

// PROFILERS
#include "GpuProfiler.h"

// STRUCTS
#include "GpuInfo.h"

// LIBS
#include "CpuNt.h"
#include "CpuFlags.h"
#include "TypesNt.h"
#include "windows.h"
#include "string.h"
#include "d3d12.h"
#include "d3d9.h"
#include "dxgi1_6.h"

#include <nvml.h>

#include <iostream>

#pragma comment(lib, "nvml.lib")
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")

using namespace ProfilingLib::Profilers;

std::string GpuProfiler::GetGpuName() {
	IDirect3D9Ex* dx3d = nullptr;
	IDirect3DDevice9Ex* dx3dDevice = nullptr;

	HRESULT res = Direct3DCreate9Ex(D3D_SDK_VERSION, &dx3d);

	if (FAILED(res)) {
		return "N/A";
	}

	D3DADAPTER_IDENTIFIER9 dx3dIden;
	res = dx3d->GetAdapterIdentifier(0, 0, &dx3dIden);

	return dx3dIden.Description;
}
std::string GpuProfiler::GetGpuVendor() {
	IDirect3D9Ex* dx3d = nullptr;
	IDirect3DDevice9Ex* dx3dDevice = nullptr;

	HRESULT res = Direct3DCreate9Ex(D3D_SDK_VERSION, &dx3d);

	if (FAILED(res)) {
		return "N/A";
	}

	D3DADAPTER_IDENTIFIER9 dx3dIden;
	res = dx3d->GetAdapterIdentifier(0, 0, &dx3dIden);

	switch (dx3dIden.VendorId){
		case 0x10DE:
			return "NVIDIA";
		case 0x1002:
			return "AMD";
		case 0x8086:
			return "INTEL";
		case 0x1043:
			return "ASUSTEK";
		case 0x106B:
			return "APPLE";
		default:
			return "UNKNOWN";
	}
}
std::string GpuProfiler::GetGpuDriverName() {
	IDirect3D9Ex* dx3d = nullptr;
	IDirect3DDevice9Ex* dx3dDevice = nullptr;

	HRESULT res = Direct3DCreate9Ex(D3D_SDK_VERSION, &dx3d);

	if (FAILED(res)) {
		return "N/A";
	}

	D3DADAPTER_IDENTIFIER9 dx3dIden;
	res = dx3d->GetAdapterIdentifier(0, 0, &dx3dIden);

	return dx3dIden.Driver;
}
std::string GpuProfiler::GetGpuDXVersion() {
	IDXGIFactory6* dxgi = nullptr;

	HRESULT res = CreateDXGIFactory1(IID_PPV_ARGS(&dxgi));

	if (FAILED(res)) {
		return "N/A";
	}

	IDXGIAdapter1* adapter = nullptr;

	std::string ver;

	dxgi->EnumAdapters1(0, &adapter);

	DXGI_ADAPTER_DESC1 desc;
	adapter->GetDesc1(&desc);

	ID3D12Device* pDevice = nullptr;
	if (SUCCEEDED(D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_12_2, IID_PPV_ARGS(&pDevice)))) {
		ver = "12.2";
	}
	else if (SUCCEEDED(D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_12_1, IID_PPV_ARGS(&pDevice)))) {
		ver = "12.1";
	}
	else if (SUCCEEDED(D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_12_0, IID_PPV_ARGS(&pDevice)))) {
		ver = "12.0";
	}
	else if (SUCCEEDED(D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_11_1, IID_PPV_ARGS(&pDevice)))) {
		ver = "11.1";
	}
	else if (SUCCEEDED(D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&pDevice)))) {
		ver = "11.0";
	}
	else if (SUCCEEDED(D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_10_1, IID_PPV_ARGS(&pDevice)))) {
		ver = "10.1";
	}
	else if (SUCCEEDED(D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_10_0, IID_PPV_ARGS(&pDevice)))) {
		ver = "10.0";
	}
	else if (SUCCEEDED(D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_9_3, IID_PPV_ARGS(&pDevice)))) {
		ver = "9.3";
	}
	else if (SUCCEEDED(D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_9_2, IID_PPV_ARGS(&pDevice)))) {
		ver = "9.2";
	}
	else if (SUCCEEDED(D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_9_1, IID_PPV_ARGS(&pDevice)))) {
		ver = "9.1";
	}
	else {
		ver = "UNKNOWN";
	}

	if (pDevice) {
		pDevice->Release();
		adapter->Release();
	}

	dxgi->Release();
	return ver;
}

UINT64 GpuProfiler::GetGpuDriverVersion() {
	IDirect3D9Ex* dx3d = nullptr;
	IDirect3DDevice9Ex* dx3dDevice = nullptr;

	HRESULT res = Direct3DCreate9Ex(D3D_SDK_VERSION, &dx3d);

	if (FAILED(res)) {
		return 0;
	}

	D3DADAPTER_IDENTIFIER9 dx3dIden;
	res = dx3d->GetAdapterIdentifier(0, 0, &dx3dIden);

	return dx3dIden.DriverVersion.QuadPart;
}

DOUBLE GpuProfiler::GetGpuVRamSize() {
	nvmlInit();

	nvmlDevice_t device;
	nvmlMemory_t memoryInfo;

	DOUBLE usage = 0.0;

	nvmlDeviceGetHandleByIndex(0, &device);
	nvmlDeviceGetMemoryInfo(device, &memoryInfo);

	usage += memoryInfo.total;

	nvmlShutdown();

	return usage / (1024 * 1024 * 1024);
}
DOUBLE GpuProfiler::GetGpuVRamUsage() {
	nvmlInit();

	UINT deviceCount;
	nvmlDevice_t device;
	nvmlMemory_t memoryInfo;

	nvmlDeviceGetCount(&deviceCount);

	DOUBLE usage = 0.0;

	for (UINT i = 0; i < deviceCount; ++i) {
		nvmlDeviceGetHandleByIndex(i, &device);
		nvmlDeviceGetMemoryInfo(device, &memoryInfo);

		usage += memoryInfo.used;
	}

	nvmlShutdown();

	return usage / (1024 * 1024 * 1024);
}	 

UINT GpuProfiler::GetGpuID() {
	IDirect3D9Ex* dx3d = nullptr;
	IDirect3DDevice9Ex* dx3dDevice = nullptr;

	HRESULT res = Direct3DCreate9Ex(D3D_SDK_VERSION, &dx3d);

	if (FAILED(res)) {
		return 0;
	}

	D3DADAPTER_IDENTIFIER9 dx3dIden;
	res = dx3d->GetAdapterIdentifier(0, 0, &dx3dIden);

	return dx3dIden.DeviceId;
}
UINT GpuProfiler::GetGpuRevision() {
	IDirect3D9Ex* dx3d = nullptr;
	IDirect3DDevice9Ex* dx3dDevice = nullptr;

	HRESULT res = Direct3DCreate9Ex(D3D_SDK_VERSION, &dx3d);

	if (FAILED(res)) {
		return 0;
	}

	D3DADAPTER_IDENTIFIER9 dx3dIden;
	res = dx3d->GetAdapterIdentifier(0, 0, &dx3dIden);

	return dx3dIden.Revision;
}

GpuInfo GpuProfiler::GetGpuInfo(GPU_GIF_FLAGS gif, GPU_MIF_FLAGS mif, GPU_UIF_FLAGS uif, GPU_PIF_FLAGS pif, GPU_RIF_FLAGS rif){
	GpuInfo info;
	
	if (gif & GPU_GIF_DX_SUPPORT) {
		info.dxSupport = _strdup(GetGpuDXVersion().c_str());
	}
	if (gif & GPU_GIF_MIN_RES) {
		info.maxResInfo = GetGpuMaxResolutionInfo(rif);
	}
	if (gif & GPU_GIF_MAX_RES) {
		info.maxResInfo = GetGpuMinResolutionInfo(rif);
	}
	if (gif & GPU_GIF_MODEL_INFO) {
		info.modelInfo = GetGpuModelInfo(mif);
	}
	if (gif & GPU_GIF_UTILIZATION) {
		info.utilInfo = GetGpuUtilizationInfo(uif);
	}

	if (gif & GPU_GIF_VRAM_USAGE) {
		info.vRamUsage = GetGpuVRamUsage();
	}

	if (gif & GPU_GIF_VRAM_SIZE) {
		info.vRamSize = GetGpuVRamSize();
	}

	return info;
}
GpuPhysicalInfo GpuProfiler::GetGpuPhysicalInfo(GPU_PIF_FLAGS pif) {
	GpuPhysicalInfo info;

	nvmlDevice_t device;
	nvmlDeviceGetHandleByIndex(0, &device);

	nvmlPciInfo_t pciInfo;
	nvmlDeviceGetPciInfo(device, &pciInfo);

	// Check the flags and assign only the requested info
	if (pif & GPU_PIF_BUS) {
		info.bus = pciInfo.bus;
	}

	if (pif & GPU_PIF_BUS_ID) {
		info.busId = pciInfo.busId;
	}

	if (pif & GPU_PIF_LEGACY_BUS_ID) {
		info.legacyBusId = pciInfo.busIdLegacy;
	}

	if (pif & GPU_PIF_DEVICE_ID) {
		info.deviceId = pciInfo.device;
	}

	if (pif & GPU_PIF_PCI_DEVICE_ID) {
		info.pciDeviceId = pciInfo.pciDeviceId;
	}

	if (pif & GPU_PIF_SUBSYS_DEVICE_ID) {
		info.subSysDeviceId = pciInfo.pciSubSystemId;
	}

	if (pif & GPU_PIF_DOMAIN) {
		info.domain = pciInfo.domain;
	}

	return info;
}
GpuModelInfo GpuProfiler::GetGpuModelInfo(GPU_MIF_FLAGS mif) {
	GpuModelInfo info;

	// Check the flags and assign only the requested info
	if (mif & GPU_MIF_NAME) {
		info.name = _strdup(GetGpuName().c_str());
	}

	if (mif & GPU_MIF_VENDOR) {
		info.vendor = _strdup(GetGpuVendor().c_str());
	}

	if (mif & GPU_MIF_DRIVER_NAME) {
		info.driverName = _strdup(GetGpuDriverName().c_str());
	}

	if (mif & GPU_MIF_DRIVER_VERSION) {
		info.driverVersion = GetGpuDriverVersion();
	}

	if (mif & GPU_MIF_ID) {
		info.id = GetGpuID();
	}

	if (mif & GPU_MIF_REVISION) {
		info.revision = GetGpuRevision();
	}

	return info;
}
GpuUtilizationInfo GpuProfiler::GetGpuUtilizationInfo(GPU_UIF_FLAGS uif) {
	GpuUtilizationInfo info;

	nvmlDevice_t device;
	nvmlUtilization_t utilization;

	UINT copyUtil;
	UINT encUtil;
	UINT decUtil;
	UINT encInstCount;
	UINT decInstCount;

	nvmlInit();

	nvmlDeviceGetHandleByIndex(0, &device);

	// Retrieve utilization data
	nvmlDeviceGetUtilizationRates(device, &utilization);
	nvmlDeviceGetEncoderUtilization(device, &encUtil, &encInstCount);
	nvmlDeviceGetDecoderUtilization(device, &decUtil, &decInstCount);

	nvmlMemory_t memInfo;
	nvmlDeviceGetMemoryInfo(device, &memInfo);
	copyUtil = static_cast<UINT>((memInfo.used * 100) / memInfo.total);

	// Check the flags and assign only the requested info
	if (uif & GPU_UIF_UTILIZATION) {
		info.utilization = utilization.gpu;
	}

	if (uif & GPU_UIF_VIDEO_ENCODE) {
		info.videoEncode = encUtil;
	}

	if (uif & GPU_UIF_VIDEO_DECODE) {
		info.videoDecode = decUtil;
	}

	if (uif & GPU_UIF_COPY) {
		info.copy = copyUtil;
	}

	return info;
}
GpuResolutionInfo GpuProfiler::GetGpuMaxResolutionInfo(GPU_RIF_FLAGS rif) {
	DEVMODE dev = {};

	UINT num = 0;

	GpuResolutionInfo info;
	UINT wid = 0;
	UINT hei = 0;

	while (EnumDisplaySettings(nullptr, num, &dev)) {
		if (dev.dmPelsWidth > wid || dev.dmPelsHeight > hei) {
			wid = dev.dmPelsWidth;
			hei = dev.dmPelsHeight;
		}
		num++;
	}

	if (rif & GPU_RIF_WIDTH) {
		info.width = wid;
	}
	if (rif & GPU_RIF_HEIGHT) {
		info.height = hei;
	}

	return info;
}
GpuResolutionInfo GpuProfiler::GetGpuMinResolutionInfo(GPU_RIF_FLAGS rif) {
	DEVMODE dev = {};

	UINT num = 0;

	GpuResolutionInfo info;
	UINT wid = UINT_MAX;
	UINT hei = UINT_MAX;

	while (EnumDisplaySettings(nullptr, num, &dev)) {
		if (dev.dmPelsWidth < wid || dev.dmPelsHeight < hei) {
			wid = dev.dmPelsWidth;
			hei = dev.dmPelsHeight;
		}
		num++;
	}

	if (rif & GPU_RIF_WIDTH) {
		info.width = wid;
	}
	if (rif & GPU_RIF_HEIGHT) {
		info.height = hei;
	}

	return info;
}