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
#include "d3d11.h"
#include "d3d9.h"
#include "dxgi1_4.h"

#include <iostream>

#pragma comment(lib, "d3d9.lib")
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
UINT64 GpuProfiler::GetGpuVRamSize() {
	IDXGIAdapter3* dxgi = nullptr;
	IDXGIFactory4* dxgiFac = nullptr;
	
	HRESULT res = CreateDXGIFactory1(__uuidof(IDXGIFactory4), (void**)&dxgiFac);

	if (FAILED(res)) {
		return 0;
	}

	res = dxgiFac->EnumAdapters(0, (IDXGIAdapter**)&dxgi);

	if (FAILED(res)) {
		return 0;
	}

	DXGI_QUERY_VIDEO_MEMORY_INFO memInfo;
	res = dxgi->QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &memInfo);

	if (FAILED(res)) {
		return 0;
	}

	return memInfo.Budget;
}
UINT64 GpuProfiler::GetGpuVRamUsage() {
	IDXGIAdapter3* dxgi = nullptr;
	IDXGIFactory4* dxgiFac = nullptr;

	HRESULT res = CreateDXGIFactory1(__uuidof(IDXGIFactory4), (void**)&dxgiFac);

	if (FAILED(res)) {
		return 0;
	}

	res = dxgiFac->EnumAdapters(0, (IDXGIAdapter**)&dxgi);

	if (FAILED(res)) {
		return 0;
	}

	DXGI_QUERY_VIDEO_MEMORY_INFO memInfo;
	res = dxgi->QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &memInfo);

	if (FAILED(res)) {
		return 0;
	}

	return memInfo.CurrentUsage;
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