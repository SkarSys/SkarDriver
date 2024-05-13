#pragma once
#include "Windows.h"
#include <iostream>
#include <TlHelp32.h>
#include "structs.h"
#include "settings.h"

namespace nMemmory {
	HANDLE hDriverHandle;
	INT32 iProcId;

	bool bFindDriver() {      
		wchar_t wDevicePath[260];
		_snwprintf_s(wDevicePath, MAX_PATH, L"\\\\.\\%s", cwDeviceName);
		hDriverHandle = CreateFileW(wDevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (!hDriverHandle || (hDriverHandle == INVALID_HANDLE_VALUE))
			return false;
		return true;
	}

	void vReadPhysical(PVOID address, PVOID buffer, DWORD size) {
		sReadWrite arguments = { 0 };

		arguments.security = cKey;
		arguments.address = (ULONGLONG)address;
		arguments.buffer = (ULONGLONG)buffer;
		arguments.size = size;
		arguments.process_id = iProcId;
		arguments.write = FALSE;

		DeviceIoControl(hDriverHandle, cReadWrite, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	void vWritePhysical(PVOID address, PVOID buffer, DWORD size) {
		sReadWrite arguments = { 0 };

		arguments.security = cKey;
		arguments.address = (ULONGLONG)address;
		arguments.buffer = (ULONGLONG)buffer;
		arguments.size = size;
		arguments.process_id = iProcId;
		arguments.write = TRUE;

		DeviceIoControl(hDriverHandle, cReadWrite, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	uintptr_t uGetImage() {
		uintptr_t image_address = { NULL };
		sBaseAddress arguments = { NULL };

		arguments.security = cKey;
		arguments.process_id = iProcId;
		arguments.address = (ULONGLONG*)&image_address;

		DeviceIoControl(hDriverHandle, cBaseAddress, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

		return image_address;
	}

	uintptr_t uGetGuardedRegion() {
		uintptr_t guarded_region_address = { NULL };
		sGuardedRegion arguments = { NULL };
		arguments.security = cKey;
		arguments.address = (ULONGLONG*)&guarded_region_address;
		DeviceIoControl(hDriverHandle, cGuardedRegion, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
		return guarded_region_address;
	}

	INT32 iGetPid(LPCTSTR process_name) {
		PROCESSENTRY32 pt;
		HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hsnap, &pt)) {
			do {
				if (!lstrcmpi(pt.szExeFile, process_name)) {
					CloseHandle(hsnap);
					iProcId = pt.th32ProcessID;
					return pt.th32ProcessID;
				}
			} while (Process32Next(hsnap, &pt));
		}
		CloseHandle(hsnap);
		return { NULL };
	}
}

template <typename T>
T tRead(uint64_t address) {
	T buffer{ };
	nMemmory::vReadPhysical((PVOID)address, &buffer, sizeof(T));
	return buffer;
}

template <typename T>
T tWrite(uint64_t address, T buffer) {
	nMemmory::vWritePhysical((PVOID)address, &buffer, sizeof(T));
	return buffer;
}