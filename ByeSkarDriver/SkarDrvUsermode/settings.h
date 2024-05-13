#pragma once
#include <iostream>
#include <Windows.h>

const wchar_t* cwDeviceName = L"SkarDriver";

#define cReadWrite CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define cBaseAddress CTL_CODE(FILE_DEVICE_UNKNOWN, 0x32, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define cGuardedRegion CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9C, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define cKey 0x736b6172 // hehehe ;)

bool bDebug = true; // making simple debug mode for testing and shit