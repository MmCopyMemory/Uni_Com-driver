#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>

#define ReadWrite_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define BaseAddress_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


typedef struct _RWOp
{
	INT32 ProcessID;
	ULONGLONG Address, Buffer, Size;
	BOOLEAN Write;
	BOOLEAN CR3;
} RWOp, * pRWOp;

typedef struct _BaseAddrQUR
{
	INT32 ProcID;
	ULONGLONG* TargetPtr;
} BaseAddrQUR, * pBaseAddrQUR;

namespace drv {
	bool eac = false;
	INT32 procid;
	HANDLE DrvHandle;

	bool Init(bool EAC = false) {
		eac = EAC;
		DrvHandle = CreateFileA("\\\\.\\T85KFKUWTP", GENERIC_READ | GENERIC_WRITE, 0, 0, 3, 0x00000080, 0);
		if (!DrvHandle) {
			return false;
		}
		return true;
	}

	void ReadPhys(PVOID address, PVOID buffer, DWORD size)
	{
		_RWOp Arguments = { 0 };
		Arguments.Address = (ULONGLONG)address;
		Arguments.Buffer = (ULONGLONG)buffer;
		Arguments.Size = size;
		Arguments.ProcessID = procid;
		Arguments.Write = false;
		Arguments.CR3 = eac;

		DeviceIoControl(DrvHandle, ReadWrite_code, &Arguments, sizeof(Arguments), nullptr, NULL, NULL, NULL);
	}

	void WritePhys(PVOID address, PVOID buffer, DWORD size)
	{
		_RWOp Arguments = { 0 };
		Arguments.Address = (ULONGLONG)address;
		Arguments.Buffer = (ULONGLONG)buffer;
		Arguments.Size = size;
		Arguments.ProcessID = procid;
		Arguments.Write = true;
		Arguments.CR3 = eac;

		DeviceIoControl(DrvHandle, ReadWrite_code, &Arguments, sizeof(Arguments), nullptr, NULL, NULL, NULL);
	}
	uintptr_t GetBase()
	{
		uintptr_t image_address = { NULL };
		_BaseAddrQUR Arguments = { NULL };

		Arguments.ProcID = procid;
		Arguments.TargetPtr = (ULONGLONG*)&image_address;
		DeviceIoControl(DrvHandle, BaseAddress_code, &Arguments, sizeof(Arguments), nullptr, NULL, NULL, NULL);

		return image_address;
	}
	inline INT32 FindProcess(LPCTSTR process_name)
	{

		PROCESSENTRY32 pt;
		HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hsnap, &pt)) {
			do {
				if (!lstrcmpi(pt.szExeFile, process_name))
				{
					CloseHandle(hsnap);
					procid = pt.th32ProcessID;
					return pt.th32ProcessID;
				}
			} while (Process32Next(hsnap, &pt));
		}

		CloseHandle(hsnap);
		return procid;
	}
}

template <typename T>
inline T read(uint64_t address)
{
	T buffer{ };
	drv::ReadPhys((PVOID)address, &buffer, sizeof(T));
	return buffer;
}

template <typename T>
inline T write(uint64_t address, T buffer)
{
	drv::WritePhys((PVOID)address, &buffer, sizeof(T));
	return buffer;
}