#include "definitions.hpp"
#include "config.hpp"


#define ReadWrite_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define BaseAddress_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
ULONGLONG DtbM;

NTSTATUS BaseAddress_Request(pBaseAddrQUR oprq) {
	if (!oprq->ProcID)
		return STATUS_UNSUCCESSFUL;
	PEPROCESS targetProces = NULL;
	__(PsLookupProcessByProcessId)((HANDLE)oprq->ProcID, &targetProces);
	if (!targetProces)
		return STATUS_UNSUCCESSFUL;
	ULONGLONG baseAddress = (ULONGLONG)__(PsGetProcessSectionBaseAddress)(targetProces);
	if (!baseAddress)
		return STATUS_UNSUCCESSFUL;
	memcpy(oprq->TargetPtr, &baseAddress, sizeof(baseAddress));
	__(ObfDereferenceObject)(targetProces);
	RefreshCR3 = true;
	return STATUS_SUCCESS;
}

NTSTATUS ReadWrite_Request(pRWOp oprq) {
	if (!oprq->ProcessID) {
		return STATUS_UNSUCCESSFUL;
	}
	PEPROCESS targetprocc = NULL;
	__(PsLookupProcessByProcessId)((HANDLE)oprq->ProcessID, &targetprocc);
	if (!targetprocc) {
		return STATUS_UNSUCCESSFUL;
	}
	SIZE_T opSize = (oprq->Size);
	INT64 PhyiscalAddress;
	if (oprq->CR3) {
		PhyiscalAddress = TranslateE(DtbM, (ULONG64)(oprq->Address));
		if (!PhyiscalAddress) {
			if (RefreshCR3) {
				DtbM = GetDTB((void*)__(PsGetProcessSectionBaseAddress)(targetprocc));
				RefreshCR3 = false;
				PhyiscalAddress = TranslateE(DtbM, (ULONG64)(oprq->Address));
				if (!PhyiscalAddress) {
					return STATUS_UNSUCCESSFUL;
				}
			}
			else {
				return STATUS_UNSUCCESSFUL;
			}
		}
	}
	else {
		uintptr_t process_dirbase = *(uintptr_t*)((PUCHAR)targetprocc + 0x28); //thisll fail idek why im putting it here
		if (process_dirbase == 0)
		{
			ULONG user_diroffset = Winver_fetch();
			process_dirbase = *(uintptr_t*)((PUCHAR)targetprocc + user_diroffset);
		}
		PhyiscalAddress = TranslateB(process_dirbase, oprq->Address);
		if (!PhyiscalAddress) {
			return STATUS_UNSUCCESSFUL;
		}
	}
	ULONG64 finaloperatioonszcie = FIND_MIN(PAGE_SIZE - (PhyiscalAddress & 0xFFF), opSize);
	SIZE_T bytesproc = NULL;
	if (oprq->Write) {
		WW(PVOID(PhyiscalAddress), (PVOID)((ULONG64)(oprq->Buffer)), finaloperatioonszcie, &bytesproc);
	}
	else {
		RR(PVOID(PhyiscalAddress), (PVOID)((ULONG64)(oprq->Buffer)), finaloperatioonszcie, &bytesproc);
	}
    return STATUS_SUCCESS;
}


NTSTATUS ioctrl(PDEVICE_OBJECT devObj, PIRP irpRequest) {
	UNREFERENCED_PARAMETER(devObj);
	NTSTATUS ioStatus = { 0 };
	ULONG bytesHandled = { 0 };
	PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(irpRequest);
	ULONG ioCode = stackLocation->Parameters.DeviceIoControl.IoControlCode;
	ULONG inputSize = stackLocation->Parameters.DeviceIoControl.InputBufferLength;
	if (ioCode == ReadWrite_code) {
		if (inputSize == sizeof(RWOp)) {
			pRWOp memRequest = (pRWOp)(irpRequest->AssociatedIrp.SystemBuffer);
			ioStatus = ReadWrite_Request(memRequest);
			bytesHandled = sizeof(RWOp);
		}
		else {
			ioStatus = STATUS_INFO_LENGTH_MISMATCH;
			bytesHandled = 0;
		}
	}
	else if (ioCode == BaseAddress_code) {
		if (inputSize == sizeof(BaseAddrQUR)) {
			pBaseAddrQUR baseAddrRequest = (pBaseAddrQUR)(irpRequest->AssociatedIrp.SystemBuffer);
			ioStatus = BaseAddress_Request(baseAddrRequest);
			bytesHandled = sizeof(BaseAddrQUR);
		}
		else {
			ioStatus = STATUS_INFO_LENGTH_MISMATCH;
			bytesHandled = 0;
		}
	}
	irpRequest->IoStatus.Status = ioStatus;
	irpRequest->IoStatus.Information = bytesHandled;
	IofCompleteRequest(irpRequest, IO_NO_INCREMENT);
	return ioStatus;
}

#ifdef sc_start
NTSTATUS DriverEntry(PDRIVER_OBJECT driverObj, PUNICODE_STRING RegPath)
#else
NTSTATUS DriverInitialization(PDRIVER_OBJECT driverObj, PUNICODE_STRING RegPath)
#endif
{
	UNREFERENCED_PARAMETER(RegPath);
	NTSTATUS statusResult = { };
	PDEVICE_OBJECT deviceObj = { };

	__(RtlInitUnicodeString)(&DeviceN, skCrypt(L"\\Device\\" DRVLink));
	__(RtlInitUnicodeString)(&DosL, skCrypt(L"\\DosDevices\\" DRVLink));

	statusResult = __(IoCreateDevice)(driverObj, 0, &DeviceN, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObj);

	if (!NT_SUCCESS(statusResult))
		return statusResult;

	statusResult = __(IoCreateSymbolicLink)(&DosL, &DeviceN);

	if (!NT_SUCCESS(statusResult))
		return statusResult;

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		driverObj->MajorFunction[i] = &Request_Not_Supported;

	deviceObj->Flags |= DO_BUFFERED_IO;

	driverObj->MajorFunction[IRP_MJ_CREATE] = &Request_Dispatch;
	driverObj->MajorFunction[IRP_MJ_CLOSE] = &Request_Dispatch;
	driverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &ioctrl;
	driverObj->DriverUnload = &DriverUnloading;
	deviceObj->Flags &= ~DO_DEVICE_INITIALIZING;
	_UNICODE_STRING unicode_Drvname;
	__(RtlInitUnicodeString)(&unicode_Drvname, DRVLink);

#ifdef sc_start
	
	__try {
		PLDR_DATA_TABLE_ENTRY currEntry = (PLDR_DATA_TABLE_ENTRY)(driverObj->DriverSection);
		PLDR_DATA_TABLE_ENTRY startEntry = currEntry;

		while ((PLDR_DATA_TABLE_ENTRY)(currEntry->InLoadOrderLinks.Flink) != startEntry) {
			if (!(ULONG)currEntry->EntryPoint > MmUserProbeAddress) {
				currEntry = (PLDR_DATA_TABLE_ENTRY)(currEntry->InLoadOrderLinks.Flink);
				continue;
			}
			if (__(wcsstr)(currEntry->BaseDllName.Buffer, DRVLink)) {
				currEntry->BaseDllName.Length = 0;
				return STATUS_SUCCESS;
			}
			currEntry = (PLDR_DATA_TABLE_ENTRY)(currEntry->InLoadOrderLinks.Flink);
		}
		return STATUS_UNSUCCESSFUL;
	}
	__except (1) {
		return STATUS_UNSUCCESSFUL;
	}
#else

#ifdef Clean_PiDDBCacheTable
	piddbcache(unicode_Drvname, randint_except_its_a_ulong(12000000, 16000000));
#endif

#endif
#ifdef Clean_Mmu
	Mmu(unicode_Drvname);
#endif
#ifdef Clean_Hashbucket
	Hashbucket(unicode_Drvname);
#endif
	//Depending on machine cleaning these can bsod so you need to play around with cfg
	return statusResult;
}

#ifndef sc_start
NTSTATUS DriverEntry() {
	return __(IoCreateDriver)(0, &DriverInitialization);
}
#endif