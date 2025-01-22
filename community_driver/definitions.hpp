#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <strsafe.h>
#include <intrin.h>
#include <windef.h>
#include <cstdint>
#include <ntdef.h>
#include <basetsd.h>
#include <ntddmou.h>
#include "KLI.hpp"
#include "SkCrypt.hpp"


bool RefreshCR3 = false; //dont touch this!

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

static const UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull;

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
	_In_ PUNICODE_STRING ObjectName,
	_In_ ULONG Attributes,
	_In_opt_ PACCESS_STATE AccessState,
	_In_opt_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_Inout_opt_ PVOID ParseContext,
	_Out_ PVOID* Object
);

#define POOL_TAG 'oamL'
typedef struct _SYSTEM_BIGPOOL_ENTRY {
	PVOID VirtualAddress;
	ULONG_PTR NonPaged : 1;
	ULONG_PTR SizeInBytes;
	UCHAR Tag[4];
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

uintptr_t dereferenceB(uintptr_t address, unsigned int offset) {
	if (address == 0)
		return 0;

	return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS;
typedef struct _SYSTEM_MODULE
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

typedef union _virt_addr_t
{
	void* value;
	struct
	{
		uintptr_t offset : 12;
		uintptr_t pt_index : 9;
		uintptr_t pd_index : 9;
		uintptr_t pdpt_index : 9;
		uintptr_t pml4_index : 9;
		uintptr_t reserved : 16;
	};
} virt_addr_t, * pvirt_addr_t;
typedef struct _MI_ACTIVE_PFN
{
	union
	{
		struct
		{
			struct /* bitfield */
			{
				/* 0x0000 */ unsigned __int64 Tradable : 1; /* bit position: 0 */
				/* 0x0000 */ unsigned __int64 NonPagedBuddy : 43; /* bit position: 1 */
			}; /* bitfield */
		} /* size: 0x0008 */ Leaf;
		struct
		{
			struct /* bitfield */
			{
				/* 0x0000 */ unsigned __int64 Tradable : 1; /* bit position: 0 */
				/* 0x0000 */ unsigned __int64 WsleAge : 3; /* bit position: 1 */
				/* 0x0000 */ unsigned __int64 OldestWsleLeafEntries : 10; /* bit position: 4 */
				/* 0x0000 */ unsigned __int64 OldestWsleLeafAge : 3; /* bit position: 14 */
				/* 0x0000 */ unsigned __int64 NonPagedBuddy : 43; /* bit position: 17 */
			}; /* bitfield */
		} /* size: 0x0008 */ PageTable;
		/* 0x0000 */ unsigned __int64 EntireActiveField;
	}; /* size: 0x0008 */
} MI_ACTIVE_PFN, * PMI_ACTIVE_PFN; /* size: 0x0008 */

typedef struct _MMPTE_HARDWARE
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 Dirty1 : 1; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 Owner : 1; /* bit position: 2 */
		/* 0x0000 */ unsigned __int64 WriteThrough : 1; /* bit position: 3 */
		/* 0x0000 */ unsigned __int64 CacheDisable : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Accessed : 1; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Dirty : 1; /* bit position: 6 */
		/* 0x0000 */ unsigned __int64 LargePage : 1; /* bit position: 7 */
		/* 0x0000 */ unsigned __int64 Global : 1; /* bit position: 8 */
		/* 0x0000 */ unsigned __int64 CopyOnWrite : 1; /* bit position: 9 */
		/* 0x0000 */ unsigned __int64 Unused : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 Write : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 PageFrameNumber : 40; /* bit position: 12 */
		/* 0x0000 */ unsigned __int64 ReservedForSoftware : 4; /* bit position: 52 */
		/* 0x0000 */ unsigned __int64 WsleAge : 4; /* bit position: 56 */
		/* 0x0000 */ unsigned __int64 WsleProtection : 3; /* bit position: 60 */
		/* 0x0000 */ unsigned __int64 NoExecute : 1; /* bit position: 63 */
	}; /* bitfield */
} MMPTE_HARDWARE, * PMMPTE_HARDWARE; /* size: 0x0008 */

typedef struct _MMPTE_PROTOTYPE
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 DemandFillProto : 1; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 HiberVerifyConverted : 1; /* bit position: 2 */
		/* 0x0000 */ unsigned __int64 ReadOnly : 1; /* bit position: 3 */
		/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 Combined : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 Unused1 : 4; /* bit position: 12 */
		/* 0x0000 */ __int64 ProtoAddress : 48; /* bit position: 16 */
	}; /* bitfield */
} MMPTE_PROTOTYPE, * PMMPTE_PROTOTYPE; /* size: 0x0008 */

typedef struct _MMPTE_SOFTWARE
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 PageFileReserved : 1; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 PageFileAllocated : 1; /* bit position: 2 */
		/* 0x0000 */ unsigned __int64 ColdPage : 1; /* bit position: 3 */
		/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 PageFileLow : 4; /* bit position: 12 */
		/* 0x0000 */ unsigned __int64 UsedPageTableEntries : 10; /* bit position: 16 */
		/* 0x0000 */ unsigned __int64 ShadowStack : 1; /* bit position: 26 */
		/* 0x0000 */ unsigned __int64 Unused : 5; /* bit position: 27 */
		/* 0x0000 */ unsigned __int64 PageFileHigh : 32; /* bit position: 32 */
	}; /* bitfield */
} MMPTE_SOFTWARE, * PMMPTE_SOFTWARE; /* size: 0x0008 */

typedef struct _MMPTE_TIMESTAMP
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 MustBeZero : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 Unused : 3; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 PageFileLow : 4; /* bit position: 12 */
		/* 0x0000 */ unsigned __int64 Reserved : 16; /* bit position: 16 */
		/* 0x0000 */ unsigned __int64 GlobalTimeStamp : 32; /* bit position: 32 */
	}; /* bitfield */
} MMPTE_TIMESTAMP, * PMMPTE_TIMESTAMP; /* size: 0x0008 */

typedef struct _MMPTE_TRANSITION
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 Write : 1; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 Spare : 1; /* bit position: 2 */
		/* 0x0000 */ unsigned __int64 IoTracker : 1; /* bit position: 3 */
		/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 PageFrameNumber : 40; /* bit position: 12 */
		/* 0x0000 */ unsigned __int64 Unused : 12; /* bit position: 52 */
	}; /* bitfield */
} MMPTE_TRANSITION, * PMMPTE_TRANSITION; /* size: 0x0008 */

typedef struct _MMPTE_SUBSECTION
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 Unused0 : 3; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 ColdPage : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 Unused1 : 3; /* bit position: 12 */
		/* 0x0000 */ unsigned __int64 ExecutePrivilege : 1; /* bit position: 15 */
		/* 0x0000 */ __int64 SubsectionAddress : 48; /* bit position: 16 */
	}; /* bitfield */
} MMPTE_SUBSECTION, * PMMPTE_SUBSECTION; /* size: 0x0008 */

typedef struct _MMPTE_LIST
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 OneEntry : 1; /* bit position: 1 */
		/* 0x0000 */ unsigned __int64 filler0 : 2; /* bit position: 2 */
		/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
		/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
		/* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
		/* 0x0000 */ unsigned __int64 filler1 : 16; /* bit position: 12 */
		/* 0x0000 */ unsigned __int64 NextEntry : 36; /* bit position: 28 */
	}; /* bitfield */
} MMPTE_LIST, * PMMPTE_LIST; /* size: 0x0008 */

typedef struct _MMPTE
{
	union
	{
		union
		{
			/* 0x0000 */ unsigned __int64 Long;
			/* 0x0000 */ volatile unsigned __int64 VolatileLong;
			/* 0x0000 */ struct _MMPTE_HARDWARE Hard;
			/* 0x0000 */ struct _MMPTE_PROTOTYPE Proto;
			/* 0x0000 */ struct _MMPTE_SOFTWARE Soft;
			/* 0x0000 */ struct _MMPTE_TIMESTAMP TimeStamp;
			/* 0x0000 */ struct _MMPTE_TRANSITION Trans;
			/* 0x0000 */ struct _MMPTE_SUBSECTION Subsect;
			/* 0x0000 */ struct _MMPTE_LIST List;
		}; /* size: 0x0008 */
	} /* size: 0x0008 */ u;
} MMPTE, * PMMPTE; /* size: 0x0008 */

typedef struct _MIPFNBLINK
{
	union
	{
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned __int64 Blink : 40; /* bit position: 0 */
			/* 0x0000 */ unsigned __int64 NodeBlinkLow : 19; /* bit position: 40 */
			/* 0x0000 */ unsigned __int64 TbFlushStamp : 3; /* bit position: 59 */
			/* 0x0000 */ unsigned __int64 PageBlinkDeleteBit : 1; /* bit position: 62 */
			/* 0x0000 */ unsigned __int64 PageBlinkLockBit : 1; /* bit position: 63 */
		}; /* bitfield */
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned __int64 ShareCount : 62; /* bit position: 0 */
			/* 0x0000 */ unsigned __int64 PageShareCountDeleteBit : 1; /* bit position: 62 */
			/* 0x0000 */ unsigned __int64 PageShareCountLockBit : 1; /* bit position: 63 */
		}; /* bitfield */
		/* 0x0000 */ unsigned __int64 EntireField;
		/* 0x0000 */ volatile __int64 Lock;
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned __int64 LockNotUsed : 62; /* bit position: 0 */
			/* 0x0000 */ unsigned __int64 DeleteBit : 1; /* bit position: 62 */
			/* 0x0000 */ unsigned __int64 LockBit : 1; /* bit position: 63 */
		}; /* bitfield */
	}; /* size: 0x0008 */
} MIPFNBLINK, * PMIPFNBLINK; /* size: 0x0008 */

typedef struct _MMPFNENTRY1
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned char PageLocation : 3; /* bit position: 0 */
		/* 0x0000 */ unsigned char WriteInProgress : 1; /* bit position: 3 */
		/* 0x0000 */ unsigned char Modified : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned char ReadInProgress : 1; /* bit position: 5 */
		/* 0x0000 */ unsigned char CacheAttribute : 2; /* bit position: 6 */
	}; /* bitfield */
} MMPFNENTRY1, * PMMPFNENTRY1; /* size: 0x0001 */

typedef struct _MMPFNENTRY3
{
	struct /* bitfield */
	{
		/* 0x0000 */ unsigned char Priority : 3; /* bit position: 0 */
		/* 0x0000 */ unsigned char OnProtectedStandby : 1; /* bit position: 3 */
		/* 0x0000 */ unsigned char InPageError : 1; /* bit position: 4 */
		/* 0x0000 */ unsigned char SystemChargedPage : 1; /* bit position: 5 */
		/* 0x0000 */ unsigned char RemovalRequested : 1; /* bit position: 6 */
		/* 0x0000 */ unsigned char ParityError : 1; /* bit position: 7 */
	}; /* bitfield */
} MMPFNENTRY3, * PMMPFNENTRY3; /* size: 0x0001 */

typedef struct _MI_PFN_ULONG5
{
	union
	{
		/* 0x0000 */ unsigned long EntireField;
		struct
		{
			struct /* bitfield */
			{
				/* 0x0000 */ unsigned long NodeBlinkHigh : 21; /* bit position: 0 */
				/* 0x0000 */ unsigned long NodeFlinkMiddle : 11; /* bit position: 21 */
			}; /* bitfield */
		} /* size: 0x0004 */ StandbyList;
		struct
		{
			/* 0x0000 */ unsigned char ModifiedListBucketIndex : 4; /* bit position: 0 */
		} /* size: 0x0001 */ MappedPageList;
		struct
		{
			struct /* bitfield */
			{
				/* 0x0000 */ unsigned char AnchorLargePageSize : 2; /* bit position: 0 */
				/* 0x0000 */ unsigned char Spare1 : 6; /* bit position: 2 */
			}; /* bitfield */
			/* 0x0001 */ unsigned char ViewCount;
			/* 0x0002 */ unsigned short Spare2;
		} /* size: 0x0004 */ Active;
	}; /* size: 0x0004 */
} MI_PFN_ULONG5, * PMI_PFN_ULONG5; /* size: 0x0004 */

typedef struct _MMPFN
{
	union
	{
		/* 0x0000 */ struct _LIST_ENTRY ListEntry;
		/* 0x0000 */ struct _RTL_BALANCED_NODE TreeNode;
		struct
		{
			union
			{
				union
				{
					/* 0x0000 */ struct _SINGLE_LIST_ENTRY NextSlistPfn;
					/* 0x0000 */ void* Next;
					struct /* bitfield */
					{
						/* 0x0000 */ unsigned __int64 Flink : 40; /* bit position: 0 */
						/* 0x0000 */ unsigned __int64 NodeFlinkLow : 24; /* bit position: 40 */
					}; /* bitfield */
					/* 0x0000 */ struct _MI_ACTIVE_PFN Active;
				}; /* size: 0x0008 */
			} /* size: 0x0008 */ u1;
			union
			{
				/* 0x0008 */ struct _MMPTE* PteAddress;
				/* 0x0008 */ unsigned __int64 PteLong;
			}; /* size: 0x0008 */
			/* 0x0010 */ struct _MMPTE OriginalPte;
		}; /* size: 0x0018 */
	}; /* size: 0x0018 */
	/* 0x0018 */ struct _MIPFNBLINK u2;
	union
	{
		union
		{
			struct
			{
				/* 0x0020 */ unsigned short ReferenceCount;
				/* 0x0022 */ struct _MMPFNENTRY1 e1;
				/* 0x0023 */ struct _MMPFNENTRY3 e3;
			}; /* size: 0x0004 */
			struct
			{
				/* 0x0020 */ unsigned short ReferenceCount;
			} /* size: 0x0002 */ e2;
			struct
			{
				/* 0x0020 */ unsigned long EntireField;
			} /* size: 0x0004 */ e4;
		}; /* size: 0x0004 */
	} /* size: 0x0004 */ u3;
	/* 0x0024 */ struct _MI_PFN_ULONG5 u5;
	union
	{
		union
		{
			struct /* bitfield */
			{
				/* 0x0028 */ unsigned __int64 PteFrame : 40; /* bit position: 0 */
				/* 0x0028 */ unsigned __int64 ResidentPage : 1; /* bit position: 40 */
				/* 0x0028 */ unsigned __int64 Unused1 : 1; /* bit position: 41 */
				/* 0x0028 */ unsigned __int64 Unused2 : 1; /* bit position: 42 */
				/* 0x0028 */ unsigned __int64 Partition : 10; /* bit position: 43 */
				/* 0x0028 */ unsigned __int64 FileOnly : 1; /* bit position: 53 */
				/* 0x0028 */ unsigned __int64 PfnExists : 1; /* bit position: 54 */
				/* 0x0028 */ unsigned __int64 NodeFlinkHigh : 5; /* bit position: 55 */
				/* 0x0028 */ unsigned __int64 PageIdentity : 3; /* bit position: 60 */
				/* 0x0028 */ unsigned __int64 PrototypePte : 1; /* bit position: 63 */
			}; /* bitfield */
			/* 0x0028 */ unsigned __int64 EntireField;
		}; /* size: 0x0008 */
	} /* size: 0x0008 */ u4;
} MMPFN, * PMMPFN; /* size: 0x0030 */
EXTERN_C
PLIST_ENTRY PsLoadedModuleList;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	/*PNON_PAGED_DEBUG_INFO*/ PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
typedef struct _ACTIVATION_CONTEXT _ACTIVATION_CONTEXT, * P_ACTIVATION_CONTEXT;
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

UNICODE_STRING DeviceN, DosL;

extern "C" POBJECT_TYPE* IoDriverObjectType;

typedef int BOOL;
typedef unsigned __int64 QWORD;

struct cache {
	uintptr_t Address;
	UINT64 Value;
};
static cache cached_pml4e[512];

#define FIND_MIN(val1, val2) (static_cast<ULONG64>((val1) < (val2) ? (val1) : (val2)))

NTSTATUS Request_Not_Supported(PDEVICE_OBJECT devObj, PIRP irpRequest) {
	UNREFERENCED_PARAMETER(devObj);
	irpRequest->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IofCompleteRequest(irpRequest, IO_NO_INCREMENT);
	return irpRequest->IoStatus.Status;
}
NTSTATUS Request_Dispatch(PDEVICE_OBJECT devObj, PIRP irpRequest) {
	UNREFERENCED_PARAMETER(devObj);
	PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(irpRequest);
	switch (stackLocation->MajorFunction) {
	case IRP_MJ_CREATE:
		break;
	case IRP_MJ_CLOSE:
		break;
	default:
		break;
	}
	IofCompleteRequest(irpRequest, IO_NO_INCREMENT);
	return irpRequest->IoStatus.Status;
}
void DriverUnloading(PDRIVER_OBJECT driverObj) {
	NTSTATUS unlinkStatus = { 0 };
	unlinkStatus = __(IoDeleteSymbolicLink)(&DosL);
	if (!NT_SUCCESS(unlinkStatus))
		return;
	__(IoDeleteDevice)(driverObj->DeviceObject);
}
/* 1903, 1909, 2004, 20H2, 21H1*/
#define KernelBucketHashPattern_21H1 skCrypt("\x4C\x8D\x35\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x8B\x84\x24")
#define KernelBucketHashMask_21H1 skCrypt("xxx????x????xxx")

/* 22H2 */
#define KernelBucketHashPattern_22H2 skCrypt("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00")
#define KernelBucketHashMask_22H2 skCrypt("xxx????x?xxxxxxx")
static char* stristr(const char* str1, const char* str2) {
	const char* p1 = str1;
	const char* p2 = str2;
	const char* r = *p2 == 0 ? str1 : 0;
	while (*p1 != 0 && *p2 != 0)
	{
		if (__(tolower)((unsigned char)*p1) == __(tolower)((unsigned char)*p2))
		{
			if (r == 0)
			{
				r = p1;
			}
			p2++;
		}
		else
		{
			p2 = str2;
			if (r != 0)
			{
				p1 = r + 1;
			}
			if (__(tolower)((unsigned char)*p1) == __(tolower)((unsigned char)*p2))
			{
				r = p1;
				p2++;
			}
			else
			{
				r = 0;
			}
		}
		p1++;
	}
	return *p2 == 0 ? (char*)r : 0;
}
PVOID
GetKernelModuleBase(
	CHAR* ModuleName
) {
	PVOID ModuleBase = NULL;

	ULONG size = NULL;
	NTSTATUS status = __(ZwQuerySystemInformation)(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		return ModuleBase;
	}

	PSYSTEM_MODULE_INFORMATION Modules = (PSYSTEM_MODULE_INFORMATION)__(ExAllocatePool)(NonPagedPool, size);
	if (!Modules) {
		return ModuleBase;
	}

	if (!NT_SUCCESS(status = __(ZwQuerySystemInformation)(SystemModuleInformation, Modules, size, 0))) {
		__(ExFreePoolWithTag)(Modules, 0);
		return ModuleBase;
	}

	for (UINT i = 0; i < Modules->ulModuleCount; i++) {
		CHAR* CurrentModuleName = reinterpret_cast<CHAR*>(Modules->Modules[i].FullPathName);
		if (stristr(CurrentModuleName, ModuleName)) {
			ModuleBase = Modules->Modules[i].ImageBase;
			break;
		}
	}

	__(ExFreePoolWithTag)(Modules, 0);
	return ModuleBase;
}

ULONGLONG GetExportedFunction(
	CONST ULONGLONG mod,
	CONST CHAR* name
) {
	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<ULONGLONG>(dos_header) + dos_header->e_lfanew);

	const auto data_directory = nt_headers->OptionalHeader.DataDirectory[0];
	const auto export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(mod + data_directory.VirtualAddress);

	const auto address_of_names = reinterpret_cast<ULONG*>(mod + export_directory->AddressOfNames);

	for (size_t i = 0; i < export_directory->NumberOfNames; i++)
	{
		const auto function_name = reinterpret_cast<const char*>(mod + address_of_names[i]);

		if (!__(_stricmp)(function_name, name))
		{
			const auto name_ordinal = reinterpret_cast<unsigned short*>(mod + export_directory->AddressOfNameOrdinals)[i];

			const auto function_rva = mod + reinterpret_cast<ULONG*>(mod + export_directory->AddressOfFunctions)[name_ordinal];
			return function_rva;
		}
	}

	return 0;
}


PVOID GetKernelBase2() {
	PVOID KernelBase = NULL;

	ULONG size = NULL;
	NTSTATUS status = __(ZwQuerySystemInformation)(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		return KernelBase;
	}

	PSYSTEM_MODULE_INFORMATION Modules = (PSYSTEM_MODULE_INFORMATION)__(ExAllocatePool)(NonPagedPool, size);
	if (!Modules) {
		return KernelBase;
	}

	if (!NT_SUCCESS(status = __(ZwQuerySystemInformation)(SystemModuleInformation, Modules, size, 0))) {
		__(ExFreePoolWithTag)(Modules, 0);
		return KernelBase;
	}

	if (Modules->ulModuleCount > 0) {
		KernelBase = Modules->Modules[0].ImageBase;
	}

	__(ExFreePoolWithTag)(Modules, 0);
	return KernelBase;
}


PERESOURCE
GetPsLoaded() {
	PCHAR base = (PCHAR)GetKernelBase2();

	auto cMmGetSystemRoutineAddress = reinterpret_cast<decltype(&MmGetSystemRoutineAddress)>(GetExportedFunction((ULONGLONG)base, (skCrypt("MmGetSystemRoutineAddress"))));

	ERESOURCE PsLoadedModuleResource;
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsLoadedModuleResource");
	auto cPsLoadedModuleResource = reinterpret_cast<decltype(&PsLoadedModuleResource)>(cMmGetSystemRoutineAddress(&routineName));

	return cPsLoadedModuleResource;
}
/* 1903, 1909, 2004, 20H2, 21H1, 22H2 */
#define MmuPatternG skCrypt("\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9")
#define MmuMask skCrypt("xxx????xxx")

/* 1903, 1909, 2004, 20H2, 21H1, 22H2 */
#define MmlPatternG skCrypt("\x8B\x05\x00\x00\x00\x00\x83\xF8\x32")
#define MmlMask skCrypt("xx????xxx")

#define MM_UNLOADED_DRIVERS_SIZE 50
typedef struct _MM_UNLOADED_DRIVER {
	UNICODE_STRING 	Name;
	PVOID 			ModuleStart;
	PVOID 			ModuleEnd;
	ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

BOOL
CheckMask(
	PCHAR Base,
	PCHAR Pattern,
	PCHAR Mask
) {
	for (; *Mask; ++Base, ++Pattern, ++Mask) {
		if (*Mask == 'x' && *Base != *Pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

PVOID
FindPattern2(
	PCHAR Base,
	DWORD Length,
	PCHAR Pattern,
	PCHAR Mask
) {
	Length -= (DWORD)__(strlen)(Mask);
	for (DWORD i = 0; i <= Length; ++i) {
		PVOID Addr = &Base[i];
		if (CheckMask((PCHAR)Addr, Pattern, Mask)) {
			return Addr;
		}
	}

	return 0;
}

PVOID FindPatternImage(
	PCHAR Base,
	PCHAR Pattern,
	PCHAR Mask
) {
	PVOID Match = 0;

	PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);
	for (DWORD i = 0; i < Headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER Section = &Sections[i];
		if (*(PINT)Section->Name == 'EGAP' || memcmp(Section->Name, skCrypt(".text"), 5) == 0) {
			Match = FindPattern2(Base + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask);
			if (Match) {
				break;
			}
		}
	}

	return Match;
}
PVOID ResolveRelativeAddress(
	_In_ PVOID Instruction,
	_In_ ULONG OffsetOffset,
	_In_ ULONG InstructionSize
)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}

PMM_UNLOADED_DRIVER
GetMmuAddress() {
	PCHAR base = (PCHAR)GetKernelBase2();

	char* pMmuPattern = PCCHAR(MmuPatternG);
	char* pMmuMask = PCCHAR(MmuMask);

	PVOID MmUnloadedDriversInstr = FindPatternImage(base, pMmuPattern, pMmuMask);

	if (MmUnloadedDriversInstr == NULL)
		return { };

	return *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress(MmUnloadedDriversInstr, 3, 7);
}

PULONG
GetMmlAddress() {
	PCHAR Base = (PCHAR)GetKernelBase2();

	char* pMmlPattern = PCCHAR(MmlPatternG);
	char* pMmlMask = PCCHAR(MmlMask);

	PVOID mmlastunloadeddriverinst = FindPatternImage(Base, pMmlPattern, pMmlMask);

	if (mmlastunloadeddriverinst == NULL)
		return { };

	return (PULONG)ResolveRelativeAddress(mmlastunloadeddriverinst, 2, 6);
}

BOOL
VerifyMmu() {
	return (GetMmuAddress() != NULL && GetMmlAddress() != NULL);
}

BOOL
IsUnloadEmpty(
	PMM_UNLOADED_DRIVER Entry
) {
	if (Entry->Name.MaximumLength == 0 || Entry->Name.Length == 0 || Entry->Name.Buffer == NULL)
		return TRUE;

	return FALSE;
}

BOOL
IsMmuFilled() {
	for (ULONG Idx = 0; Idx < MM_UNLOADED_DRIVERS_SIZE; ++Idx) {
		PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Idx];
		if (IsUnloadEmpty(Entry))
			return FALSE;
	}
	return TRUE;
}
ULONG RandomNumberInRange(ULONG min, ULONG max)
{
	ULONG seed = (ULONG)__(KeQueryPerformanceCounter)(NULL).QuadPart;
	ULONG rand = __(RtlRandomEx)(&seed);
	return (rand % (max - min + 1)) + min;
}
PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
#define BB_POOL_TAG 'Esk'
PVOID GetKernelBase(OUT PULONG pSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;

	if (g_KernelBase != NULL)
	{
		if (pSize)
			*pSize = g_KernelSize;
		return g_KernelBase;
	}

	__(RtlInitUnicodeString)(&routineName, skCrypt(L"NtOpenFile"));

	checkPtr = __(MmGetSystemRoutineAddress)(&routineName);
	if (checkPtr == NULL)
		return NULL;

	status = __(ZwQuerySystemInformation)(SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
	{
		return NULL;
	}

	pMods = (PRTL_PROCESS_MODULES)__(ExAllocatePoolWithTag)(NonPagedPool, bytes, BB_POOL_TAG);
	if (pMods) {
		RtlZeroMemory(pMods, bytes);
	}
	else {
		return NULL;
	}

	status = __(ZwQuerySystemInformation)(SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		for (ULONG i = 0; i < pMods->NumberOfModules; i++)
		{
			if (checkPtr >= pMod[i].ImageBase &&
				checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{
				g_KernelBase = pMod[i].ImageBase;
				g_KernelSize = pMod[i].ImageSize;
				if (pSize)
					*pSize = g_KernelSize;
				break;
			}
		}
	}

	if (pMods)
		__(ExFreePoolWithTag)(pMods, BB_POOL_TAG);
	//log("g_KernelBase: %x", g_KernelBase);
	//log("g_KernelSize: %x", g_KernelSize);
	return g_KernelBase;
}

uintptr_t get_kerneladdr(const char* name, size_t& size) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	__(ZwQuerySystemInformation)(
		SystemModuleInformation,
		&neededSize,
		0,
		&neededSize
		);

	PSYSTEM_MODULE_INFORMATION pModuleList;

	pModuleList = (PSYSTEM_MODULE_INFORMATION)__(ExAllocatePoolWithTag)(NonPagedPool, neededSize, 'dEad');

	if (!pModuleList) {
		return 0;
	}

	status = __(ZwQuerySystemInformation)(SystemModuleInformation,
		pModuleList,
		neededSize,
		0
		);

	ULONG i = 0;
	uintptr_t address = 0;

	for (i = 0; i < pModuleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE mod = pModuleList->Modules[i];

		address = uintptr_t(pModuleList->Modules[i].ImageBase);
		size = uintptr_t(pModuleList->Modules[i].ImageSize);
		if (strstr((char*)mod.FullPathName, name) != NULL)
			break;
	}

	__(ExFreePoolWithTag)(pModuleList, 'dEad');

	return address;
}

#define win10_1803 17134
#define win10_1809 17763
#define win10_1903 18362
#define win10_1909 18363
#define win10_2004 19041
#define win10_20h2 19042
#define win10_21h1 19043
#define win10_21h2 19044
#define win10_22h2 19045
#define win11_21h2 22000
#define win11_22h2 22621
//#define win11_23h2 22631
//#define win11_24h2 26100
//#define win11_25h2 27723 //Canary
ULONG Winver_fetch()
{
	RTL_OSVERSIONINFOW ver = { 0 };
	__(RtlGetVersion)(&ver);
	switch (ver.dwBuildNumber)
	{
	case win10_1803:
	case win10_1809:
		return 0x0278;
	case win10_1903:
	case win10_1909:
		return 0x0280;
	case win10_2004:
	case win10_20h2:
	case win10_21h1:
	case win10_21h2:
	case win10_22h2:
		return 0x0388;
	case win11_21h2:
	case win11_22h2:
		return 0x0390;
	default:
		return 0x0390;
	}
}
NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
	_In_ PVOID ModuleAddress
);
NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound, int index = 0)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_ACCESS_DENIED;
	int cIndex = 0;
	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE && cIndex++ == index)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}
NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, PVOID base = nullptr)
{
	if (ppFound == NULL)
		return STATUS_ACCESS_DENIED;

	if (nullptr == base)
		base = GetKernelBase(&g_KernelSize);
	if (base == nullptr)
		return STATUS_ACCESS_DENIED;

	PIMAGE_NT_HEADERS64 pHdr = __(RtlImageNtHeader)(base);
	if (!pHdr)
		return STATUS_ACCESS_DENIED;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		ANSI_STRING s1, s2;
		__(RtlInitAnsiString)(&s1, section);
		__(RtlInitAnsiString)(&s2, (PCCHAR)pSection->Name);
		if (__(RtlCompareString)(&s1, &s2, TRUE) == 0)
		{
			PVOID ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status)) {
				*(PULONG64)ppFound = (ULONG_PTR)(ptr);
				return status;
			}
		}
	}

	return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;
}

namespace pml4 {

	auto FindPatternInMemory(PVOID startAddress, SIZE_T memorySize, const void* pattern, SIZE_T patternSize) -> PVOID {
		const auto* memStart = static_cast<const UCHAR*>(startAddress);
		const auto* memPattern = static_cast<const UCHAR*>(pattern);

		for (SIZE_T i = 0; i <= memorySize - patternSize; ++i) {
			SIZE_T j = 0;
			while (j < patternSize && memStart[i + j] == memPattern[j]) {
				++j;
			}
			if (j == patternSize) {
				return const_cast<UCHAR*>(&memStart[i]);
			}
		}
		return nullptr;
	}
	void* KernelDatabase = nullptr;
	auto InitializePfnDatabase() -> NTSTATUS {
		struct PfnDatabasePattern {
			const UCHAR* bytePattern;
			SIZE_T byteSize;
			bool isHardcoded;
		};

		static const UCHAR win10x64Pattern[] = { 0x48, 0x8B, 0xC1, 0x48, 0xC1, 0xE8, 0x0C, 0x48, 0x8D, 0x14, 0x40, 0x48, 0x03, 0xD2, 0x48, 0xB8 };

		PfnDatabasePattern pfnSearchConfig{
			win10x64Pattern,
			sizeof(win10x64Pattern),
			true
		};
		auto getVirtualFn = reinterpret_cast<UCHAR*>(__(MmGetVirtualForPhysical));
		if (!getVirtualFn) {
			return STATUS_PROCEDURE_NOT_FOUND;
		}
		auto resultAddr = reinterpret_cast<UCHAR*>(FindPatternInMemory(getVirtualFn, 0x20, pfnSearchConfig.bytePattern, pfnSearchConfig.byteSize));
		if (!resultAddr) {
			return STATUS_UNSUCCESSFUL;
		}
		resultAddr += pfnSearchConfig.byteSize;
		if (pfnSearchConfig.isHardcoded) {
			KernelDatabase = *reinterpret_cast<void**>(resultAddr);
		}
		else {
			auto pfnAddr = *reinterpret_cast<ULONG_PTR*>(resultAddr);
			KernelDatabase = *reinterpret_cast<void**>(pfnAddr);
		}
		KernelDatabase = PAGE_ALIGN(KernelDatabase);
		return STATUS_SUCCESS;
	}
}

ULONG randint_except_its_a_ulong(ULONG min, ULONG max)
{
	ULONG seed = (ULONG)__(KeQueryPerformanceCounter)(NULL).QuadPart;
	ULONG rand = __(RtlRandomEx)(&seed);
	return (rand % (max - min + 1)) + min;
}

NTSTATUS WW(PVOID destBuf, PVOID srcPhys, SIZE_T size, SIZE_T* copiedSize){//(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read) {
	if (!destBuf || !srcPhys || size == 0) return STATUS_INVALID_PARAMETER;

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = LONGLONG(destBuf);

	PVOID pmapped_mem = __(MmMapIoSpaceEx)(AddrToWrite, size, PAGE_READWRITE);
	if (!pmapped_mem) return STATUS_UNSUCCESSFUL;
	__try {
		memcpy(pmapped_mem, srcPhys, size);
		*copiedSize = size;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		__(MmUnmapIoSpace)(pmapped_mem, size);
		return GetExceptionCode();
	}
	__(MmUnmapIoSpace)(pmapped_mem, size);
	return STATUS_SUCCESS;
}

NTSTATUS RR(PVOID destBuf, PVOID srcPhys, SIZE_T size, SIZE_T* copiedSize) {
	MM_COPY_ADDRESS srcAddr;
	srcAddr.PhysicalAddress.QuadPart = (LONGLONG)destBuf;
	return __(MmCopyMemory)(srcPhys, srcAddr, size, MM_COPY_MEMORY_PHYSICAL, copiedSize);
}

UINT64 RC(UINT64 address, cache* cached_entry, SIZE_T* readsize) {
	if (cached_entry->Address == address) {
		return cached_entry->Value;
	}
	RR(PVOID(address), &cached_entry->Value, sizeof(cached_entry->Value), readsize);
	cached_entry->Address = address;
	return cached_entry->Value;
}

UINT64 TranslateB(UINT64 dtbase, UINT64 vtaddy) {
	dtbase &= ~0xF;

	UINT64 pageOffset = vtaddy & ((1ULL << 12) - 1);
	UINT64 pteIndex = (vtaddy >> 12) & 0x1FF;
	UINT64 ptIndex = (vtaddy >> 21) & 0x1FF;
	UINT64 pdIndex = (vtaddy >> 30) & 0x1FF;
	UINT64 pdpIndex = (vtaddy >> 39) & 0x1FF;

	SIZE_T bytesRead = 0;
	UINT64 pdpeEntry = 0;
	RR(PVOID(dtbase + 8 * pdpIndex), &pdpeEntry, sizeof(pdpeEntry), &bytesRead);
	if (!(pdpeEntry & 1)) return 0;
	UINT64 pdeEntry = 0;
	RR(PVOID((pdpeEntry & PMASK) + 8 * pdIndex), &pdeEntry, sizeof(pdeEntry), &bytesRead);
	if (!(pdeEntry & 1)) return 0;
	if (pdeEntry & 0x80) {
		return (pdeEntry & (~0ULL << 42 >> 12)) + (vtaddy & ((1ULL << 30) - 1));
	}
	UINT64 pteEntry = 0;
	RR(PVOID((pdeEntry & PMASK) + 8 * ptIndex), &pteEntry, sizeof(pteEntry), &bytesRead);
	if (!(pteEntry & 1)) return 0;
	if (pteEntry & 0x80) {
		return (pteEntry & PMASK) + (vtaddy & ((1ULL << 21) - 1));
	}
	UINT64 pageEntry = 0;
	RR(PVOID((pteEntry & PMASK) + 8 * pteIndex), &pageEntry, sizeof(pageEntry), &bytesRead);
	pageEntry &= PMASK;
	if (!pageEntry) return 0;
	return pageEntry + pageOffset;
}

UINT64 TranslateE(UINT64 dtbase, UINT64 vtaddy) {
	dtbase &= ~0xf;
	UINT64 pageOffset = vtaddy & ((1ULL << 12) - 1);
	UINT64 pte = (vtaddy >> 12) & 0x1ff;
	UINT64 pt = (vtaddy >> 21) & 0x1ff;
	UINT64 pd = (vtaddy >> 30) & 0x1ff;
	UINT64 pdp = (vtaddy >> 39) & 0x1ff;
	SIZE_T readsize = 0;
	UINT64 pdpe = 0;
	pdpe = RC(dtbase + 8 * pdp, &cached_pml4e[pdp], &readsize);
	if ((pdpe & 1) == 0)
		return 0;
	UINT64 pde = 0;
	RR(PVOID((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
	if ((pde & 1) == 0)
		return 0;
	if (pde & 0x80) {
		return (pde & PMASK) + (vtaddy & ((1ULL << 30) - 1));
	}
	UINT64 pteAddr = 0;
	RR(PVOID((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
	if ((pteAddr & 1) == 0)
		return 0;
	if (pteAddr & 0x80) {
		return (pteAddr & PMASK) + (vtaddy & ((1ULL << 21) - 1));
	}
	UINT64 finalAddr = 0;
	RR(PVOID((pteAddr & PMASK) + 8 * pte), &finalAddr, sizeof(finalAddr), &readsize);
	finalAddr &= PMASK;
	if (finalAddr == 0)
		return 0;
	return finalAddr + pageOffset;
}
auto GetDTB(void* processBase) -> uintptr_t {
	if (!NT_SUCCESS(pml4::InitializePfnDatabase())) {
		return 0;
	}
	virt_addr_t virtualBase{};
	virtualBase.value = processBase;
	size_t bytesRead = 0;
	auto physicalMemory = __(MmGetPhysicalMemoryRanges)();
	for (int i = 0; physicalMemory[i].BaseAddress.QuadPart; ++i) {
		auto& currentRange = physicalMemory[i];
		UINT64 physicalAddr = currentRange.BaseAddress.QuadPart;
		for (UINT64 offset = 0; offset < currentRange.NumberOfBytes.QuadPart; offset += 0x1000, physicalAddr += 0x1000) {
			auto pfn = reinterpret_cast<_MMPFN*>((uintptr_t)pml4::KernelDatabase + ((physicalAddr >> 12) * sizeof(_MMPFN)));
			if (pfn->u4.PteFrame == (physicalAddr >> 12)) {
				MMPTE pml4Entry{};
				if (!NT_SUCCESS(RR(PVOID(physicalAddr + 8 * virtualBase.pml4_index), &pml4Entry, 8, &bytesRead))) {
					continue;
				}
				if (!pml4Entry.u.Hard.Valid) {
					continue;
				}
				MMPTE pdptEntry{};
				if (!NT_SUCCESS(RR(PVOID((pml4Entry.u.Hard.PageFrameNumber << 12) + 8 * virtualBase.pdpt_index), &pdptEntry, 8, &bytesRead))) {
					continue;
				}
				if (!pdptEntry.u.Hard.Valid) {
					continue;
				}
				MMPTE pdeEntry{};
				if (!NT_SUCCESS(RR(PVOID((pdptEntry.u.Hard.PageFrameNumber << 12) + 8 * virtualBase.pd_index), &pdeEntry, 8, &bytesRead))) {
					continue;
				}
				if (!pdeEntry.u.Hard.Valid) {
					continue;
				}
				MMPTE pteEntry{};
				if (!NT_SUCCESS(RR(PVOID((pdeEntry.u.Hard.PageFrameNumber << 12) + 8 * virtualBase.pt_index), &pteEntry, 8, &bytesRead))) {
					continue;
				}
				if (!pteEntry.u.Hard.Valid) {
					continue;
				}
				return physicalAddr;
			}
		}
	}
	return 0;
}

struct PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16];
};


UCHAR PiDDBLockPtr_sig_win10[] = "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24";
UCHAR PiDDBLockPtr_sig_win11[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8";
UCHAR PiDDBCacheTablePtr_sig[] = "\x66\x03\xD2\x48\x8D\x0D";


bool LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
	PVOID PiDDBLockPtr = nullptr, PiDDBCacheTablePtr = nullptr;

	if (NT_SUCCESS(BBScanSection(PCCHAR(skCrypt("PAGE")), PiDDBLockPtr_sig_win10, 0, sizeof(PiDDBLockPtr_sig_win10) - 1, reinterpret_cast<PVOID*>(&PiDDBLockPtr)))) {
		PiDDBLockPtr = PVOID((uintptr_t)PiDDBLockPtr + 28);
	}
	else {
		if (NT_SUCCESS(BBScanSection(PCCHAR(skCrypt("PAGE")), PiDDBLockPtr_sig_win11, 0, sizeof(PiDDBLockPtr_sig_win11) - 1, reinterpret_cast<PVOID*>(&PiDDBLockPtr)))) {
			PiDDBLockPtr = PVOID((uintptr_t)PiDDBLockPtr + 16);
		}
		else {
			return 1;
		}

	}

	if (!NT_SUCCESS(BBScanSection(PCCHAR(skCrypt("PAGE")), PiDDBCacheTablePtr_sig, 0, sizeof(PiDDBCacheTablePtr_sig) - 1, reinterpret_cast<PVOID*>(&PiDDBCacheTablePtr)))) {
		return false;
	}

	PiDDBCacheTablePtr = PVOID((uintptr_t)PiDDBCacheTablePtr + 3);

	*lock = (PERESOURCE)(ResolveRelativeAddress(PiDDBLockPtr, 3, 7));
	*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7));

	return true;
}


BOOL piddbcache(UNICODE_STRING DriverName, ULONG timeDateStamp) {
	PERESOURCE PiDDBLock; PRTL_AVL_TABLE PiDDBCacheTable;
	if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable)) {
		return 1;
	}

	PiDDBCacheEntry lookupEntry = { };
	lookupEntry.DriverName = DriverName;
	lookupEntry.TimeDateStamp = timeDateStamp;

	__(ExAcquireResourceExclusiveLite)(PiDDBLock, TRUE);
	auto pFoundEntry = (PiDDBCacheEntry*)__(RtlLookupElementGenericTableAvl)(PiDDBCacheTable, &lookupEntry);
	if (pFoundEntry == nullptr)
	{
		__(ExReleaseResourceLite)(PiDDBLock);
		return 1;
	}
	__(RemoveEntryList)(&pFoundEntry->List);
	if (!__(RtlDeleteElementGenericTableAvl)(PiDDBCacheTable, pFoundEntry)) {
		return 1;
	}

	__(ExReleaseResourceLite)(PiDDBLock);
	return 0;
}
NTSTATUS PSLMEntry(PDRIVER_OBJECT drvobj, wchar_t* DriverName) {
	__try {
		PLDR_DATA_TABLE_ENTRY currEntry = (PLDR_DATA_TABLE_ENTRY)(drvobj->DriverSection);
		PLDR_DATA_TABLE_ENTRY startEntry = currEntry;

		while ((PLDR_DATA_TABLE_ENTRY)(currEntry->InLoadOrderLinks.Flink) != startEntry) {
			if (!(ULONG)currEntry->EntryPoint > MmUserProbeAddress) {
				currEntry = (PLDR_DATA_TABLE_ENTRY)(currEntry->InLoadOrderLinks.Flink);
				continue;
			}
			if (__(wcsstr)(currEntry->BaseDllName.Buffer, DriverName)) {
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
}
BOOL Mmu(UNICODE_STRING DriverName) {
	auto ps_loaded = GetPsLoaded();

	if (ps_loaded == NULL) {
		return 1;
	}

	__(ExAcquireResourceExclusiveLite)(ps_loaded, TRUE);

	BOOLEAN Modified = FALSE;
	BOOLEAN Filled = IsMmuFilled();

	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index) {
		PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
		if (IsUnloadEmpty(Entry)) {
			continue;
		}
		BOOL empty = IsUnloadEmpty(Entry);
		if (Modified) {
			PMM_UNLOADED_DRIVER PrevEntry = &GetMmuAddress()[Index - 1];
			RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));

			if (Index == MM_UNLOADED_DRIVERS_SIZE - 1) {
				RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			}
		}
		else if (__(RtlEqualUnicodeString)(&DriverName, &Entry->Name, TRUE)) {
			PVOID BufferPool = Entry->Name.Buffer;
			RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			__(ExFreePoolWithTag)(BufferPool, 'TDmM');

			*GetMmlAddress() = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *GetMmlAddress()) - 1;
			Modified = TRUE;
		}
	}

	if (Modified) {
		ULONG64 PreviousTime = 0;

		for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index) {
			PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
			if (IsUnloadEmpty(Entry)) {
				continue;
			}

			if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime) {
				Entry->UnloadTime = PreviousTime - RandomNumberInRange(1561795696, 1698136146);
			}

			PreviousTime = Entry->UnloadTime;
		}

		Mmu(DriverName);
	}

	__(ExReleaseResourceLite)(ps_loaded);

	if (Modified == FALSE) {
		return 1;
	}
	else {
		return 0;
	}

	return 0;
}
BOOL Hashbucket(UNICODE_STRING DriverName) {
	char* CIDLLString = PCCHAR(skCrypt("ci.dll"));
	CONST PVOID CIDLLBase = GetKernelModuleBase(CIDLLString);

	if (!CIDLLBase) {
		return 1;
	}

	char* pKernelBucketHashPattern_21H1 = PCCHAR(KernelBucketHashPattern_21H1);
	char* pKernelBucketHashMask_21H1 = PCCHAR(KernelBucketHashMask_21H1);

	char* pKernelBucketHashPattern_22H2 = PCCHAR(KernelBucketHashPattern_22H2);
	char* pKernelBucketHashMask_22H2 = PCCHAR(KernelBucketHashMask_22H2);

	PVOID SignatureAddress = FindPatternImage((PCHAR)CIDLLBase, pKernelBucketHashPattern_21H1, pKernelBucketHashMask_21H1);
	if (!SignatureAddress) {
		SignatureAddress = FindPatternImage((PCHAR)CIDLLBase, pKernelBucketHashPattern_22H2, pKernelBucketHashMask_22H2);
		if (!SignatureAddress) {
			return 1;
		}
	}

	CONST ULONGLONG* g_KernelHashBucketList = (ULONGLONG*)ResolveRelativeAddress(SignatureAddress, 3, 7);
	if (!g_KernelHashBucketList) {
		return 1;
	}

	LARGE_INTEGER Time{};
	__(KeQuerySystemTimePrecise)(&Time);

	BOOL Status = FALSE;
	for (ULONGLONG i = *g_KernelHashBucketList; i; i = *(ULONGLONG*)i) {
		CONST PWCHAR wsName = PWCH(i + 0x48);
		if (__(wcsstr)(wsName, DriverName.Buffer)) {
			PUCHAR Hash = PUCHAR(i + 0x18);
			for (UINT j = 0; j < 20; j++)
				Hash[j] = UCHAR(__(RtlRandomEx)(&Time.LowPart) % 255);

			Status = TRUE;
		}
	}

	if (Status == FALSE) {
		return 1;
	}
	else {
		return 0;
	}
	return 0;
}