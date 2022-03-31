#pragma once

typedef enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute = NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed = NonPagedPool + 2,
    DontUseThisType,
    NonPagedPoolCacheAligned = NonPagedPool + 4,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
    MaxPoolType,
    NonPagedPoolBase = 0,
    NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
    NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
    NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
    NonPagedPoolSession = 32,
    PagedPoolSession = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
    DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
    NonPagedPoolNx = 512,
    NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
    NonPagedPoolSessionNx = NonPagedPoolNx + 32,

} POOL_TYPE;

using KeSetSystemAffinityThread_t = void(*)(KAFFINITY);
using KeQueryActiveProcessors_t = KAFFINITY(*)();
using MmGetSystemRoutineAddress_t = void* (*)(PUNICODE_STRING);
using DbgPrint_t = void(*)(const char*, ...);
using ExAllocatePool_t = void* (*)(POOL_TYPE, SIZE_T);
using RtlCopyMemory_t = void (*)(void*, void*, SIZE_T);
using DriverEntry_t = NTSTATUS(*)(void*, void*);

constexpr auto STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

constexpr auto SystemModuleInformation = 11;

typedef NTSTATUS(*NtLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(*NtUnloadDriver)(PUNICODE_STRING DriverServiceName);

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

enum COMMAND
{
	IS_VALID,
	READ_MEMORY,
	WRITE_MEMORY,
	ALLOCATE_MEMORY,
	ALLOCATE_KRNL_MEMORY,
	EXPOSE_MEM_TO_PROCESS
};

typedef struct _COMMAND_BUFFER {
	UINT64 m_command_id;
	UINT64 m_data[5];
	NTSTATUS m_status;
} COMMAND_BUFFER, * PCOMMAND_BUFFER;

using NtQueryAuxiliaryCounterFrequency_t = void(*)(PCOMMAND_BUFFER);

struct control_ctx_t 
{
	uint64_t m_size;
	uint64_t m_physical_address;
	uint64_t m_section_handle;
	uint64_t m_user_address;
	uint64_t m_section_object;
};

enum class e_control_code : ulong_t 
{
	map = 0x80102040,
	unmap = 0x80102044
};

struct handler_ctx_t
{
	uintptr_t MmGetSystemRoutineAddress;
};

using callback_t = std::function<void(handler_ctx_t)>;
using handler_t = void(__fastcall*)(handler_ctx_t ctx);
