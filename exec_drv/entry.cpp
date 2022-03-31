typedef unsigned long ulong_t;

#include <windows.h>
#include <winternl.h>
#include <process.h>
#include <wtsapi32.h>
#include <tlhelp32.h>
#include <conio.h>
#include <cstdio>
#include <cstdlib>
#include <type_traits>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <immintrin.h>
#include <intrin.h>
#include <array>

#include "misc/kli.hpp"
#include "misc/ia32.hpp"

#define OXORANY_DISABLE_OBFUSCATION

#include "misc/oxorany.hpp"

#define NtCurrentProcess()        ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess()        NtCurrentProcess()

#define INRANGE(x,a,b)    (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xA) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))

#define SIZE_ALIGN(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)

#define PAGE_SIZE (ULONG)0x1000
#define PAGE_SHIFT   12

#define PHYSICAL_ADDRESS_BITS 40
#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PTE_SHIFT 3

#define MM_COPY_MEMORY_PHYSICAL 0x1
#define MM_COPY_MEMORY_VIRTUAL 0x2

#define ADDRESS_AND_SIZE_TO_SPAN_PAGES(Va,Size) \
   (((((Size) - 1) >> PAGE_SHIFT) + \
   (((((ULONG)(Size-1)&(PAGE_SIZE-1)) + (PtrToUlong(Va) & (PAGE_SIZE -1)))) >> PAGE_SHIFT)) + 1L)

#define MmGetMdlPfnArray(_Mdl) \
  ((PPFN_NUMBER) ((_Mdl) + 1))

#define MmGetMdlVirtualAddress(_Mdl) \
  ((PVOID) ((PCHAR) ((_Mdl)->StartVa) + (_Mdl)->ByteOffset))

#define MmGetMdlByteCount(_Mdl) \
  ((_Mdl)->ByteCount)

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

constexpr auto SystemModuleInformation = 11;

#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_CASE_INSENSITIVE                0x00000040L

typedef struct _MDL {
	struct _MDL* Next;
	SHORT           Size;
	SHORT           MdlFlags;
	struct _EPROCESS* Process;
	PVOID            MappedSystemVa;
	PVOID            StartVa;
	ULONG            ByteCount;
	ULONG            ByteOffset;
} MDL, * PMDL;

typedef struct _POOL_TRACKER_BIG_PAGES
{
	PVOID Va;
	ULONG Key;
	ULONG PoolType;
	ULONG NumberOfBytes;
} POOL_TRACKER_BIG_PAGES, * PPOOL_TRACKER_BIG_PAGES;

typedef ULONG_PTR* PPFN_NUMBER;

typedef struct __LARGE_INTEGER {
	LONGLONG QuadPart;
} ___LARGE_INTEGER;

typedef __LARGE_INTEGER PHYSICAL_ADDRESS;

typedef struct _MM_COPY_ADDRESS {
	union {
		PVOID            VirtualAddress;
		PHYSICAL_ADDRESS PhysicalAddress;
	};
} MM_COPY_ADDRESS, * PMMCOPY_ADDRESS;

typedef struct _RTL_BALANCED_LINKS {
	struct _RTL_BALANCED_LINKS* Parent;
	struct _RTL_BALANCED_LINKS* LeftChild;
	struct _RTL_BALANCED_LINKS* RightChild;
	CHAR Balance;
	UCHAR Reserved[3];
} RTL_BALANCED_LINKS;
typedef RTL_BALANCED_LINKS* PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE {
	RTL_BALANCED_LINKS BalancedRoot;
	PVOID OrderedPointer;
	ULONG WhichOrderedElement;
	ULONG NumberGenericTableElements;
	ULONG DepthOfTree;
	PVOID RestartKey;
	ULONG DeleteCount;
	PVOID CompareRoutine;
	PVOID AllocateRoutine;
	PVOID FreeRoutine;
	PVOID TableContext;
} RTL_AVL_TABLE;
typedef RTL_AVL_TABLE* PRTL_AVL_TABLE;

typedef struct _PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
} PiDDBCacheEntry, * NPiDDBCacheEntry;

typedef struct _UNLOADED_DRIVERS {
	UNICODE_STRING Name;
	PVOID StartAddress;
	PVOID EndAddress;
	LARGE_INTEGER CurrentTime;
} UNLOADED_DRIVERS, * PUNLOADED_DRIVERS;

// if exceeded it'll start to overwrite existing entries
// https://github.com/Zer0Mem0ry/ntoskrnl/blob/a1eded2d8efb071685e1f3cc59a1054f8545b73a/Mm/sysload.c#L3427
#define MI_UNLOADED_DRIVERS 50

typedef struct _MM_UNLOADED_DRIVER {
	UNICODE_STRING 	Name;
	PVOID 			ModuleStart;
	PVOID 			ModuleEnd;
	ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

#ifndef MAXIMUM_FILENAME_LENGTH
#define MAXIMUM_FILENAME_LENGTH 255
#endif // MAXIMUM_FILENAME_LENGTH

#pragma pack(push, 8)
typedef struct _SYSTEM_MODULE_ENTRY
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
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[0];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
#pragma pack(pop)

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

typedef struct _KAPC_STATE
{
	LIST_ENTRY ApcListHead[2];
	uint64_t Process;
	UCHAR KernelApcInProgress;
	UCHAR KernelApcPending;
	UCHAR UserApcPending;
} KAPC_STATE, * PKAPC_STATE;

typedef enum _MEMORY_CACHING_TYPE_ORIG {
	MmFrameBufferCached = 2
} MEMORY_CACHING_TYPE_ORIG;

typedef enum _MEMORY_CACHING_TYPE {
	MmNonCached = FALSE,
	MmCached = TRUE,
	MmWriteCombined = MmFrameBufferCached,
	MmHardwareCoherentCached,
	MmNonCachedUnordered,       // IA64
	MmUSWCCached,
	MmMaximumCacheType,
	MmNotMapped = -1
} MEMORY_CACHING_TYPE;

typedef CCHAR KPROCESSOR_MODE;

typedef enum _MODE {
	KernelMode,
	UserMode,
	MaximumMode
} MODE;

typedef enum _MM_PAGE_PRIORITY {
	LowPagePriority,
	NormalPagePriority = 16,
	HighPagePriority = 32
} MM_PAGE_PRIORITY;

// fn defs

ULONG DbgPrint(
	PCSTR Format,
	...
);

NTSTATUS MmCopyMemory(
	PVOID           TargetAddress,
	MM_COPY_ADDRESS SourceAddress,
	SIZE_T          NumberOfBytes,
	ULONG           Flags,
	PSIZE_T         NumberOfBytesTransferred
);

PMDL IoAllocateMdl(
	PVOID VirtualAddress,
	ULONG                  Length,
	BOOLEAN                SecondaryBuffer,
	BOOLEAN                ChargeQuota,
	void*                  Irp
);

BOOLEAN ExAcquireResourceExclusiveLite(
	void* Resource,
	BOOLEAN    Wait
);

PVOID RtlEnumerateGenericTableAvl(
	PRTL_AVL_TABLE Table,
	BOOLEAN        Restart
);

void ExReleaseResourceLite(
	void* Resource
);

BOOLEAN RemoveEntryList(
	PLIST_ENTRY Entry
);

BOOLEAN RtlDeleteElementGenericTableAvl(
	PRTL_AVL_TABLE Table,
	PVOID          Buffer
);

PVOID ExAllocatePool(
	POOL_TYPE PoolType,
	SIZE_T NumberOfBytes
);

void ExFreePool(
	PVOID P
);

NTSTATUS ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

void KeQuerySystemTimePrecise(
	PLARGE_INTEGER CurrentTime
);

ULONG RtlRandomEx(
	PULONG Seed
);

uint64_t KeGetCurrentThread();

NTSTATUS PsLookupProcessByProcessId(
	HANDLE    ProcessId,
	uint64_t* Process
);

HANDLE MmSecureVirtualMemory(
	PVOID  Address,
	SIZE_T Size,
	ULONG  ProbeMode
);

NTSTATUS ZwAllocateVirtualMemory(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);

void ObDereferenceObject(
	uint64_t a
);

void KeStackAttachProcess(
	uint64_t PROCESS,
	PKAPC_STATE ApcState
);

void KeUnstackDetachProcess(
	PKAPC_STATE ApcState
);

uint64_t
MmGetVirtualForPhysical(
	PHYSICAL_ADDRESS PhysicalAddress
);

uint64_t IoGetCurrentProcess();

void KeFlushCurrentTbImmediately();

BOOLEAN MmIsAddressValid(
	PVOID VirtualAddress
);

PMDL MmAllocatePagesForMdl(
	PHYSICAL_ADDRESS LowAddress,
	PHYSICAL_ADDRESS HighAddress,
	PHYSICAL_ADDRESS SkipBytes,
	SIZE_T           TotalBytes
);

uint64_t MmMapLockedPagesSpecifyCache(
	PMDL                                                                          MemoryDescriptorList,
	KPROCESSOR_MODE AccessMode,
	MEMORY_CACHING_TYPE                      CacheType,
	PVOID                                                                         RequestedAddress,
	 ULONG                                                                         BugCheckOnFailure,
	  ULONG                                                                         Priority
);

NTSTATUS MmProtectMdlSystemAddress(
	PMDL  MemoryDescriptorList,
	ULONG NewProtect
);

void MmUnmapLockedPages(
	PVOID BaseAddress,
	PMDL  MemoryDescriptorList
);

void MmFreePagesFromMdl(
	PMDL MemoryDescriptorList
);

// globals

uintptr_t kernel_base = 0;
uint64_t pte_base = 0;
uint64_t pde_base = 0;

char* __cdecl _strstr(const char* Str, const char* SubStr)
{
	char* v3; // r8
	char v5; // al
	signed __int64 i; // r9
	const char* v7; // rdx

	v3 = (char*)Str;
	if (!*SubStr)
		return (char*)Str;
	v5 = *Str;
	if (!*Str)
		return 0i64;
	for (i = Str - SubStr; ; ++i)
	{
		v7 = SubStr;
		if (v5)
			break;
	LABEL_9:
		if (!*v7)
			return v3;
		v5 = *++v3;
		if (!*v3)
			return 0i64;
	}
	while (*v7)
	{
		if (v7[i] == *v7)
		{
			++v7;
			if (v7[i])
				continue;
		}
		goto LABEL_9;
	}
	return v3;
}

wchar_t* __cdecl _wcsstr(const wchar_t* Str, const wchar_t* SubStr)
{
	wchar_t* v3; // r8
	wchar_t v5; // ax
	signed __int64 i; // r9
	const wchar_t* v7; // rdx

	v3 = (wchar_t*)Str;
	if (!*SubStr)
		return (wchar_t*)Str;
	v5 = *Str;
	if (!*Str)
		return 0i64;
	for (i = (char*)Str - (char*)SubStr; ; i += 2i64)
	{
		v7 = SubStr;
		if (v5)
			break;
	LABEL_9:
		if (!*v7)
			return v3;
		v5 = *++v3;
		if (!*v3)
			return 0i64;
	}
	while (*v7)
	{
		if (*(const wchar_t*)((char*)v7 + i) == *v7)
		{
			if (*(const wchar_t*)((char*)++v7 + i))
				continue;
		}
		goto LABEL_9;
	}
	return v3;
}

wchar_t* __cdecl _wcscpy(wchar_t* Dest, const wchar_t* Source)
{
	signed __int64 v2; // r8
	wchar_t v3; // ax

	v2 = (char*)Dest - (char*)Source;
	do
	{
		v3 = *Source;
		*(wchar_t*)((char*)Source + v2) = *Source;
		++Source;
	} while (v3);
	return Dest;
}

size_t __cdecl _wcslen(const wchar_t* Str)
{
	const wchar_t* v1; // rax

	v1 = Str;
	while (*v1++);

	return v1 - Str - 1;
}

PCHAR lower_str(PCHAR str) 
{
	auto tolower_ = KLI_FN(tolower);

	for (PCHAR s = str; *s; ++s) {
		*s = (CHAR)tolower_(*s);
	}

	return str;
}

uintptr_t get_module_base(const char* name, PULONG out_module_size)
{
	uintptr_t module_address = 0;
	ULONG size = 0;

	auto zw_query_sys_info = KLI_FN(ZwQuerySystemInformation);
	auto status = zw_query_sys_info(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), 0, 0, &size);

	if (status != STATUS_INFO_LENGTH_MISMATCH) 
	{
		return module_address;
	}

	PSYSTEM_MODULE_INFORMATION modules = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(KLI_FN(ExAllocatePool)(NonPagedPool, size));

	if (!modules) 
	{
		return module_address;
	}

	if (!NT_SUCCESS(status = zw_query_sys_info(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), modules, size, 0))) 
	{
		KLI_FN(ExFreePool)(modules);
		return module_address;
	}

	for (ULONG i = 0; i < modules->Count; ++i) 
	{
		auto m = modules->Module[i];

		if (_strstr(lower_str((PCHAR)m.FullPathName), name)) 
		{
			module_address = reinterpret_cast<uintptr_t>(m.ImageBase);
			if (out_module_size) {
				*out_module_size = m.ImageSize;
			}
			break;
		}
	}

	KLI_FN(ExFreePool)(modules);
	return module_address;
}

namespace omniz
{
	namespace detail
	{
		template<std::size_t n>
		constexpr std::size_t get_bytes_count(const char(&str)[n]) {
			std::size_t b = 0;
			auto any_byte = false;
			for (std::size_t i = 0; i < n - 1; i++)
			{
				if (str[i] == ' ')
				{
					any_byte = false;
					continue;
				}
				if (str[i] == '?')
				{
					if (!any_byte)
					{
						any_byte = true;
						b++;
					}
					continue;
				}
				b++;
				i++;
			}
			return b;
		}

		template<std::size_t bc, std::size_t n>
		constexpr auto convert_to_bytes_array(const char(&str)[n]) {
			std::array<std::uint8_t, bc> result{};
			auto any_byte = false;
			for (size_t i = 0, bn = 0; i < n - 1; i++) {
				if (str[i] == ' ')
				{
					any_byte = false;
					continue;
				}
				if (str[i] == '?')
				{
					if (!any_byte)
					{
						any_byte = true;
						result[bn++] = 0;
					}
					continue;
				}

				result[bn++] = getBits(str[i]) << 4 | getBits(str[i + 1]);
				i++;
			}

			return result;
		}

		template<std::size_t bc, std::size_t n>
		constexpr auto convert_to_mask_array(const char(&str)[n]) {
			std::array<std::uint8_t, bc> result{};
			auto any_byte = false;
			size_t any_byte_pos = 0;
			for (size_t i = 0, bn = 0; i < n - 1; i++) {
				if (str[i] == ' ')
				{
					any_byte = false;
					continue;
				}
				if (str[i] == '?')
				{
					if (!any_byte)
					{
						any_byte = true;
						if (!any_byte_pos)
							any_byte_pos = bn;
						result[bn++] = 1;
					}
					continue;
				}
				if (any_byte_pos)
				{
					result[any_byte_pos] = static_cast<std::uint8_t>(bn - any_byte_pos);
					any_byte_pos = 0;
				}
				any_byte = 0;
				result[bn++] = 0;
				i++;
			}

			return result;
		}

		template<std::size_t bc/*, std::uint8_t Seed*/>
		class pattern_wrapper {
			const std::array<std::uint8_t, bc>   m_bytes;
			const std::array<std::uint8_t, bc>   m_mask;
		public:
			template<size_t n>
			constexpr pattern_wrapper(const char(&str)[n]) :
				m_bytes{ convert_to_bytes_array<bc>(str) },
				m_mask{ convert_to_mask_array<bc>(str) }
			{}

			/* constexpr auto key() const {
				 return Seed;
			 }*/

			constexpr auto size() const {
				return bc;
			}

			constexpr auto byte_code() const {
				return m_bytes.data();
			}

			constexpr auto mask() const {
				return m_mask.data();
			}

			constexpr bool compare(const std::uintptr_t& start) const
			{
				size_t index_of = 0;
				for (std::uint8_t* pCur = reinterpret_cast<uint8_t*>(start);; pCur++)
				{
					auto mask_of = mask()[index_of];
					auto byte_of = byte_code()[index_of];
					if (mask_of || *pCur == byte_of)
					{
						index_of += max(mask_of, 1);
						pCur += max(mask_of - 1, 0);
						if (index_of < size())
							continue;
						return true;
					}
					break;
				}
				return false;
			}

			constexpr std::uint8_t* find(const std::uintptr_t& start, const std::uintptr_t& finish) const
			{
				auto index_of = 0;
				auto finish_s = reinterpret_cast<uint8_t*>(finish - size());
				for (std::uint8_t* pCur = reinterpret_cast<uint8_t*>(start); pCur < finish_s; pCur++)
				{
					auto mask_of = mask()[index_of];
					auto byte_of = byte_code()[index_of];
					if (mask_of || *pCur == byte_of)
					{
						index_of += max(mask_of, 1);
						pCur += max(mask_of - 1, 0);
						if (index_of < size())
							continue;
						return pCur - index_of + 1;
					}
					index_of = 0;
				}
				return nullptr;
			}

			uintptr_t find(uintptr_t module_base)
			{
				if (!module_base) return 0;

				auto image_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + reinterpret_cast<IMAGE_DOS_HEADER*>(module_base)->e_lfanew);
				auto module_end = module_base + image_nt_headers->OptionalHeader.SizeOfImage;

				return reinterpret_cast<uintptr_t>(find(module_base, module_end));
			}

			//constexpr address_t address(address_t start, uintptr_t range) const
			//{
			//	return address_t(find(start, range));
			//}
		};
	}
}

#define IDA(s) \
    (([]() { \
        using namespace omniz;\
        using namespace detail;\
        constexpr auto count = get_bytes_count(s); \
        constexpr auto out = pattern_wrapper<count>(s); \
        return out; \
    })())

//uintptr_t find_pattern(uintptr_t module_base, const char* pattern)
//{
//	auto pattern_ = pattern;
//	uintptr_t first_match = 0;
//
//	if (!module_base) return 0;
//
//	auto image_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + reinterpret_cast<IMAGE_DOS_HEADER*>(module_base)->e_lfanew);
//	auto module_end = module_base + image_nt_headers->OptionalHeader.SizeOfImage;
//
//	for (uintptr_t current = module_base; current < module_end; current++)
//	{
//		if (!*pattern_)
//			return first_match;
//
//		if (*(PBYTE)pattern_ == '\?' || *(BYTE*)current == getByte(pattern_))
//		{
//			if (!first_match)
//				first_match = current;
//
//			if (!pattern_[2])
//				return first_match;
//
//			if (*(PWORD)pattern_ == '\?\?' || *(PBYTE)pattern_ != '\?')
//				pattern_ += 3;
//
//			else
//				pattern_ += 2;
//		}
//		else
//		{
//			pattern_ = pattern;
//			first_match = 0;
//		}
//	}
//
//	return 0;
//}

uintptr_t resolve_rel_address(uintptr_t instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
	auto instr = instruction;
	LONG rip_offset = *(PLONG)(instr + OffsetOffset);
	uintptr_t resolved_addr = instr + InstructionSize + rip_offset;

	return resolved_addr;
}

bool find_pool_table(uintptr_t* pool_big_page_table, size_t* pool_big_page_table_size)
{
	//auto ex_protect_pool_ex_call_inst_address = find_pattern(kernel_base, "E8 ? ? ? ? 83 67 0C 00");

	auto ex_protect_pool_ex_call_inst_address = IDA("E8 ? ? ? ? 83 67 0C 00").find(kernel_base);

	if (!ex_protect_pool_ex_call_inst_address) return false;

	auto ex_protect_pool_ex_addr = resolve_rel_address(ex_protect_pool_ex_call_inst_address, 1, 5);

	if (!ex_protect_pool_ex_addr) return false;

	auto pool_big_page_table_inst_address = ex_protect_pool_ex_addr + 0x95;
	*pool_big_page_table = resolve_rel_address(pool_big_page_table_inst_address, 3, 7);

	auto pool_big_page_table_size_inst_addr = ex_protect_pool_ex_addr + 0x8E;
	*pool_big_page_table_size = resolve_rel_address(pool_big_page_table_size_inst_addr, 3, 7);

	return true;
}

bool remove_from_bigpool(uintptr_t base_address)
{
	uintptr_t _pool_big_page_table = 0;
	size_t _pool_big_page_table_size = 0;

	auto memcpy_ = KLI_FN(memcpy);

	if (find_pool_table(&_pool_big_page_table, &_pool_big_page_table_size))
	{
		PPOOL_TRACKER_BIG_PAGES pool_big_page_table = 0;
		memcpy_(&pool_big_page_table, (PVOID)_pool_big_page_table, 8);

		SIZE_T pool_big_page_table_size = 0;
		memcpy_(&pool_big_page_table_size, (PVOID)_pool_big_page_table_size, 8);

		for (int i = 0; i < pool_big_page_table_size; i++)
		{
			if (pool_big_page_table[i].Va == (void*)base_address || pool_big_page_table[i].Va == (void*)(base_address + 0x1))
			{
				pool_big_page_table[i].Va = (void*)0x1;
				pool_big_page_table[i].NumberOfBytes = 0x0;

				return true;
			}
		}

		return false;
	}

	return false;
}

bool null_pfn(PMDL mdl)
{
	PPFN_NUMBER mdl_pages = MmGetMdlPfnArray(mdl);
	if (!mdl_pages) { return false; }

	ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));

	ULONG null_pfn = 0x0;

	MM_COPY_ADDRESS source_address = { 0 };
	source_address.VirtualAddress = &null_pfn;

	auto mm_copy = KLI_FN(MmCopyMemory);

	for (ULONG i = 0; i < mdl_page_count; i++)
	{
		size_t bytes = 0;
		mm_copy(&mdl_pages[i], source_address, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &bytes);
	}

	return true;
}

bool clean_piddb_cache_table()
{
	auto piddb_lock_ptr = IDA("8B D8 85 C0 0F 88 ? ? ? ? 65 48 8B 04 25 ? ? ? ? 66 FF 88 ? ? ? ? B2 01 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B ? 24").find(kernel_base);
	auto piddb_cache_table_ptr = IDA("66 03 D2 48 8D 0D").find(kernel_base);

	if (!piddb_lock_ptr)
	{
		piddb_lock_ptr = IDA("48 8B 0D ? ? ? ? 48 85 C9 0F 85 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? E8").find(kernel_base);

		piddb_lock_ptr += 16;
	}
	else
	{
		piddb_lock_ptr += 28;
	}

	auto piddb_lock = resolve_rel_address(piddb_lock_ptr, 3, 7);
	auto piddb_cache_table = resolve_rel_address(piddb_cache_table_ptr, 6, 10);

	auto piddb_cache_table_ = reinterpret_cast<PRTL_AVL_TABLE>(piddb_cache_table);

	PiDDBCacheEntry* FirstEntry = reinterpret_cast<PiDDBCacheEntry*>(piddb_cache_table_->BalancedRoot.RightChild);

	KLI_FN(ExAcquireResourceExclusiveLite)(reinterpret_cast<void*>(piddb_lock), TRUE);

	auto rtl_enum_table = KLI_FN(RtlEnumerateGenericTableAvl);

	for (PiDDBCacheEntry* current_entry =
		(PiDDBCacheEntry*)rtl_enum_table(piddb_cache_table_, TRUE);			/* restart */
		current_entry != NULL;									/* as long as the current entry is valid */
		current_entry = (PiDDBCacheEntry*)rtl_enum_table(piddb_cache_table_, FALSE)	/* no restart, get latest element */
		)
	{
		if (current_entry->TimeDateStamp == _xor(0x58355A99))
		{
			KLI_FN(memcpy)(current_entry->DriverName.Buffer, _xor(L"monitor.sys"), 24);
			current_entry->DriverName.Length = 22;
			current_entry->DriverName.MaximumLength = 24;

			//KLI_FN(RtlInitUnicodeString)(&current_entry->DriverName, L"monitor.sys");
			current_entry->TimeDateStamp = _xor(0x54752b1b);

			//KLI_FN(DbgPrint)("[+] current_entry->DriverName: %ws\n", current_entry->DriverName.Buffer);
			//KLI_FN(DbgPrint)("[+] current_entry->DriverName Length: %i\n", current_entry->DriverName.Length);
			//KLI_FN(DbgPrint)("[+] current_entry->DriverName MaximumLength: %i\n", current_entry->DriverName.MaximumLength);

			KLI_FN(ExReleaseResourceLite)(reinterpret_cast<void*>(piddb_lock));

			return true;
		}
	}

	KLI_FN(ExReleaseResourceLite)(reinterpret_cast<void*>(piddb_lock));

	return false;
}

bool clean_kernel_hash_bucket_list()
{
	bool result = false;

	ULONG size = 0;
	auto module_base = get_module_base(_xor("ci.dll"), &size);

	//KLI_FN(DbgPrint)("[+] ci.dll base: %p\n", module_base);

	auto pattern_address = IDA("4C 8D 35 ? ? ? ? E9 ? ? ? ? 8B 84 24").find(module_base);

	//KLI_FN(DbgPrint)("[+] ci.dll pattern_address: %p\n", pattern_address);

	auto g_kernel_hash_bucket_list = reinterpret_cast<ULONGLONG*>(resolve_rel_address(pattern_address, 3, 7));

	//KLI_FN(DbgPrint)("[+] ci.dll g_kernel_hash_bucket_list: %p\n", g_kernel_hash_bucket_list);

	LARGE_INTEGER Time;
	KLI_FN(KeQuerySystemTimePrecise)(&Time);

	for (ULONGLONG i = *g_kernel_hash_bucket_list; i; i = *(ULONGLONG*)i) 
	{
		PWCHAR driver_name = PWCH(i + 0x48);

		if (_wcsstr(driver_name, _xor(L"phymem.sys")))
		{
			//_wcscpy(driver_name, _xor(L"\\Windows\\System32\\win32k.sys"));

			KLI_FN(memcpy)(driver_name, _xor(L"\\Windows\\System32\\win32k.sys"), 58);

			//KLI_FN(DbgPrint)("[+] hash_bucket_list_driver: %ws\n", driver_name);

			PUCHAR hash = PUCHAR(i + 0x18);
			for (UINT j = 0; j < 20; j++) hash[j] = UCHAR(KLI_FN(RtlRandomEx)(&Time.LowPart) % 255);

			result = true;
		}

		//KLI_FN(DbgPrint)("[+] hash_bucket_list_driver: %ws\n", driver_name);
	}

	return result;
}

enum COMMAND
{
	IS_VALID,
	READ_MEMORY,
	WRITE_MEMORY,
	ALLOCATE_MEMORY,
	ALLOCATE_KRNL_MEMORY,
	EXPOSE_MEM_TO_PROCESS,
	GET_PROCESS_MODULE
};

typedef struct _COMMAND_BUFFER {
	UINT64 m_command_id;
	UINT64 m_data[5];
	NTSTATUS m_status;
} COMMAND_BUFFER, * PCOMMAND_BUFFER;

uint64_t swap_process(uint64_t new_process)
{
	auto current_thread = KLI_FN(KeGetCurrentThread)();

	auto apc_state = *(uint64_t*)(current_thread + 0x98);
	auto old_process = *(uint64_t*)(apc_state + 0x20);
	*(uint64_t*)(apc_state + 0x20) = new_process;

	auto dir_table_base = *(uint64_t*)(new_process + 0x28);
	__writecr3(dir_table_base);

	return old_process;
}

struct page_info_t
{
	PML4E_64* m_pml4e;
	PDPTE_64* m_pdpte;
	PDE_64* m_pde;
	PTE_64* m_pte;
};

page_info_t get_page_info(
	PVOID VirtualAddress,
	CR3 HostCr3
) {
	ADDRESS_TRANSLATION_HELPER helper;
	UINT32 level;
	PML4E_64* pml4;
	PML4E_64* pml4e;
	PDPTE_64* pdpt;
	PDPTE_64* pdpte;
	PDE_64* pd;
	PDE_64* pde;
	PTE_64* pt;
	PTE_64* pte;

	//KLI_FN(DbgPrint)("[+] virtual address -> %p\n", VirtualAddress);

	auto mm_get_v4p = KLI_FN(MmGetVirtualForPhysical);

	page_info_t info;

	helper.AsUInt64 = (UINT64)VirtualAddress;

	PHYSICAL_ADDRESS addr;

	addr.QuadPart = HostCr3.AddressOfPageDirectory << PAGE_SHIFT;

	pml4 = (PML4E_64*)mm_get_v4p(addr);

	pml4e = &pml4[helper.AsIndex.Pml4];

	info.m_pml4e = pml4e;

	if (pml4e->Present == FALSE) 
	{
		info.m_pte = nullptr;
		info.m_pde = nullptr;
		info.m_pdpte = nullptr;

		goto Exit;
	}

	addr.QuadPart = pml4e->PageFrameNumber << PAGE_SHIFT;

	pdpt = (PDPTE_64*)mm_get_v4p(addr);

	pdpte = &pdpt[helper.AsIndex.Pdpt];

	info.m_pdpte = pdpte;

	if ((pdpte->Present == FALSE) || (pdpte->LargePage != FALSE)) 
	{
		info.m_pte = nullptr;
		info.m_pde = nullptr;

		goto Exit;
	}

	addr.QuadPart = pdpte->PageFrameNumber << PAGE_SHIFT;

	pd = (PDE_64*)mm_get_v4p(addr);

	pde = &pd[helper.AsIndex.Pd];

	info.m_pde = pde;

	if ((pde->Present == FALSE) || (pde->LargePage != FALSE)) 
	{
		info.m_pte = nullptr;

		goto Exit;
	}

	addr.QuadPart = pde->PageFrameNumber << PAGE_SHIFT;

	pt = (PTE_64*)mm_get_v4p(addr);

	pte = &pt[helper.AsIndex.Pt];

	info.m_pte = pte;

	return info;

Exit:
	return info;
}

typedef union _virt_addr_t
{
	PVOID value;
	struct
	{
		ULONG64 offset : 12;
		ULONG64 pt_index : 9;
		ULONG64 pd_index : 9;
		ULONG64 pdpt_index : 9;
		ULONG64 pml4_index : 9;
		ULONG64 reserved : 16;
	};
} virt_addr_t, * pvirt_addr_t;
static_assert(sizeof(virt_addr_t) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef union _pml4e
{
	ULONG64 value;
	struct
	{
		ULONG64 present : 1;          // Must be 1, region invalid if 0.
		ULONG64 ReadWrite : 1;        // If 0, writes not allowed.
		ULONG64 user_supervisor : 1;   // If 0, user-mode accesses not allowed.
		ULONG64 PageWriteThrough : 1; // Determines the memory type used to access PDPT.
		ULONG64 page_cache : 1; // Determines the memory type used to access PDPT.
		ULONG64 accessed : 1;         // If 0, this entry has not been used for translation.
		ULONG64 Ignored1 : 1;
		ULONG64 page_size : 1;         // Must be 0 for PML4E.
		ULONG64 Ignored2 : 4;
		ULONG64 pfn : 36; // The page frame number of the PDPT of this PML4E.
		ULONG64 Reserved : 4;
		ULONG64 Ignored3 : 11;
		ULONG64 nx : 1; // If 1, instruction fetches not allowed.
	};
} pml4e, * ppml4e;
static_assert(sizeof(pml4e) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef union _pdpte
{
	ULONG64 value;
	struct
	{
		ULONG64 present : 1;          // Must be 1, region invalid if 0.
		ULONG64 rw : 1;        // If 0, writes not allowed.
		ULONG64 user_supervisor : 1;   // If 0, user-mode accesses not allowed.
		ULONG64 PageWriteThrough : 1; // Determines the memory type used to access PD.
		ULONG64 page_cache : 1; // Determines the memory type used to access PD.
		ULONG64 accessed : 1;         // If 0, this entry has not been used for translation.
		ULONG64 Ignored1 : 1;
		ULONG64 page_size : 1;         // If 1, this entry maps a 1GB page.
		ULONG64 Ignored2 : 4;
		ULONG64 pfn : 36; // The page frame number of the PD of this PDPTE.
		ULONG64 Reserved : 4;
		ULONG64 Ignored3 : 11;
		ULONG64 nx : 1; // If 1, instruction fetches not allowed.
	};
} pdpte, * ppdpte;
static_assert(sizeof(pdpte) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef union _pde
{
	ULONG64 value;
	struct
	{
		ULONG64 present : 1;          // Must be 1, region invalid if 0.
		ULONG64 ReadWrite : 1;        // If 0, writes not allowed.
		ULONG64 user_supervisor : 1;   // If 0, user-mode accesses not allowed.
		ULONG64 PageWriteThrough : 1; // Determines the memory type used to access PT.
		ULONG64 page_cache : 1; // Determines the memory type used to access PT.
		ULONG64 Accessed : 1;         // If 0, this entry has not been used for translation.
		ULONG64 Ignored1 : 1;
		ULONG64 page_size : 1; // If 1, this entry maps a 2MB page.
		ULONG64 Ignored2 : 4;
		ULONG64 pfn : 36; // The page frame number of the PT of this PDE.
		ULONG64 Reserved : 4;
		ULONG64 Ignored3 : 11;
		ULONG64 nx : 1; // If 1, instruction fetches not allowed.
	};
} pde, * ppde;
static_assert(sizeof(pde) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef union _pte
{
	ULONG64 value;
	struct
	{
		ULONG64 present : 1;          // Must be 1, region invalid if 0.
		ULONG64 ReadWrite : 1;        // If 0, writes not allowed.
		ULONG64 user_supervisor : 1;   // If 0, user-mode accesses not allowed.
		ULONG64 PageWriteThrough : 1; // Determines the memory type used to access the memory.
		ULONG64 page_cache : 1; // Determines the memory type used to access the memory.
		ULONG64 accessed : 1;         // If 0, this entry has not been used for translation.
		ULONG64 Dirty : 1;            // If 0, the memory backing this page has not been written to.
		ULONG64 PageAccessType : 1;   // Determines the memory type used to access the memory.
		ULONG64 Global : 1;           // If 1 and the PGE bit of CR4 is set, translations are global.
		ULONG64 Ignored2 : 3;
		ULONG64 pfn : 36; // The page frame number of the backing physical page.
		ULONG64 Reserved : 4;
		ULONG64 Ignored3 : 7;
		ULONG64 ProtectionKey : 4;  // If the PKE bit of CR4 is set, determines the protection key.
		ULONG64 nx : 1; // If 1, instruction fetches not allowed.
	};
} pte, * ppte;
static_assert(sizeof(pte) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef union _cr3
{
	ULONG64 flags;
	struct
	{
		ULONG64 reserved1 : 3;
		ULONG64 page_level_write_through : 1;
		ULONG64 page_level_cache_disable : 1;
		ULONG64 reserved2 : 7;
		ULONG64 dirbase : 36;
		ULONG64 reserved3 : 16;
	};
} cr3;

typedef struct _CURSOR_PAGE
{
	void* page; // virtual address
	ppte  pte;
	unsigned org_pfn; // original pfn
} CURSOR_PAGE, * PCURSOR_PAGE;

CURSOR_PAGE get_cursor()
{
	const auto cursor =
		KLI_FN(ExAllocatePool)(
			NonPagedPool,
			0x1000
		);

	KLI_FN(memset)(cursor, NULL, 0x1000);
	virt_addr_t addr_t{ cursor };

	const auto dirbase =
		::cr3{ __readcr3() }.dirbase;

	const auto pml4 =
		reinterpret_cast<ppml4e>(
			KLI_FN(MmGetVirtualForPhysical)(
				PHYSICAL_ADDRESS{ (LONGLONG)dirbase << 12 })) + addr_t.pml4_index;

	if (!KLI_FN(MmIsAddressValid)(pml4))
		return {};

	const auto pdpt =
		reinterpret_cast<ppdpte>(
			KLI_FN(MmGetVirtualForPhysical)(
				PHYSICAL_ADDRESS{ (LONGLONG)pml4->pfn << 12 })) + addr_t.pdpt_index;

	if (!KLI_FN(MmIsAddressValid)(pdpt))
		return {};

	const auto pd =
		reinterpret_cast<ppde>(
			KLI_FN(MmGetVirtualForPhysical)(
				PHYSICAL_ADDRESS{ (LONGLONG)pdpt->pfn << 12 })) + addr_t.pd_index;

	if (!KLI_FN(MmIsAddressValid)(pd))
		return {};

	const auto pt =
		reinterpret_cast<ppte>(
			KLI_FN(MmGetVirtualForPhysical)(
				PHYSICAL_ADDRESS{ (LONGLONG)pd->pfn << 12 })) + addr_t.pt_index;

	if (!KLI_FN(MmIsAddressValid)(pt))
		return {};

	return { cursor, pt, (unsigned)pt->pfn };
}

CURSOR_PAGE cursor;

void set_user_on_page(uint64_t pid, void* addr)
{
	uint64_t peproc;

	if (NT_SUCCESS(KLI_FN(PsLookupProcessByProcessId)((HANDLE)pid, &peproc)) && peproc)
	{
		virt_addr_t addr_t{ addr };

		if (!cursor.pte || !cursor.org_pfn || !cursor.page)
		{
			KLI_FN(ObDereferenceObject)(peproc);
			return;
		}

		const auto dirbase = // dirbase is a pfn
			*reinterpret_cast<pte*>(
				peproc + 0x28);

		{
			cursor.pte->pfn = dirbase.pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
		}

		if (!KLI_FN(MmIsAddressValid)(reinterpret_cast<ppml4e>(cursor.page) + addr_t.pml4_index))
		{
			cursor.pte->pfn = cursor.org_pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
			KLI_FN(ObDereferenceObject)(peproc);
			return;
		}

		KLI_FN(KeFlushCurrentTbImmediately)();
		auto pml4e =
			reinterpret_cast<::pml4e*>(
				reinterpret_cast<ppml4e>(cursor.page) + addr_t.pml4_index);

		if (!pml4e->value || !pml4e->present || !pml4e->pfn)
		{
			cursor.pte->pfn = cursor.org_pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
			KLI_FN(ObDereferenceObject)(peproc);
			return;
		}

		pml4e->user_supervisor = TRUE;

		{
			cursor.pte->pfn = pml4e->pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
		}

		if (!KLI_FN(MmIsAddressValid)(reinterpret_cast<ppdpte>(cursor.page) + addr_t.pdpt_index))
		{
			cursor.pte->pfn = cursor.org_pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
			KLI_FN(ObDereferenceObject)(peproc);
			return;
		}

		KLI_FN(KeFlushCurrentTbImmediately)();
		auto pdpte =
			reinterpret_cast<::pdpte*>(
				reinterpret_cast<ppdpte>(cursor.page) + addr_t.pdpt_index);

		if (!pdpte->value || !pdpte->present || !pdpte->pfn)
		{
			cursor.pte->pfn = cursor.org_pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
			KLI_FN(ObDereferenceObject)(peproc);
			return;
		}

		pdpte->user_supervisor = TRUE;

		{
			cursor.pte->pfn = pdpte->pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
		}

		if (!KLI_FN(MmIsAddressValid)(reinterpret_cast<ppde>(cursor.page) + addr_t.pd_index))
		{
			cursor.pte->pfn = cursor.org_pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
			KLI_FN(ObDereferenceObject)(peproc);
			return;
		}

		KLI_FN(KeFlushCurrentTbImmediately)();
		auto pde =
			reinterpret_cast<::pde*>(
				reinterpret_cast<ppde>(cursor.page) + addr_t.pd_index);

		if (!pde->value || !pde->present || !pde->pfn)
		{
			cursor.pte->pfn = cursor.org_pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
			KLI_FN(ObDereferenceObject)(peproc);
			return;
		}

		pde->user_supervisor = TRUE;

		{
			cursor.pte->pfn = pde->pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
		}

		if (!KLI_FN(MmIsAddressValid)(reinterpret_cast<ppte>(cursor.page) + addr_t.pt_index))
		{
			cursor.pte->pfn = cursor.org_pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
			KLI_FN(ObDereferenceObject)(peproc);
			return;
		}

		KLI_FN(KeFlushCurrentTbImmediately)();
		auto pte =
			reinterpret_cast<::pte*>(
				reinterpret_cast<ppte>(cursor.page) + addr_t.pt_index);

		if (!pte->value || !pte->present || !pte->pfn)
		{
			cursor.pte->pfn = cursor.org_pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
			KLI_FN(ObDereferenceObject)(peproc);
			return;
		}

		pte->user_supervisor = TRUE;

		//
		// reset pfn
		//
		{
			cursor.pte->pfn = cursor.org_pfn;
			KLI_FN(KeFlushCurrentTbImmediately)();
		}

		KLI_FN(ObDereferenceObject)(peproc);
	}
}

struct mem_t
{
	PMDL m_mdl;
	uint64_t m_virt_addr;
};

mem_t allocate_mdl_memory(size_t size)
{
	mem_t mem_;

	PHYSICAL_ADDRESS LowAddress, HighAddress;
	LowAddress.QuadPart = 0;
	HighAddress.QuadPart = 0xffff'ffff'ffff'ffffULL;

	uint64_t pages = (size / PAGE_SIZE) + 1;

	auto mdl = KLI_FN(MmAllocatePagesForMdl)(LowAddress, HighAddress, LowAddress, pages * (uint64_t)PAGE_SIZE);

	if (!mdl) return { 0, 0 };

	auto mappingStartAddress = KLI_FN(MmMapLockedPagesSpecifyCache)(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	
	if (!mappingStartAddress) return { 0, 0 };

	auto status = KLI_FN(MmProtectMdlSystemAddress)(mdl, PAGE_EXECUTE_READWRITE);

	if (!NT_SUCCESS(status)) return { 0, 0 };

	mem_.m_mdl = mdl;
	mem_.m_virt_addr = mappingStartAddress;

	return mem_;
}

void free_mdl_memory(mem_t &mem)
{
	KLI_FN(MmUnmapLockedPages)(reinterpret_cast<void*>(mem.m_virt_addr), mem.m_mdl);
	KLI_FN(MmFreePagesFromMdl)(mem.m_mdl);
	KLI_FN(ExFreePool)(mem.m_mdl);
}

__int64 __fastcall hook_handler(PCOMMAND_BUFFER cmd_buffer)
{
	switch (cmd_buffer->m_command_id)
	{
		case IS_VALID:
		{
			cmd_buffer->m_status = TRUE;

			break;
		}

		case READ_MEMORY:
		{
			auto dst = cmd_buffer->m_data[0];
			auto src = cmd_buffer->m_data[1];
			auto size = cmd_buffer->m_data[2];
			auto process_id = cmd_buffer->m_data[3];

			break;
		}

		case WRITE_MEMORY:
		{
			auto dst = cmd_buffer->m_data[0];
			auto src = cmd_buffer->m_data[1];
			auto size = cmd_buffer->m_data[2];
			auto process_id = cmd_buffer->m_data[3];

			break;
		}

		case ALLOCATE_MEMORY:
		{
			auto size = SIZE_ALIGN(cmd_buffer->m_data[2]);
			auto process_id = cmd_buffer->m_data[3];
			PVOID base_address = nullptr;

			uint64_t process = 0;

			if (NT_SUCCESS(KLI_FN(PsLookupProcessByProcessId)((HANDLE)process_id, &process)))
			{
				auto old_process = swap_process(process);

				if (NT_SUCCESS(KLI_FN(ZwAllocateVirtualMemory)(ZwCurrentProcess(), &base_address, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
				{
					KLI_FN(MmSecureVirtualMemory)(base_address, size, PAGE_READWRITE);

					swap_process(old_process);

					KLI_FN(ObDereferenceObject)(process);

					cmd_buffer->m_status = TRUE;
					cmd_buffer->m_data[1] = reinterpret_cast<uint64_t>(base_address);
				}
				else
				{
					swap_process(old_process);

					KLI_FN(ObDereferenceObject)(process);
					cmd_buffer->m_status = FALSE;
				}
			}
			else
			{
				cmd_buffer->m_status = FALSE;
			}

			break;
		}

		case ALLOCATE_KRNL_MEMORY:
		{
			auto size = SIZE_ALIGN(cmd_buffer->m_data[2]);

			uint64_t kernel_address = 0;

			{
				auto mem_ = allocate_mdl_memory(size);

				while (mem_.m_virt_addr % 0x10000 != 0)
				{
					free_mdl_memory(mem_);
					mem_ = allocate_mdl_memory(size);
				}

				kernel_address = mem_.m_virt_addr;
			}

			cmd_buffer->m_data[1] = kernel_address;
			cmd_buffer->m_status = TRUE;

			break;
		}

		case EXPOSE_MEM_TO_PROCESS:
		{
			auto kernel_address = cmd_buffer->m_data[1];
			auto size = SIZE_ALIGN(cmd_buffer->m_data[2]);
			auto process_id = cmd_buffer->m_data[3];
			
			for (uint64_t addr_it = kernel_address; addr_it <= kernel_address + size; addr_it += PAGE_SIZE)
			{
				set_user_on_page(process_id, reinterpret_cast<void*>(addr_it));
			}

			cmd_buffer->m_status = TRUE;

			break;
		}
	}

	return 0;
}

void entry(uintptr_t image_base, size_t image_size)
{
	kernel_base = ::kli::detail::find_kernel_base();
	auto remove_result = remove_from_bigpool(image_base);

 //   KLI_FN(DbgPrint)("[+] kernel_base: %p\n", kernel_base);
	//KLI_FN(DbgPrint)("[+] image_base: %p\n", image_base);
	//KLI_FN(DbgPrint)("[+] image_size: %p\n", image_size);
	//KLI_FN(DbgPrint)("[+] remove_result: %s\n", remove_result ? "true" : "false");

	auto mdl = KLI_FN(IoAllocateMdl)(reinterpret_cast<void*>(image_base), image_base, FALSE, FALSE, NULL);

	//KLI_FN(DbgPrint)("[+] mdl: %p\n", mdl);

	auto nullpfn_result = null_pfn(mdl);

	//KLI_FN(DbgPrint)("[+] nullpfn_result: %s\n", nullpfn_result ? "true" : "false");

	auto clean_piddb_result = clean_piddb_cache_table();

	//KLI_FN(DbgPrint)("[+] clear_piddb_result: %s\n", clean_piddb_result ? "true" : "false");

	auto clean_kernel_hash_bucket_list_result = clean_kernel_hash_bucket_list();

	//KLI_FN(DbgPrint)("[+] clean_kernel_hash_bucket_list_result: %s\n", clean_kernel_hash_bucket_list_result ? "true" : "false");

	auto mi_get_pte_address = IDA("48 23 C8 48 B8 ? ? ? ? ? ? ? ? 48 03 C1 C3").find(kernel_base);
	auto pte_base_value = *reinterpret_cast<uint64_t*>(mi_get_pte_address + 0x5);

	uint64_t mask = (1ll << (PHYSICAL_ADDRESS_BITS - 1)) - 1;
	pde_base = (pte_base_value & ~mask) | ((pte_base_value >> 9) & mask);
	pte_base = pte_base_value;

	// setup hook

	auto second_function_address = IDA("48 89 5C 24 ? 57 48 83 EC 20 48 8B 05 ? ? ? ? 48 8B FA").find(kernel_base);

	//KLI_FN(DbgPrint)("[+] second_function_address: %p\n", second_function_address);

	auto second_ptr_address = resolve_rel_address(second_function_address + 0xa, 3, 7);

	//KLI_FN(DbgPrint)("[+] second_ptr_address: %p\n", second_ptr_address);

	auto first_function_address = IDA("40 53 48 83 EC 20 48 8B D9 48 83 64 24 ? ?").find(kernel_base);

	//KLI_FN(DbgPrint)("[+] first_function_address: %p\n", first_function_address);

	auto first_ptr_address = resolve_rel_address(first_function_address + 0x30, 3, 7);

	//KLI_FN(DbgPrint)("[+] first_ptr_address: %p\n", first_ptr_address);

	char hook_shellcode[] = 
	{ 
		0x48, 0x89, 0xD9, 
		0x48, 0xB8, 0xF4, 0xFF, 0xF3, 0xFF, 0xF2, 0xFF, 0xF1, 0xFF, 
		0xFF, 0xE0 
	};

	KLI_FN(memcpy)(reinterpret_cast<void*>(image_base), &hook_shellcode, sizeof(hook_shellcode));

	*reinterpret_cast<void**>(image_base + 0x5) = &hook_handler;

	//// NtQueryAuxiliaryCounterFrequency ref
	//auto first_ptr_address = kernel_base + 0xC00930;

	//// KseHookExAllocatePoolWithTag ref
	//auto second_ptr_address = kernel_base + 0xC04A28;
	//auto second_function_address = kernel_base + 0x521F00;

	InterlockedExchangePointer(reinterpret_cast<void**>(first_ptr_address), reinterpret_cast<void*>(second_function_address));
	InterlockedExchangePointer(reinterpret_cast<void**>(second_ptr_address), reinterpret_cast<void*>(image_base));

	cursor = get_cursor();
}