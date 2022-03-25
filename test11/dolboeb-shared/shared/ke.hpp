#pragma once
#include <Windows.h>
#include <winternl.h>

namespace shared::ke {
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

	using KeSetSystemAffinityThread_t = void( * )( KAFFINITY );
	using KeQueryActiveProcessors_t = KAFFINITY( * )( );
	using MmGetSystemRoutineAddress_t = void*( * )( PUNICODE_STRING );
	using DbgPrint_t = void( * )( const char*, ... );
    using ExAllocatePool_t = void* ( * )( POOL_TYPE, SIZE_T );
    using RtlCopyMemory_t = void ( * )( void*, void*, SIZE_T );
    using DriverEntry_t = NTSTATUS ( * )( void*, void* );
}
