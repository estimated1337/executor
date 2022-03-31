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

#define OXORANY_DISABLE_OBFUSCATION

#include "misc/oxorany.hpp"
#include "misc/lazy_importer.hpp"

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

class c_driver
{
private:
	NtQueryAuxiliaryCounterFrequency_t syscall_fn;

	void send_command(COMMAND_BUFFER& cmd_buffer)
	{
		syscall_fn(&cmd_buffer);
	}

public:
	c_driver() : syscall_fn(nullptr)
	{
		syscall_fn = ::li::detail::lazy_function
			<
			LAZY_IMPORTER_KHASH("NtQueryAuxiliaryCounterFrequency"),
			NtQueryAuxiliaryCounterFrequency_t
			>().get();
	}

	bool is_mapped()
	{
		COMMAND_BUFFER cmd;

		cmd.m_command_id = IS_VALID;
		memset(&cmd.m_data, 0, sizeof(cmd.m_data));
		cmd.m_status = FALSE;

		send_command(cmd);

		return cmd.m_status == TRUE;
	}

	bool allocate_user_memory(uint64_t process_id, uint64_t& address, size_t size)
	{
		COMMAND_BUFFER cmd;

		cmd.m_command_id = ALLOCATE_MEMORY;
		memset(&cmd.m_data, 0, sizeof(cmd.m_data));

		cmd.m_data[2] = size;
		cmd.m_data[3] = process_id;
		cmd.m_status = FALSE;

		send_command(cmd);

		const bool result = cmd.m_status == TRUE;

		if (result)
		{
			address = cmd.m_data[1];
		}

		return result;
	}

	bool allocate_krnl_memory(uint64_t& address, size_t size)
	{
		COMMAND_BUFFER cmd;

		cmd.m_command_id = ALLOCATE_KRNL_MEMORY;
		memset(&cmd.m_data, 0, sizeof(cmd.m_data));

		cmd.m_data[2] = size;
		//cmd.m_data[3] = process_id;
		//cmd.m_data[4] = cur_proc_id;
		cmd.m_status = FALSE;

		send_command(cmd);

		const bool result = cmd.m_status == TRUE;

		if (result)
		{
			address = cmd.m_data[1];
		}

		return result;
	}

	bool expose_mem_to_process(uint64_t process_id, uint64_t address, size_t size)
	{
		COMMAND_BUFFER cmd;

		cmd.m_command_id = EXPOSE_MEM_TO_PROCESS;
		memset(&cmd.m_data, 0, sizeof(cmd.m_data));

		cmd.m_data[1] = address;
		cmd.m_data[2] = size;
		cmd.m_data[3] = process_id;
		cmd.m_status = FALSE;

		send_command(cmd);

		const bool result = cmd.m_status == TRUE;

		if (result)
		{
			address = cmd.m_data[1];
		}

		return result;
	}
};

enum e_gametype
{
	UnrealWindow
};

struct mmap_data_t
{
	uint64_t m_address;
	uint64_t m_size;
	uint64_t m_entrypoint;
	uint64_t m_gametype;
};

typedef struct _main_struct
{
	int status;
	uintptr_t fn_dll_main;
	HINSTANCE dll_base;
} main_struct;

template <typename destt, typename srct>
void __memcpy(destt Destination, srct Source, SIZE_T Count) {
	__movsb((PBYTE)Destination, (BYTE*)Source, Count);
}

void entry(mmap_data_t* mmap_data)
{
	c_driver driver;

	if (driver.is_mapped())
	{
		ulong_t process_id = 0;
		ulong_t thread_id = 0;

		while (!process_id)
		{
			thread_id = LI_FN(GetWindowThreadProcessId).get()(LI_FN(FindWindowW).get()(_xor(L"UnityWndClass"), NULL), &process_id);
			LI_FN(Sleep).get()(20);
		}

		auto current_proc_id = LI_FN(GetCurrentProcessId).get()();

		driver.expose_mem_to_process(current_proc_id, mmap_data->m_address, mmap_data->m_size);
		driver.expose_mem_to_process(process_id, mmap_data->m_address, mmap_data->m_size);

		BYTE remote_call_dll_main[92] =
		{
			0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24,
			0x20, 0x83, 0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48,
			0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B,
			0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
		};

		DWORD shell_data_offset = 0x6;

		HMODULE nt_dll = LI_FN(LoadLibraryW).get()(_xor(L"ntdll.dll"));

		DWORD shell_size = sizeof(remote_call_dll_main) + sizeof(main_struct);

		PVOID alloc_local = LI_FN(VirtualAlloc).get()(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		memcpy(alloc_local, &remote_call_dll_main, sizeof(remote_call_dll_main));
		uintptr_t shell_data = mmap_data->m_address + sizeof(remote_call_dll_main);
		*(uintptr_t*)((uintptr_t)alloc_local + shell_data_offset) = shell_data;
		main_struct* main_data = (main_struct*)((uintptr_t)alloc_local + sizeof(remote_call_dll_main));
		main_data->dll_base = (HINSTANCE)mmap_data->m_address;
		main_data->fn_dll_main = mmap_data->m_entrypoint;

		__memcpy(reinterpret_cast<void*>(mmap_data->m_address), alloc_local, shell_size);

		HHOOK h_hook = LI_FN(SetWindowsHookExW).get()(WH_GETMESSAGE, (HOOKPROC)reinterpret_cast<void*>(mmap_data->m_address), nt_dll, thread_id);

		while (main_data->status != 2)
		{
			LI_FN(PostThreadMessageW).get()(thread_id, WM_NULL, 0, 0);
			__memcpy((PVOID)main_data, (PVOID)shell_data, sizeof(main_struct));
			LI_FN(Sleep).get()(10);
		}

		LI_FN(UnhookWindowsHookEx).get()(h_hook);

		LI_FN(VirtualFree).get()(alloc_local, 0, MEM_RELEASE);
	}
}