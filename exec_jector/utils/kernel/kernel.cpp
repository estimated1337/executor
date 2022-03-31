#include "../../common.hpp"

c_kernel::c_kernel()
{
	m_ntoskrnl = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
}

c_kernel::~c_kernel()
{
	FreeLibrary(m_ntoskrnl);
}

uint64_t c_kernel::get_kernel_module(const std::string& module_name)
{
	void* buffer = nullptr;
	DWORD buffer_size = 0;

	NTSTATUS status = LI_FN(NtQuerySystemInformation).get()(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = LI_FN(NtQuerySystemInformation).get()(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status)) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
	if (!modules)
		return 0;

	for (auto i = 0u; i < modules->NumberOfModules; ++i) {
		const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

		if (!_stricmp(current_module_name.c_str(), module_name.c_str())) {
			const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}

uint64_t c_kernel::get_ntoskrnl_export(const std::string& fn_name)
{
	const uint64_t ntos_local_address = reinterpret_cast<uint64_t>(GetProcAddress(m_ntoskrnl, fn_name.c_str()));
	const uint64_t ntos_fn_offset = ntos_local_address - reinterpret_cast<uint64_t>(m_ntoskrnl);

	const uint64_t ntos_address = get_kernel_module("ntoskrnl.exe");

	return ntos_local_address ? ntos_address + ntos_fn_offset : 0;
}
