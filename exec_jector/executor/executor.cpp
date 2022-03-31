#include "../common.hpp"

bool c_executor::startup()
{
	const auto ke_query_affinity = c_kernel::get()->get_ntoskrnl_export("KeQueryActiveProcessors");
	const auto ke_set_affinity = c_kernel::get()->get_ntoskrnl_export("KeSetSystemAffinityThread");
	const auto mm_get = c_kernel::get()->get_ntoskrnl_export("MmGetSystemRoutineAddress");

	//util::logger::debug("ke_query_affinity: 0x%p", ke_query_affinity);
	//util::logger::debug("ke_set_affinity: 0x%p", ke_set_affinity);
	//util::logger::debug("mm_get: 0x%p", mm_get);

	auto shell = c_util::get()->craft_shellcode(mm_get, ke_set_affinity, ke_query_affinity);
	const auto drv_addr = c_kernel::get()->get_kernel_module(c_service::get()->get_name() + ".sys");
	const auto function_to_patch = c_phymem::get()->vtop(drv_addr + c_phymem::get()->target_function_rva());

	//util::logger::debug("function_to_patch: 0x%p", function_to_patch);

	c_phymem::get()->write_phys(function_to_patch, shell.get(), shell.size());

	//util::logger::info("Successfully patched handler");

	return true;
}

callback_t callback;

void __fastcall shell_executor(handler_ctx_t ctx) 
{
	callback(ctx);
}

bool c_executor::exec(callback_t cb)
{
	callback = cb;

	return c_phymem::get()->send_callback_request(&shell_executor);
}
