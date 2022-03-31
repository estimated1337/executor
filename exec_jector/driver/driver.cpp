#include "../common.hpp"

c_driver::c_driver()
{
	syscall_fn = ::li::detail::lazy_function
	<
		LAZY_IMPORTER_KHASH("NtQueryAuxiliaryCounterFrequency"), 
		NtQueryAuxiliaryCounterFrequency_t
	>().get();
}

void c_driver::send_command(COMMAND_BUFFER& cmd_buffer)
{
	syscall_fn(&cmd_buffer);
}

bool c_driver::mmap_driver()
{
	return false;
}

bool c_driver::clean_traces()
{
	return false;
}

bool c_driver::is_mapped()
{
	return false;

	COMMAND_BUFFER cmd;

	cmd.m_command_id = IS_VALID;
	memset(&cmd.m_data, 0, sizeof(cmd.m_data));
	cmd.m_status = FALSE;

	send_command(cmd);

	return cmd.m_status == TRUE;
}

bool c_driver::allocate_user_memory(uint64_t process_id, uint64_t& address, size_t size)
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

bool c_driver::allocate_krnl_memory(uint64_t& address, size_t size)
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

bool c_driver::expose_mem_to_process(uint64_t process_id, uint64_t address, size_t size)
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