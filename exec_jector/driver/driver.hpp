#pragma once

class c_driver : public s<c_driver>
{
public:
	c_driver();

	bool mmap_driver();
	bool clean_traces();
	bool is_mapped();
	bool allocate_user_memory(uint64_t process_id, uint64_t& address, size_t size);
	bool allocate_krnl_memory(uint64_t& address, size_t size);
	bool expose_mem_to_process(uint64_t process_id, uint64_t address, size_t size);
	
private:
	void send_command(COMMAND_BUFFER& cmd_buffer);

	NtQueryAuxiliaryCounterFrequency_t syscall_fn;
};