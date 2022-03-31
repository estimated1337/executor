#pragma once

class c_phymem : public s<c_phymem>
{
public:
	uint64_t target_function_rva() { return 0x13E0; }
	HANDLE get_device_handle() { return m_device_handle; }
	uint64_t get_directory_base() { return m_directory_base; }
	void set_directory_base(uint64_t base) { m_directory_base = base; }
	void set_device_handle(HANDLE handle) { m_device_handle = handle; }

	bool control(control_ctx_t& control_io, e_control_code ctl_code);
	bool read_phys(const uint64_t phys_addr, uint8_t* buffer, const uint64_t size);
	bool write_phys(const uint64_t phys_addr, uint8_t* buffer, const uint64_t size);

	uint64_t find_ntos_dirbase();
	uint64_t vtop(const uint64_t virt_addr);

	bool send_callback_request(void* shell_executor_addr);
	bool setup_driver();
	bool init();
	bool unload_driver();

private:
	HANDLE m_device_handle;
	uint64_t m_directory_base;
};

