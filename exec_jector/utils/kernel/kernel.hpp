#pragma once

class c_kernel : public s<c_kernel>
{
public:
	c_kernel();
	~c_kernel();
	//
	// Gets kernel module
	uint64_t get_kernel_module(const std::string& module_name);

	//
	// Gets ntoskrnl export
	uint64_t get_ntoskrnl_export(const std::string& fn_name);

private:
	HMODULE m_ntoskrnl = 0x0;
};