#pragma once

class c_util : public s<c_util>
{
public:
	std::string random_string(std::string::size_type size);
	void grant_privileges(const std::vector<std::wstring_view> names);
	c_shellcode craft_shellcode(uint64_t mm_get, uint64_t ke_set_affinity, uint64_t ke_query_affinity);
};