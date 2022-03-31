#pragma once

class c_service : public s<c_service>
{
public:
	bool start(unsigned char* buffer, size_t size, const std::string& name);
	bool stop();
	std::string get_name() { return m_name; };

private:
	bool run(const std::string& path);

	std::string m_name;
};