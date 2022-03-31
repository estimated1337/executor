#pragma once

template<typename t>
class s
{
public:
	template<typename... args_t>
	static t* get(args_t&&... args);
protected:
	s() = default;
	~s() = default;
};

template<typename t>
template<typename... args_t>
t* s<t>::get(args_t&&... args)
{
	static t instance(std::forward<args_t>(args)...);
	t* inst = &instance;
	return inst;
}
