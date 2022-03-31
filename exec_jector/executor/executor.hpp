#pragma once

class c_executor : public s<c_executor>
{
public:
	bool startup();
	bool exec(callback_t cb);
};