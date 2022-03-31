#pragma once

class c_bootstrap : public s<c_bootstrap>
{
public:
	bool startup();
	bool cleanup();
};