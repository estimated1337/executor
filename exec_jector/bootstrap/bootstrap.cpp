#include "../common.hpp"

bool c_bootstrap::startup()
{
	if (!c_phymem::get()->setup_driver())
	{
		return false;
	}

	if (!c_phymem::get()->init())
	{
		return false;
	}

	return true;
}

bool c_bootstrap::cleanup()
{
	if (!c_phymem::get()->unload_driver())
	{
		return false;
	}

	return true;
}
