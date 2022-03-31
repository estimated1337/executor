#include "common.hpp"

__forceinline void hexdump(void* ptr, int buflen) 
{
    unsigned char* buf = (unsigned char*)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16) {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        printf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printf("\n");
    }
}

int main()
{
	c_util::get()->grant_privileges({ L"SeDebugPrivilege",  L"SeLoadDriverPrivilege" });

	if (!c_bootstrap::get()->startup())
	{
		std::cout << "error c_bootstrap::get()->startup()" << std::endl;
		return 0;
	}

    if (!c_executor::get()->startup())
    {
        std::cout << "c_executor::get()->startup()" << std::endl;
        c_bootstrap::get()->cleanup();
        return 0;
    }

    const auto fn = c_kernel::get()->get_ntoskrnl_export("DbgPrint");

    c_executor::get()->exec
    (
        [&](handler_ctx_t ctx) -> void
        {
            reinterpret_cast<DbgPrint_t>(fn)("[+] ya ebal");
        }
    );

	c_bootstrap::get()->cleanup();

	return 0;
}