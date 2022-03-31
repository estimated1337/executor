#include "../../common.hpp"

bool c_phymem::control(control_ctx_t& control_io, e_control_code ctl_code)
{
	ulong_t bytes_returned;
	return DeviceIoControl(get_device_handle(), static_cast<DWORD>(ctl_code), &control_io, sizeof(control_ctx_t), &control_io, sizeof(control_ctx_t), &bytes_returned, 0);
}

uint64_t c_phymem::find_ntos_dirbase()
{
	uint8_t* buffer = new uint8_t[0x10000];

	for (int i = 0; i < 10; i++) {
		if (!read_phys(static_cast<uint64_t>(i) * 0x10000, buffer, 0x10000))
			continue;

		for (int offset = 0; offset < 0x10000; offset += 0x1000) {
			if ((0x00000001000600E9 ^ (0xffffffffffff00ff & *(uint64_t*)(buffer + offset))) ||
				(0xfffff80000000000 ^ (0xfffff80000000000 & *(uint64_t*)(buffer + offset + 0x70))) ||
				(0xffffff0000000fff & *(uint64_t*)(buffer + offset + 0xA0)))
				continue;

			uint64_t directory_base = *(uint64_t*)(buffer + offset + 0xA0);
			delete[] buffer;

			return directory_base;
		}
	}

	delete[] buffer;
	return 0;
}

uint64_t c_phymem::vtop(const uint64_t virt_addr)
{
	uint64_t dir_base = get_directory_base();

	if (!dir_base)
		return 0;

	//read PML4E
	uint64_t PML4E = 0;
	uint16_t PML4 = (uint16_t)((virt_addr >> 39) & 0x1FF);
	read_phys(dir_base + (PML4 * 8), reinterpret_cast<uint8_t*>(&PML4E), 8);
	if (!PML4E)
		return 0;

	//read PDPTE 
	uint64_t PDPTE = 0;
	uint16_t DirPtr = (uint16_t)((virt_addr >> 30) & 0x1FF);
	read_phys((PML4E & 0xFFFFFFFFFF000) + (DirPtr * 8), reinterpret_cast<uint8_t*>(&PDPTE), 8);
	if (!PDPTE)
		return 0;

	//PS=1 (1GB page)
	if ((PDPTE & (1 << 7)) != 0) {
		//if (PageSize) *PageSize = 0x40000000/*1Gb*/;
		return (PDPTE & 0xFFFFFC0000000) + (virt_addr & 0x3FFFFFFF);
	}

	//read PDE 
	uint64_t PDE = 0;
	uint16_t Dir = (uint16_t)((virt_addr >> 21) & 0x1FF);
	read_phys((PDPTE & 0xFFFFFFFFFF000) + (Dir * 8), reinterpret_cast<uint8_t*>(&PDE), 8);
	if (!PDE)
		return 0;

	//PS=1 (2MB page)
	if ((PDE & (1 << 7)) != 0) {
		//if (PageSize) *PageSize = 0x200000/*2MB*/;
		return (PDE & 0xFFFFFFFE00000) + (virt_addr & 0x1FFFFF);
	}

	//read PTE
	uint64_t PTE = 0;
	uint16_t Table = (uint16_t)((virt_addr >> 12) & 0x1FF);
	read_phys((PDE & 0xFFFFFFFFFF000) + (Table * 8), reinterpret_cast<uint8_t*>(&PTE), 8);
	if (!PTE)
		return 0;

	//BasePage (4KB Page)
	//if (PageSize) *PageSize = 0x1000/*4KB*/;
	return (PTE & 0xFFFFFFFFFF000) + (virt_addr & 0xFFF);
}

bool c_phymem::read_phys(const uint64_t phys_addr, uint8_t* buffer, const uint64_t size) {
	control_ctx_t ctx = {};
	ctx.m_physical_address = phys_addr;
	ctx.m_size = size;

	if (!control(ctx, e_control_code::map))
		return false;

	if (!ctx.m_user_address)
		return false;

	memcpy(buffer, reinterpret_cast<void*>(ctx.m_user_address), size);

	control_ctx_t ctx2 = {};
	memcpy(&ctx2, &ctx, sizeof(ctx2));

	return control(ctx2, e_control_code::unmap);
}

bool c_phymem::write_phys(const uint64_t phys_addr, uint8_t* buffer, const uint64_t size) {
	control_ctx_t ctx = {};
	ctx.m_physical_address = phys_addr;
	ctx.m_size = size;

	if (!control(ctx, e_control_code::map))
		return false;

	if (!ctx.m_user_address)
		return false;

	memcpy(reinterpret_cast<void*>(ctx.m_user_address), buffer, size);

	control_ctx_t ctx2 = {};
	memcpy(&ctx2, &ctx, sizeof(ctx2));

	return control(ctx2, e_control_code::unmap);
}

bool c_phymem::send_callback_request(void* shell_executor_addr) {
	control_ctx_t ctx;
	ctx.m_physical_address = reinterpret_cast<uint64_t>(shell_executor_addr);
	return control(ctx, e_control_code::map);
}

bool c_phymem::setup_driver() 
{
	return c_service::get()->start(phymemx_sys, sizeof(phymemx_sys), c_util::get()->random_string(16));
}

bool c_phymem::init() {
	set_device_handle(CreateFileW(L"\\\\.\\PhyMem", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
	const auto result = static_cast<bool>(get_device_handle());
	//dolboeb::util::logger::debug("Device: 0x%x", get_device_handle());
	if (result) set_directory_base(find_ntos_dirbase());
	return result;
}

bool c_phymem::unload_driver() 
{
	return c_service::get()->stop();
}