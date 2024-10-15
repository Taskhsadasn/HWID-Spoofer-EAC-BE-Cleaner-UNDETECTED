#include "mapp.hpp"
#include "utils.hpp"
#include "xorstr.hpp"

HANDLE ttConsole = GetStdHandle(STD_OUTPUT_HANDLE);

uint64_t lksmapp::MapDriver(HANDLE vul_driver_device_handle, std::vector<uint8_t> raw_image)
{

	const PIMAGE_NT_HEADERS64 nt_headers = portable::GetNtHeaders(raw_image.data());

	if (!nt_headers)
	{
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		return 0;
	}

	const uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	uint64_t kernel_image_base = vul_driver::AllocatePool(vul_driver_device_handle, nt::NonPagedPool, image_size);

	do
	{
		if (!kernel_image_base)
		{
			break;
		}
		SetConsoleTextAttribute(ttConsole, 10);

		// Copy image headers

		std::memcpy(local_image_base, raw_image.data(), nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
		{
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(local_image_base) + current_image_section[i].VirtualAddress);
			std::memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(raw_image.data()) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}

		// Resolve relocs and imports

		RelocateImageByDelta(portable::GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!ResolveImports(vul_driver_device_handle, portable::GetImports(local_image_base)))
		{
			break;
		}

		// Write fixed image to kernel

		if (!vul_driver::WriteMemory(vul_driver_device_handle, kernel_image_base, local_image_base, image_size))
		{
			break;
		}

		VirtualFree(local_image_base, 0, MEM_RELEASE);

		// Call driver entry point

		const uint64_t address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		SetConsoleTextAttribute(ttConsole, 10);

		NTSTATUS status = 0;

		if (!vul_driver::CallKernelFunction(vul_driver_device_handle, &status, address_of_entry_point))
		{
			break;
		}
		BlockInput(TRUE);
		SetConsoleTextAttribute(ttConsole, 10);
		utilitiesy::slow_print(XorString("\n\n                    ---->               ["), 9);
		SetConsoleTextAttribute(ttConsole, 8);
		utilitiesy::slow_print(XorString("+"), 9);
		SetConsoleTextAttribute(ttConsole, 10);
		utilitiesy::slow_print(XorString("]"), 9);
		utilitiesy::slow_print(XorString(" Spoof "), 9);
		SetConsoleTextAttribute(ttConsole, 3);
		utilitiesy::slow_print(XorString("SMBIOS"), 9);
		Sleep(1000);
		SetConsoleTextAttribute(ttConsole, 10);
		utilitiesy::slow_print(XorString("\n\n                    ---->               ["), 9);
		SetConsoleTextAttribute(ttConsole, 8);
		utilitiesy::slow_print(XorString("+"), 9);
		SetConsoleTextAttribute(ttConsole, 10);
		utilitiesy::slow_print(XorString("]"), 9);
		utilitiesy::slow_print(XorString(" Spoof "), 9);
		SetConsoleTextAttribute(ttConsole, 3);
		utilitiesy::slow_print(XorString("CPU"), 9);
		Sleep(1000);
		SetConsoleTextAttribute(ttConsole, 10);
		utilitiesy::slow_print(XorString("\n\n                    ---->               ["), 9);
		SetConsoleTextAttribute(ttConsole, 8);
		utilitiesy::slow_print(XorString("+"), 9);
		SetConsoleTextAttribute(ttConsole, 10);
		utilitiesy::slow_print(XorString("]"), 9);
		utilitiesy::slow_print(XorString(" Spoof "), 9);
		SetConsoleTextAttribute(ttConsole, 3);
		utilitiesy::slow_print(XorString("Disks Serials"), 9);
		Sleep(1000);
		SetConsoleTextAttribute(ttConsole, 10);
		utilitiesy::slow_print(XorString("\n\n                    ---->               ["), 15);
		SetConsoleTextAttribute(ttConsole, 8);
		utilitiesy::slow_print(XorString("+"), 15);
		SetConsoleTextAttribute(ttConsole, 10);
		utilitiesy::slow_print(XorString("]"), 15);
		utilitiesy::slow_print(XorString(" Spoof "), 15);
		SetConsoleTextAttribute(ttConsole, 3);
		utilitiesy::slow_print(XorString("RAM\n"), 15);
		Sleep(5000);
		// Erase PE headers
		vul_driver::SetMemory(vul_driver_device_handle, kernel_image_base, 0, nt_headers->OptionalHeader.SizeOfHeaders);
		Sleep(1000);
		BlockInput(FALSE);
		return kernel_image_base;

	} while (false);
	VirtualFree(local_image_base, 0, MEM_RELEASE);
	vul_driver::FreePool(vul_driver_device_handle, kernel_image_base);
	return 0;
}

void lksmapp::RelocateImageByDelta(portable::vec_relocs relocs, const uint64_t delta)
{
	for (const auto& current_reloc : relocs)
	{
		for (auto i = 0u; i < current_reloc.count; ++i)
		{
			const uint16_t type = current_reloc.item[i] >> 12;
			Sleep(1000);
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				* reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}

bool lksmapp::ResolveImports(HANDLE vul_driver_device_handle, portable::vec_imports imports)
{
	Sleep(1000);
	for (const auto& current_import : imports)
	{
		if (!utilitiesy::GetKernelModuleAddress(current_import.module_name))
		{
			SetConsoleTextAttribute(ttConsole, 12);
			return false;
		}
		for (auto& current_function_data : current_import.function_datas)
		{
			const uint64_t function_address = vul_driver::GetKernelModuleExport(vul_driver_device_handle, utilitiesy::GetKernelModuleAddress(current_import.module_name), current_function_data.name);

			if (!function_address)
			{
				SetConsoleTextAttribute(ttConsole, 10);
				return false;
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}