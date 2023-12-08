#include "pch.h"
#include "Shellcode.h"
#include "Memory.h"

std::vector<std::string> blacklist = {"kernel32.dll", "kernelbase.dll", "wow64.dll", "wow64win.dll", "wow64cpu.dll", "ntoskrnl.exe", "win32kbase.sys"};

uint64_t c_shellcode::find_codecave(size_t function_size, std::string process_name, std::string module)
{
	int pid = mem.GetPidFromName(process_name);
	VMMDLL_PROCESS_INFORMATION process_info = {0};
	process_info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
	process_info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
	SIZE_T process_info_size = sizeof(VMMDLL_PROCESS_INFORMATION);
	if (!VMMDLL_ProcessGetInformation(mem.vHandle, pid, &process_info, &process_info_size))
	{
		LOG("[!] Could not retrieve process for PID: %i", pid);
		return 0;
	}

	DWORD cSections = 0;
	if (!VMMDLL_ProcessGetSectionsU(mem.vHandle, pid, (LPSTR)module.c_str(), NULL, 0, &cSections) || !cSections)
	{
		LOG("[!] Could not retrieve sections #1 for '%s'\n", module.c_str());
		return 0;
	}
	PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)LocalAlloc(LMEM_ZEROINIT, cSections * sizeof(IMAGE_SECTION_HEADER));
	if (!pSections || !VMMDLL_ProcessGetSectionsU(mem.vHandle, pid, (LPSTR)module.c_str(), pSections, cSections, &cSections) || !cSections)
	{
		LOG("[!] Could not retrieve sections #2 for '%s'\n", module);
		return 0;
	}

	/*Scan for code cave*/
	uint64_t codecave = 0;
	for (int i = 0; i < cSections; i++)
	{
		if (!codecave && ((pSections[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ))) && ((pSections[i].Misc.VirtualSize & 0xfff) < (0x1000 - function_size)))
		{
			codecave = VMMDLL_ProcessGetModuleBaseU(mem.vHandle, pid, (LPSTR)module.c_str()) + ((pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize)) + 0x10;
			if (!codecave)
				break;
		}
	}
	if (!codecave)
	{
		LOG("[!] Could not find a code cave for '%s'\n", module.c_str());
		return 0;
	}

	auto buffer = std::unique_ptr<uint8_t[]>(new uint8_t(function_size));
	if (!mem.Read(codecave, buffer.get(), function_size, pid))
	{
		LOG("[!] Could not read codecave for '%s'\n", module.c_str());
		return 0;
	}

	for (size_t i = 0; i < function_size; i++)
	{
		if (buffer[i] != 0x0)
		{
			LOG("[!] Codecave isn't big enough for the shellcode.\n");
			return 0;
		}
	}

	return codecave;
}

std::vector<uint64_t> c_shellcode::find_all_codecave(size_t function_size, std::string process_name)
{
	std::vector<uint64_t> codecaves = { };
	std::vector<std::string> module_list = mem.GetModuleList(process_name);
	for (size_t i = 0; i < module_list.size(); i++)
	{
		if (std::find(blacklist.begin(), blacklist.end(), module_list[i]) != blacklist.end())
			continue;

		std::string module = module_list[i];
		uint64_t codecave = find_codecave(function_size, process_name, module);
		if (!codecave)
			continue;
		codecaves.push_back(codecave);
	}
	return codecaves;
}

bool c_shellcode::call_function(void* hook, void* function, std::string process_name)
{
	int pid = mem.GetPidFromName(process_name);

	BYTE jmp_bytes[14] = {
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [RIP+0x00000000]
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // RIP value
	};

	// Set jump address
	*reinterpret_cast<uint64_t*>(jmp_bytes + 6) = (uintptr_t)hook;

	auto orig_bytes = std::unique_ptr<uint8_t[]>(new uint8_t[sizeof(jmp_bytes)]);
	if (!mem.Read((uintptr_t)function, orig_bytes.get(), sizeof(jmp_bytes), pid))
		return 0;

	if (!VMMDLL_MemWrite(mem.vHandle, pid, (uintptr_t)function, jmp_bytes, sizeof(jmp_bytes)))
	{
		LOG("[!] 1 Failed to write memory at 0x%p\n", function);
		return false;
	}

	Sleep(100);

	//Restore function
	if (!VMMDLL_MemWrite(mem.vHandle, pid, (uintptr_t)function, orig_bytes.get(), sizeof(jmp_bytes)))
	{
		LOG("[!] 2 Failed to write memory at 0x%p\n", function);
		return false;
	}

	return true;
}
