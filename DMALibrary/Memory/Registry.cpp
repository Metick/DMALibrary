#include "pch.h"
#include "Registry.h"
#include "Memory.h"

std::string c_registry::QueryValue(const char* path, e_registry_type type)
{
	BYTE buffer[0x128];
	DWORD _type = (DWORD)type;
	DWORD size = sizeof(buffer);

	if (!VMMDLL_WinReg_QueryValueExU(mem.vHandle, CC_TO_LPSTR(path), &_type, buffer, &size))
	{
		LOG("[!] failed QueryValueExU call\n");
		return nullptr;
	}

	std::wstring wstr = std::wstring((wchar_t*)buffer);
	return std::string(wstr.begin(), wstr.end());
}
