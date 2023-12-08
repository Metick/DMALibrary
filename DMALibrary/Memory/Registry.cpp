#include "pch.h"
#include "Registry.h"
#include "Memory.h"

char* c_registry::QueryValue(const char* path, e_registry_type type)
{
	static BYTE buffer[0x128];
	static bool result;
	DWORD _type = (DWORD)type;
	DWORD size = sizeof(buffer);
	result = VMMDLL_WinReg_QueryValueExU(mem.vHandle, CC_TO_LPSTR(path), &_type, buffer, &size);
	if (!result)
	{
		LOG("[!] failed QueryValueExU call\n");
		return nullptr;
	}
	return const_cast<char*>(LPWSTR_TO_CC((LPWSTR)buffer));
}
