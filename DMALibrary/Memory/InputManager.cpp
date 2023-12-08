#include "pch.h"
#include "InputManager.h"
#include "Registry.h"
#include "Memory/Memory.h"

bool c_keys::InitKeyboard()
{
	char* win = registry.QueryValue("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CurrentBuild", e_registry_type::sz);
	int Winver = 0;
	if (win != nullptr)
		Winver = std::stoi(win);
	else
		return false;

	this->win_logon_pid = mem.GetPidFromName("winlogon.exe");
	if (Winver > 22000)
	{
		auto pids = mem.GetPidListFromName("csrss.exe");
		for (size_t i = 0; i < pids.size(); i++)
		{
			auto pid = pids[i];
			uintptr_t tmp = VMMDLL_ProcessGetModuleBaseU(mem.vHandle, pid, (LPSTR)"win32ksgd.sys");
			uintptr_t gSessionGlobalSlots = tmp + 0x3110;
			uintptr_t Session1_UserSessionState = mem.Read<uintptr_t>(mem.Read<uintptr_t>(mem.Read<uintptr_t>(gSessionGlobalSlots, pid), pid), pid);
			gafAsyncKeyStateExport = Session1_UserSessionState + 0x3690;
			if (gafAsyncKeyStateExport > 0x7FFFFFFFFFFF)
				break;
		}
		if (gafAsyncKeyStateExport > 0x7FFFFFFFFFFF)
			return true;
		return false;
	}
	else
	{
		PVMMDLL_MAP_EAT pEatMap = NULL;
		PVMMDLL_MAP_EATENTRY pEatMapEntry;
		bool result = VMMDLL_Map_GetEATU(mem.vHandle, mem.GetPidFromName("winlogon.exe") | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, (LPSTR)"win32kbase.sys", &pEatMap);
		if (!result)
			return false;

		if (pEatMap->dwVersion != VMMDLL_MAP_EAT_VERSION)
		{
			VMMDLL_MemFree(pEatMap);
			pEatMap = NULL;
			return false;
		}

		for (int i = 0; i < pEatMap->cMap; i++)
		{
			pEatMapEntry = pEatMap->pMap + i;
			if (strcmp(pEatMapEntry->uszFunction, "gafAsyncKeyState") == 0)
			{
				gafAsyncKeyStateExport = pEatMapEntry->vaFunction;

				break;
			}
		}

		VMMDLL_MemFree(pEatMap);
		pEatMap = NULL;
		if (gafAsyncKeyStateExport > 0x7FFFFFFFFFFF)
			return true;
		return false;
	}
}

void c_keys::UpdateKeys()
{
	uint8_t previous_key_state_bitmap[64] = {0};
	memcpy(previous_key_state_bitmap, state_bitmap, 64);

	VMMDLL_MemReadEx(mem.vHandle, this->win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, gafAsyncKeyStateExport, (PBYTE)&state_bitmap, 64, NULL, VMMDLL_FLAG_NOCACHE);
	for (int vk = 0; vk < 256; ++vk)
		if ((state_bitmap[(vk * 2 / 8)] & 1 << vk % 4 * 2) && !(previous_key_state_bitmap[(vk * 2 / 8)] & 1 << vk % 4 * 2))
			previous_state_bitmap[vk / 8] |= 1 << vk % 8;
}

bool c_keys::IsKeyDown(uint32_t virtual_key_code)
{
	this->UpdateKeys();
	return state_bitmap[(virtual_key_code * 2 / 8)] & 1 << virtual_key_code % 4 * 2;
}
