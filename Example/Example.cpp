// Example.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <DMALibrary/Memory/Memory.h>

int main()
{
	if (!mem.Init("explorer.exe", true, true))
	{
		std::cout << "Failed to initilize DMA" << std::endl;
		return 1;
	}

	std::cout << "DMA initilized" << std::endl;

	if (!mem.GetKeyboard()->InitKeyboard())
	{
		std::cout << "Failed to initialize keyboard hotkeys through kernel." << std::endl;
		return 1;
	}

	//example keyboard usage.
	std::cout << "Continueing once 'A' has been pressed." << std::endl;
	while (!mem.GetKeyboard()->IsKeyDown(0x41))
	{
		Sleep(100);
	}

	if (!mem.FixCr3())
		std::cout << "Failed to fix CR3" << std::endl;
	else
		std::cout << "CR3 fixed" << std::endl;

	uintptr_t base = mem.GetBaseDaddy("explorer.exe");

	std::cout << "Value: " << mem.Read<int>(base + 0x66) << std::endl;
	mem.Write<int>(base + 0x66, 0x69);
	std::cout << "Value: " << mem.Read<int>(base + 0x66) << std::endl;

	int value = 0;
	if (mem.Read(base + 0x66, &value, sizeof(value)))
		std::cout << "Read Value" << std::endl;
	else
		std::cout << "Failed to read Value" << std::endl;
	std::cout << "Value: " << value << std::endl;

	auto handle = mem.CreateScatterHandle();

	value = 0;
	mem.AddScatterReadRequest(handle, base + 0x66, &value, sizeof(value));
	//You have to execute the read requests before you can read the values.
	mem.ExecuteReadScatter(handle);
	std::cout << "Value: " << value << std::endl;

	//You can also write to memory using scatter requests.
	value = 500;
	mem.AddScatterWriteRequest(handle, base + 0x66, &value, sizeof(value));
	mem.ExecuteWriteScatter(handle);

	//Always make sure to clean up the handle, otherwise you'll end up with a memory leak.
	mem.CloseScatterHandle(handle);

	std::cout << "Hello World!\n";
	//pause();
	Sleep(10000);
	return 0;
}
