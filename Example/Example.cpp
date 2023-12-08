// Example.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <DMALibrary/Memory/Memory.h>

int main()
{
	if (!mem.Init("explorer.exe", true))
	{
		std::cout << "Failed to initilize DMA" << std::endl;
		return 1;
	}

	std::cout << "DMA initilized" << std::endl;

	if (!mem.GetKeyboard().InitKeyboard())
	{
		std::cout << "Failed to initialize keyboard hotkeys through kernel." << std::endl;
		return 1;
	}

	//example keyboard usage.
	//mem.GetKeyboard().IsKeyDown(VK_F5);

	if (!mem.FixCr3())
		std::cout << "Failed to fix CR3" << std::endl;
	else
		std::cout << "CR3 fixed" << std::endl;
	/*auto all_modules = mem.GetModuleList("explorer.exe");
	std::cout << "Explorer.exe Modules: " << std::endl;
	for (size_t i = 0; i < all_modules.size(); i++)
	{
		std::cout << "Module: " << all_modules[i] << std::endl;
	}*/

	std::cout << "Hello World!\n";
	//pause();
	Sleep(10000);
	return 0;
}
