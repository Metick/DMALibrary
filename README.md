# DMALibrary
Simple but extensive library for DMA users

Supports
- Sig Scanning
- Read Memory
- Write Memory
- Scatter Read Memory
- Scatter Write Memory
- Dumping Physical Memory
- Dumping Memory
- Fix CR3
- Target Computer Keyboard
- Getting PID & Base Address
- Code Cave Finder
- Function Caller
- Syscalling kernel functions
- Utilities (Get Import, Get Export, Get Base Size ect)
- Clean & Good documented code.

## Please read!

The program expects you to have the dlls FTD3XX.dll, leechcore.dll and vmm.dll (download them from your DMA supplier) at the root directory when shipping the program.

If you're making use of the CR3 Fix you requires additional .dlls as mentioned in the source.
Using CR3 fix requires you to have symsrv.dll, dbghelp.dll and info.db
You can find all these also in the compiled version of ulfrisk.

The project requires the leechcore.lib and vmm.lib libraries in the libs/ folder. I did not add the precompiled libraries for security purposes. 
You can get the files from 
https://github.com/ufrisk/LeechCore
and
https://github.com/ufrisk/MemProcFS/tree/master/vmm

and compiled from if you are lazy.
https://github.com/ufrisk/MemProcFS/tree/master/includes/lib32

Also special thanks to ufrisk for the libraries i used in this project.
