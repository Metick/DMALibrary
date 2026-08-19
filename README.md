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

The latest info.db from the MemProcFS release is downloaded automatically on the first build of the Example project.
You can of course download one yourself if you wish — if the file already exists in Example's output folder, the automatic download will be skipped.

The project pulls the required headers (leechcore.h, vmmdll.h) and import libraries
(leechcore.lib, vmm.lib) directly from ufrisk's MemProcFS repository, wired in as a
git submodule at `extern/MemProcFS`. No precompiled binaries are committed to this repo.

Clone with submodules:

```
git clone --recurse-submodules https://github.com/dactDMA/DMALibrary
```

or, if you already cloned without submodules:

```
git submodule update --init
```



Also special thanks to ufrisk for the libraries i used in this project.

## License
License This DMALibrary is open-source and licensed under the MIT License. Feel free to use, modify, and distribute it in your projects.
