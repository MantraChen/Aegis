# Project Aegis

**A minimal Windows kernel anti-cheat framework** that protects designated processes (e.g. simulated game clients) from **read**, **write**, and **injection**.

This project is for **training my own project and systems programming skills** (kernel-mode development, WDK, process protection). It is not intended for production or commercial use.

- **Target platform**: Windows 10 / 11 (x64)
- **Stack**: C / C++
- **Tools**: Visual Studio, WDK (Windows Driver Kit), WinDbg, VMware/VirtualBox

> **Important**: Develop and test **only inside a VM**. Running or testing this driver on a physical machine can cause BSODs or unbootable systems.

---

## Layout

```
Project Aegis/
├── README.md
├── ProjectAegis.sln              # Visual Studio solution
└── ProjectAegis/
    ├── ProjectAegis.vcxproj     # WDK driver project (WDM, x64)
    ├── ProjectAegis.inf         # Driver install info (dev/test)
    ├── driver.c                 # Entry, unload, process notify, protection skeleton
    ├── config.h                 # Protected process names, feature flags, debug macros
    └── protection.h             # Protection API declarations
```

---

## Requirements

1. **Windows 10/11 x64** (ideally in a VM)
2. **Visual Studio 2022** with “Desktop development with C++”
3. **Windows Driver Kit (WDK)** matching your Windows SDK  
   - Install the WDK VSIX so Visual Studio has the driver build targets

---

## Build

1. Open `ProjectAegis.sln` in the VM.
2. Select **Debug | x64** or **Release | x64**.
3. **Build → Build Solution** (Ctrl+Shift+B).
4. Output: `bin\Debug\` or `bin\Release\` → `ProjectAegis.sys` (and `ProjectAegis.inf` if configured).

From “x64 Native Tools Command Prompt for VS 2022”:

```bat
msbuild ProjectAegis.sln /p:Configuration=Debug /p:Platform=x64
```

---

## Deploy and test (VM only)

1. **Disable driver signature enforcement** (test only):  
   - F8 or Advanced startup → “Disable driver signature enforcement”, or  
   - `bcdedit /set testsigning on` and reboot.

2. **Install/register the driver**:  
   - Right‑click the INF → Install, or  
   - Use `sc create` + `NtLoadDriver` (or similar) with admin rights.

3. **Load/unload**:  
   - Load: `sc start ProjectAegis` (or your service name)  
   - Unload: `sc stop ProjectAegis`, then remove the driver package if needed.

4. **Debug**:  
   - Set up WinDbg kernel debugging (VM serial/pipe or network KD), then break and watch `DbgPrint` output.

---

## Current implementation (skeleton)

- **DriverEntry / DriverUnload**: Initialize/teardown protection, register/unregister process create notify.
- **Process create notify**: `PsSetCreateProcessNotifyRoutineEx` to detect protected processes by image name.
- **Protection API** (`protection.h` / `driver.c`):  
  - `AegisProtectionInitialize` / `AegisProtectionUninitialize`  
  - `AegisIsProcessProtected` / `AegisIsProcessProtectedByPid` / `AegisIsProcessProtectedByImageName`  
  - `AegisRegisterCallbacks` / `AegisUnregisterCallbacks` (stubs for Ob callbacks, image notify, etc.)

**Default protected image names** are `GameClient.exe` and `TestProtected.exe` (see `config.h` / `driver.c`); they can be changed or later made configurable via IOCTL.

---

## Possible extensions

- **Read/write protection**: `ObRegisterCallbacks` to restrict handles, or hook `NtReadVirtualMemory` / `NtWriteVirtualMemory`.
- **Injection protection**: `PsSetLoadImageNotifyRoutine` to monitor module loads and block DLL injection into protected processes.
- **Dynamic protected list**: Add/remove protected names or PIDs via registry or user-mode IOCTL.

---

## Disclaimer and compliance

This project is for **learning and personal skill training** only. Deploying unsigned kernel drivers on a real system may violate Windows licensing and local laws. Use only in an isolated VM and comply with applicable regulations.
