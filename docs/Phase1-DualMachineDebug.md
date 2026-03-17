# Phase 1 – Task 1: Dual-Machine Kernel Debugging

**Goal**: Host (physical) runs Visual Studio and WinDbg; guest (VM) runs the test Windows system where the driver loads. You develop and debug from the host.

---

## 1. VM setup (guest – “test system”)

- **OS**: Windows 10 or 11 x64.
- **Tools on guest**: No need for VS/WDK on the VM if you deploy built binaries (recommended). Optionally install WDK only if you want to build inside the VM.

### 1.1 Enable kernel debugging

Open **Command Prompt (Admin)** and run:

```bat
bcdedit /debug on
bcdedit /set {current} nx OptIn
```

Choose **one** of the following.

**Option A – Named pipe (recommended for VMware)**

```bat
bcdedit /set {current} debugtype serial
bcdedit /set {current} debugport 1
bcdedit /set {current} baudrate 115200
```

In VMware: **VM → Settings → Add → Serial Port**  
- Output to **named pipe**, e.g. `\\.\pipe\aegis_kd`  
- “Yield CPU on poll” checked.

**Option B – Network (recommended for VirtualBox or remote)**

```bat
bcdedit /set {current} debugtype net
bcdedit /set {current} key 1.2.3.4
bcdedit /set {current} hostip 192.168.x.y
bcdedit /set {current} port 50000
```

Replace `192.168.x.y` with the **host** IP (the machine running WinDbg). The VM’s IP is not used for this.

Reboot the VM after changing `bcdedit`.

### 1.2 Test signing (so you can load the driver)

On the guest, in an elevated command prompt:

```bat
bcdedit /set testsigning on
```

Reboot again.

---

## 2. Host setup (physical – “development machine”)

- **Visual Studio 2022** with “Desktop development with C++” and **Windows Driver Kit (WDK)**.
- **WinDbg** (from WDK or Windows SDK): e.g. `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe`.

### 2.1 Connect WinDbg to the VM

**If you use serial (named pipe):**

1. Start the VM first (guest boots and waits for debugger).
2. On the host, run WinDbg.
3. **File → Kernel Debug** (or Ctrl+K).
4. **Pipe** tab:  
   - **Resets**: 0  
   - **Pipe**: `\\.\pipe\aegis_kd` (must match the pipe name in VMware).
5. **OK**. WinDbg attaches; the guest continues booting.

**If you use network:**

1. On the host, run WinDbg.
2. **File → Kernel Debug → Net** tab.
3. **Port**: 50000 (match `bcdedit /set {current} port`).
4. **Key**: same as on guest, e.g. `1.2.3.4`.
5. **OK**. Then start (or restart) the VM; WinDbg will connect when the guest is up.

### 2.2 Verify connection

In WinDbg command window:

```text
kd> .reload
kd> lm
```

You should see kernel modules. Breaking (Ctrl+Break) should freeze the guest and give a prompt in WinDbg.

---

## 3. Build and deploy from host

1. On the **host**, open `ProjectAegis.sln` and build (e.g. **Debug | x64**).
2. Copy the driver (and client) to the guest, e.g.:
   - `bin\Debug\ProjectAegis.sys`
   - `bin\Debug\AegisClient.exe` (after Phase 1 Task 3)
   - Optionally the whole `bin\Debug` folder.
3. On the **guest**, install/load the driver (see main README: INF install or `sc create` + `sc start`).

---

## 4. Debugging flow

- **Breakpoints**: Set in WinDbg (e.g. `bp ProjectAegis!DriverEntry`) or use VS **Attach to Kernel** and set breakpoints in source (if symbols are loaded).
- **Symbols**: In WinDbg, set symbol path to your driver’s output, e.g.  
  `.sympath+ C:\path\to\Project Aegis\bin\Debug`
- **DbgPrint**: In WinDbg, **File → Open Executable** and run **DebugView** (or use WinDbg’s **!dbgprint** or kernel log) to see `DbgPrint` from the driver.

---

## 5. Quick checklist

| Step | Host | Guest (VM) |
|------|------|------------|
| 1 | Install VS + WDK + WinDbg | Windows 10/11 x64 |
| 2 | — | `bcdedit /debug on`, serial or net, `testsigning on`, reboot |
| 3 | Start WinDbg, connect (pipe or net) | Start VM (if serial) or reboot (if net) |
| 4 | Build driver, copy .sys to VM | Install driver, `sc start ProjectAegis` |
| 5 | Set breakpoints, reload symbols | Run AegisClient or trigger driver code |

Once this works, you have a working dual-machine setup for Phase 1 and beyond.
