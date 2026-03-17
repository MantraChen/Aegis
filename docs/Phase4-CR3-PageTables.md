# Phase 4 – Task 2 (Optional): CR3 and Page Table Basics

This document explains the role of **CR3** and page tables in x64 Windows, and how malicious drivers could theoretically modify a game’s page table attributes. It is for learning only; implementing full detection is advanced and often OS-version dependent.

---

## 1. Virtual to physical address translation (x64)

On x86-64, each process has its own **page tables**. The CPU uses them to translate **virtual addresses (VA)** to **physical addresses (PA)**.

- **CR3** (Control Register 3) holds the **physical** address of the **PML4 table** (Page Map Level 4) for the **current** logical processor. When the OS switches to a process, it loads that process’s PML4 physical address into CR3.
- Translation is a **four-level walk** (on standard 4-level paging):
  1. **PML4** (Page Map Level 4) – index from bits 39–47 of VA  
  2. **PDPT** (Page Directory Pointer Table) – index from bits 30–38  
  3. **PD** (Page Directory) – index from bits 21–29  
  4. **PT** (Page Table) – index from bits 12–20  

  The low 12 bits of the VA are the **page offset** (4 KB page). The final **PTE (Page Table Entry)** gives the **physical page frame** and **attributes** (R/W, U/S, NX, etc.).

- **NX (No-Execute)** is bit 63 of the PTE. If set, the page is non-executable. Normal code pages have NX clear; data/heap often have NX set. **RWX (Read-Write-Execute)** pages have both write and execute enabled and are suspicious when they are not backed by a known image.

---

## 2. Where the process CR3 lives

- For the **current** process, the effective “process CR3” is simply **CR3** (the register). Reading it in the driver (e.g. in a context where you are running in the target process) gives that process’s PML4 physical address.
- For an **arbitrary** process (e.g. the game), the kernel stores the **directory table base** (same value that gets loaded into CR3 when that process runs) in the process object. On Windows this is in **EPROCESS** (or the internal **KPROCESS**). The exact **offset** is **undocumented** and can change between Windows builds. Many anti-cheat and research projects resolve it at runtime (e.g. by pattern or by reading from a known process that has just been scheduled).
- **Do not** hardcode EPROCESS offsets; they differ per OS version and patch level.

---

## 3. What “page table manipulation” by a rootkit could do

A malicious driver with access to physical memory (e.g. via **MDL**, **MmMapIoSpace**, or other means) could in principle:

- **Locate** the game process’s page tables (using its CR3 / directory base).
- **Walk** VA → PA using the PML4/PDPT/PD/PT and find the **PTE** for a given virtual page.
- **Change** the PTE:
  - Clear **NX** to make a data page executable (for shellcode).
  - Set **R/W** to allow writing to code pages (for hooks).
  - Remap a physical page (e.g. swap the PFN) to replace code or data.

Such changes are **hard to detect** from another kernel driver because:

- You would need to **read** the same PTEs and compare them to an expected value (e.g. “this VA should be NX”), which requires a correct VA→PA walk and handling of large pages, etc.
- The layout and semantics of PTEs (and sometimes table formats) can change with OS versions and with **VBS/HVCI** (e.g. with **Kernel VA Shadowing** and **second-level paging**).
- **PatchGuard** restricts many kernel modifications; a rootkit that tampers with critical structures risks detection or crash.

So in practice, **detecting** “someone modified the game’s page tables” is **advanced**: it usually involves either a **trusted reference** (e.g. expected PTE attributes per VA range) or lower-level components (e.g. hypervisor or VBS-based integrity). This project does **not** implement full PTE-walk or PTE-integrity checks; Phase 4 Task 1 uses **VAD-style scanning** (virtual memory query API) instead.

---

## 4. Educational use of CR3 in the driver (optional)

If you want to **see** the current process’s CR3 from the driver (e.g. when attached to the game process), you can use the following **concept** (do not rely on this for security; it is for understanding):

- While running in the **context of the target process** (e.g. after **KeStackAttachProcess**), **CR3** holds that process’s directory table base. On x64 you can read it with a compiler intrinsic or inline asm (e.g. `__readcr3()` in MSVC). The value is a **physical address** of the PML4 table.
- You must be at the right IRQL and in a safe context (e.g. not in an arbitrary thread that might not have the process’s CR3 loaded). Attaching to the target process and then reading CR3 is the typical approach.

Example **conceptual** snippet (no guarantees; use only in a test environment):

```c
// Conceptual only – attach to process, then read CR3 for the current logical processor.
// The value is the PML4 physical address for that process.
void ExampleReadProcessCr3(PEPROCESS Process)
{
    KAPC_STATE apcState;
    KeStackAttachProcess(Process, &apcState);
    // Now we are “in” the target process; CR3 holds its directory table base.
    // ULONG_PTR cr3 = __readcr3();  // PML4 physical address (implementation-defined)
    KeUnstackDetachProcess(&apcState);
}
```

Full **VA → PA** translation would require:

1. Getting the **physical address** of each level (PML4, PDPT, PD, PT) by reading the current table and using the next-level physical frame number.
2. Mapping physical pages (e.g. **MmMapIoSpace**) if you need to read them from a driver that is not currently using that CR3.
3. Handling **large pages** (2 MB / 1 GB) where the walk stops early.
4. Interpreting **PTE** bits (R/W, U/S, NX, etc.) according to the OS and CPU manual.

This is left as an optional, advanced exercise. For Phase 4, the **VAD-style scan** (Task 1) provides a practical way to detect unbacked RWX regions (e.g. manual map) without walking page tables.
