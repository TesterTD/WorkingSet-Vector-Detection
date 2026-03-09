# WorkingSet Vector Detection

## Introduction

This project demonstrates a method for detecting external/internal manipulation of process memory based on monitoring the **Working Set** — a set of physical memory pages assigned to a process at a given point in time.

The hypothesis is simple: if no one touches the process memory, after a forced Working Set flush, the number of pages reloaded should be predictable and minimal. Any external access to the process memory — whether reading, writing, or code injection — causes additional pages to be loaded, leading to an abnormal increase in the `TotalEntries` counter.

---

## What is Working Set?

The **Working Set** of a process is the set of virtual memory pages that are currently in physical RAM and are associated with a specific process.

The Windows OS manages memory at the **page** level — blocks of 4 KB (on x86/x64) or 2 MB / 1 GB for large pages. Not all of a process's virtual memory is in RAM at the same time. When a process accesses a page that is not in physical memory, a **page fault** occurs, and Windows loads the required page from disk or recreates it.

**Working Set** refers specifically to those pages that are currently "hot" and located in physical memory.

---

## What is TotalEntries?

When `QueryWorkingSet()` is called, Windows returns a `MEMORY_WORKING_SET_INFORMATION` structure, in which the `NumberOfEntries` field contains the number of entries — one for each page in the Working Set.

```cpp
typedef struct _MEMORY_WORKING_SET_INFORMATION {
    ULONG_PTR                NumberOfEntries;   // <-- this is TotalEntries
    MEMORY_WORKING_SET_BLOCK WorkingSetInfo[1];  // array of records
} MEMORY_WORKING_SET_INFORMATION;
```

Each `MEMORY_WORKING_SET_BLOCK` entry contains:

| Field | Bits | Description |
|---|---|---|
| Protection | 5 | Page protection flags (RO, RW, RX, RWC, etc.) |
| ShareCount | 3 | How many processes share this page |
| Shared | 1 | Whether the page is shared |
| Node | 3 | NUMA node |
| VirtualPage | 52 | Virtual page number (address = VirtualPage x page size) |

`TotalEntries` is essentially the number of memory pages that the operating system physically holds in RAM for a given process. It is a direct indicator of what memory the process (or someone from outside) has accessed.

`WS.TotalEntries` serves as Proactive Defense, which means that the system does not necessarily have to wait for malicious activity (opening a handle, injection), but reacts to preparations for it (viewing the list of all available handles, preparing to read).

The algorithm for this PoC is quite simple: we resolve all functions using `GetProcAddress`, open our own process using `OpenProcess`, forcefully reset `EmptyWorkingSet()` for the entire Working Set, then pause for 100 milliseconds (`NtDelayExecution`). During this time, only those pages that are actually needed for consistency in the Working Set are loaded. `QueryWorkingSet` naturally counts the total entries.

---

## Why Does It Detect Any Memory Tampering?

For example, if someone reads memory through `ReadProcessMemory` to our process, the following happens:

1. The Windows kernel receives a request to read N bytes at address X in the main process.
2. The kernel must ensure that the pages being read are in physical memory.
3. If the page has been unloaded (which is the case after `EmptyWorkingSet()`), a discrepancy occurs, which can be called desynchronization in Windows Worker conditions.
4. The page is loaded back into RAM and **added to the Working Set**.

`TotalEntries` grows, which explains everything.

This is a fundamental property of Windows virtual memory architecture. In order to read data, it **must** be in physical memory. And if it is in physical memory, it is in the Working Set.

It can also detect Ring 0 read attempts if the kernel is involved in address translation. DMA-based reads via PCIe will most likely not be affected, although hypothetically even MMU techniques for hiding such things will not be particularly helpful.

Works great for detecting any attempts to detect DLL injection vector attacks, where there will be huge spikes in `WS.TotalEntries`, and in general, Working Set after injection shows a lot that can definitely be considered an anomaly and recorded in suspicious flags.

---

## Examples

### DLL Injection via Xenos

Here, I selected these parameters via Xenos, and I will load the emptiest DLL possible.

```cpp
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
```

<img width="599" height="436" alt="Xenos injection parameters" src="https://github.com/user-attachments/assets/eaa8fbab-0f70-4f4d-ae4e-3b92eba7c3f1" />

And what will happen after injecting this small DLL?

<img width="713" height="217" alt="Detection after DLL injection" src="https://github.com/user-attachments/assets/f67c414d-a7ea-4e56-9572-73a53908ba07" />

As you can see, Working Set caused a spike in `TotalEntries`, and if the DLL had been conditionally alive (tick message every second), Working Set would have processed it constantly, which would have been an unambiguous detection of memory manipulation.

---

## Cheat Engine

### Opening the Process List

First, we will simply open a list of all available handles without connecting.

<img width="1544" height="875" alt="Cheat Engine process list detection" src="https://github.com/user-attachments/assets/e7888cdb-d690-458b-8b13-c10f39a2bc74" />

Every time we open the process list again and again, it will be detected in the same way, as will Process Hacker or System Informer, but with significantly less impact.

### Connecting to the Process

<img width="1478" height="745" alt="Cheat Engine attach detection" src="https://github.com/user-attachments/assets/8df5dd40-8e70-4067-b1bc-f8fc706a0c32" />

We connected to our `WorkingSet.exe` handle. The main triggers are +102 and +85 pages, and they fired immediately after opening, which is due to the influence of Cheat Engine.

### Scanning Values

<img width="1537" height="692" alt="Cheat Engine value scan detection" src="https://github.com/user-attachments/assets/08e0abdc-3433-4d3d-9612-1c7172e597e6" />

I scanned several times to show what appears after one scan.

### Code Cave Scanner

Let's try using a simple scanner for Code Caves from Cheat Engine. Here are the results. It was also stopped and started several times for accurate readings.

<img width="1857" height="912" alt="Cheat Engine code cave scan detection" src="https://github.com/user-attachments/assets/b834e01b-b00b-4ae8-a84a-d68676105f1b" />

What a massive surge — it all explains itself. I think you understood.

---

## False Positives and Random Growth of TotalEntries

Many may say that yes, it really works and it's phenomenal. But how can you use it if there are sudden page spikes, for example, due to SuperFetch in Windows 10/11?

Then check out `WorkingSetInfo`. By analyzing Working Set, you can easily understand what kind of memory region it is, its type, which module it belongs to, the total size of the region, and many other flags. Working with tracing for Working Set is fundamentally simple; it is very easy to create a pattern from the source data that never appears in a normal Worker. For example, look at the call pattern on Cheat Engine — it is always the same in terms of the size of pages and modules that are called in reading.

You can also create a whitelist if you have a thorough understanding of which pages are always accessed under any circumstances, but if you are a beginner, this option is not recommended.

And, of course, the main pattern is huge page outputs, 200+ pages. Windows will never show such a sudden release for reading; there will most likely be small intervals.

---

## Alternatives

There are many different flags in Working Set. In addition to `WS.TotalEntries`, there are:

- `SharedPages`
- `ShareablePages`
- `ExecPages`
- `Node0Pages`
- `PrivatePages`
- `MinWorkingSetSize`

And many others. I have only listed the main ones that can be involved in any attempts to read your process or inject themselves. There are definitely better flags than `TotalEntries` for more accurate detection, so stay informed — knowledge is power.

---

## Conclusion

Using Working Set to attempt to catch any tampering is very powerful. But to work with it, you will need to spend some time researching to understand the exact algorithms and behaviors of Working Set in Windows.

---

*This project was created for educational purposes to study memory management mechanisms in Windows.*
