# Vape V4 Detector

Detects Vape V4 injected into Minecraft (`javaw.exe` / `java.exe`) by scanning for its unique `.vlizer` PE section inside RWX memory regions.

## How It Works

Vape injects its cheat DLL into Minecraft by writing the entire PE flat into a single allocation and marking it `PAGE_EXECUTE_READWRITE`. The injected PE is protected with Themida/WinLicense, which adds a section called `.vlizer` containing virtualized bytecode. No legitimate software does this to a Java process.

The detector:

1. Finds `javaw.exe` or `java.exe` via process snapshot
2. Walks the process memory with `VirtualQueryEx` looking for **private, committed, RWX** regions
3. Checks if the region starts with an `MZ` header and has a valid `PE` signature
4. Parses the PE section table looking for a section named **`.vlizer`**
5. If found, prints the base address of the injected module

After scanning, it optionally dumps each detected module to `vape-V4-{n}.bin`.

## Building

MSVC:
```
cl /EHsc vape_detector.cpp
```

Run as administrator (needs `PROCESS_VM_READ` access to `javaw.exe`).

## Usage

```
vape_detector.exe
```

Auto-finds Minecraft. No arguments needed.

```
looking for vape v4
vape v4 found @ 0x000002F9BCC40000
dump? (y/n): n
```

## Why `.vlizer`

The `.vlizer` section is added by Themida/WinLicense, a commercial code protection tool. Vape uses it to virtualize sensitive routines like authentication, payload decryption, and anti-tamper checks. The section name survives injection because the entire PE (headers and all) is written into memory as-is. Since no legitimate Java library ships with Themida protection injected at runtime, the presence of `.vlizer` inside an RWX region in `javaw.exe` is a definitive Vape signature.

## How Vape Injects

1. Enables `SeDebugPrivilege` on its process token
2. Finds Minecraft by scanning localhost ports (not process enumeration)
3. Downloads the cheat DLL from `online.vape.gg` over HTTPS with User-Agent `Vape4/Launcher`
4. Allocates memory in Minecraft with `VirtualAllocEx` (`MEM_COMMIT | MEM_RESERVE`, `PAGE_READWRITE`)
5. Writes the entire PE with `WriteProcessMemory`
6. Flips the region to `PAGE_EXECUTE_READWRITE` with `VirtualProtectEx`
7. Starts a remote thread with `CreateRemoteThread` at an export named `"tim"` in the injected PE

The flat write + RWX flip is what makes it trivially detectable from the outside.
