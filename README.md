# Vape V4 Detector

Detects Vape V4 injected into Minecraft (`javaw.exe` / `java.exe`) by scanning for its `.vlizer` PE section inside RWX memory regions.

## How It Works

Vape injects its cheat DLL into Minecraft by writing the entire PE flat into a single allocation and marking it `PAGE_EXECUTE_READWRITE`. The injected PE is protected with Themida/WinLicense, which adds a section called `.vlizer`.

The detector:

1. Finds `javaw.exe` or `java.exe`
2. Walks the process memory with `VirtualQueryEx` looking for **private, committed, RWX** regions
3. Checks if the region starts with an `MZ` header and has a valid `PE` signature
4. Parses the PE section table looking for a section named **`.vlizer`**
5. If found, prints the base address of the injected module

After scanning, it optionally dumps each detected module to `vape-V4-{n}.bin`.

## Building

MSVC:
```
open the sln and build with vs 22 - 26
```


## Usage

```
just open the exe when it builds after injecting vape-v4
```

output

```
looking for vape v4
vape v4 found @ 0x000002F9BCC40000
dump? (y/n): n
```

## Why check `.vlizer`

The `.vlizer` section is added by Themida/WinLicense, we check for PAGE_EXECUTE_READWRITE - MEM_PRIVATE 

## How Vape Injects

1. Enables `SeDebugPrivilege` on its process token
2. Allocates memory in Minecraft with `VirtualAllocEx` (`MEM_COMMIT | MEM_RESERVE`, `PAGE_READWRITE`)
3. Writes the entire PE with `WriteProcessMemory`
4. Flips the region to `PAGE_EXECUTE_READWRITE` with `VirtualProtectEx`
5. Starts a remote thread with `CreateRemoteThread` at an export named `"tim"` in the injected PE
```
also for some reason vape maps the same dll twice, for no reason -_- so it will always show 2 instances 
```
<img width="848" height="573" alt="image" src="https://github.com/user-attachments/assets/052bd635-6e68-4159-ad5d-3b90f9935cca" />

```
so they map the module then the module maps the same module the courrupts the 1st dll pages?, its fucked but this does work 100% as of right now 
```

```
ptview output
```

<img width="1682" height="812" alt="image" src="https://github.com/user-attachments/assets/2b598a32-8fa8-405e-8461-927d142c3eb3" />
<img width="1644" height="963" alt="image" src="https://github.com/user-attachments/assets/25a462c6-92da-4599-9894-930d5432d80d" />

