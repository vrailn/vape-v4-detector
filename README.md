# Vape V4 Loader — Reverse Engineering Analysis

> **Protection:** VMProtect 3.x (`.vlizer` section, ~7MB virtualized code) (or code defender)
> **Target:** Minecraft (Java Edition)

---

## 1. Binary Layout

| Segment | VA Range | Size | Purpose |
|---------|----------|------|---------|
| `.text` | `0x7FF6F4FC1000` – `0x7FF6F52B4000` | 0x2F3000 (3MB) | Application code — 304 recognized functions |
| `.rdata` | `0x7FF6F52B4000` – `0x7FF6F5383000` | 0xCF000 | Read-only data, ~19,268 strings |
| `.data` | `0x7FF6F5383000` – `0x7FF6F5400000` | 0x7D000 | Writable globals, state variables |
| `.pdata` | `0x7FF6F5400000` – `0x7FF6F5432000` | 0x32000 | Exception unwind tables |
| `.fptable` | `0x7FF6F5432000` – `0x7FF6F5433000` | 0x1000 | VMProtect function pointer table |
| **`.vlizer`** | `0x7FF6F5440000` – `0x7FF6F5B4C000` | **0x70C000 (7MB)** | **VMProtect virtualized code** |
| `.idata` | `0x7FF6F5B4C000` – `0x7FF6F5B4D910` | 0x1910 | Import Address Table |
| `.vulkan` | `0x7FF6F5B4D910` – `0x7FF6F5B54000` | 0x66F0 | Additional import/data |

**Key observation:** The `.vlizer` section is >2x the size of `.text`. The majority of the loader's logic — authentication handshake, payload decryption, injection orchestration, and anti-debug — is VMProtect-virtualized and cannot be statically decompiled.

---

## 2. Statically Linked Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| **GLFW 3.x** | — | Windowing, input, OpenGL context |
| **Dear ImGui** | 1.7x | GUI overlay (login screen, process list, settings) |
| **OpenSSL** | 1.0.2o (Mar 2018) | TLS, RSA, AES, SHA, certificate validation |
| **Crypto++** | — | Additional crypto: RSA signature verification, AES-CBC, SHA-1 HMAC |
| **Boost.Asio** | — | Async networking, TCP/UDP |
| **nlohmann/json** | — | JSON parsing for API responses |
| **lodepng** | — | PNG image decoding (UI textures) |
| **zlib/inflate** | — | Payload decompression |
| **Proxima Nova** | Semibold, v1.000 | Embedded font for UI rendering |

**Detection note:** The use of OpenSSL 1.0.2o (EOL since Dec 2019) is a static fingerprint. The Crypto++ RTTI strings (e.g., `.?AVAuthenticatedSymmetricCipher@CryptoPP@@`) are visible in `.rdata`.

---

## 3. Execution Flow

### 3.1 Entry Point & Initialization

```
start() → __scrt_common_main_seh() → main()
```

`main` at `0x7FF6F506CBD0`:

1. Calls `sub_7FF6F5067290()` three times — appears to set checkpoints/diagnostic strings
2. Installs `AddVectoredExceptionHandler` and `SetUnhandledExceptionFilter` with custom handlers (`Handler` at `0x7FF6F5067720`, `TopLevelExceptionFilter` at `0x7FF6F5067780`)
3. Calls `sub_7FF6F5067CF0()` — **VMProtect-virtualized init** (decompilation fails) — likely performs anti-debug checks, environment validation, and UI framework initialization
4. Checks two boolean flags: if either `sub_7FF6F500CF80()` or `sub_7FF6F501A500()` returns true, proceeds to shutdown via `sub_7FF6F501A490()`; otherwise fatal-errors with "Launcher exited before UI initialization completed"

### 3.2 Fatal Error Handler

`sub_7FF6F5067530` at `0x7FF6F5067530`:

Logs `[FATAL]` messages with the error description, last checkpoint string, and Win32 `GetLastError()` value. Flushes stdout and calls a cleanup/exit routine. This is a one-shot handler (guarded by a static boolean).

### 3.3 Privilege Escalation

`sub_7FF6F506CAE0` at `0x7FF6F506CAE0`:

```
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
LookupPrivilegeValueW(NULL, L"SeDebugPrivilege")
AdjustTokenPrivileges(...)
```

Enables `SeDebugPrivilege` on the current process token. This is required for `OpenProcess` with `PROCESS_ALL_ACCESS` on the target Minecraft JVM process.

**Detection IOC:** A process acquiring `SeDebugPrivilege` and subsequently calling `VirtualAllocEx` / `WriteProcessMemory` / `CreateRemoteThread` targeting `javaw.exe` or `java.exe`.

---

## 4. Authentication System

The loader authenticates against `vape.gg` using two methods:

### 4.1 HWID Generation

`sub_7FF6F5136390` at `0x7FF6F5136390`:

1. Calls `GetVolumeInformationA("C:\\", ..., &VolumeSerialNumber, ...)`
2. Converts the volume serial number to a string via `stringstream` with a custom format function (`sub_7FF6F5139370` — likely hex formatting)
3. If `C:\` fails, iterates drives `A:\` through `Z:\` trying each until `GetVolumeInformationA` succeeds
4. The resulting string is the HWID

**Detection note:** HWID is solely based on the C: drive volume serial number. No CPU/motherboard/MAC address components. This is a weak binding — trivially spoofable via `VolumeID` or registry edits.

### 4.2 Browser-Based OAuth Flow

**Token Generation** — `sub_7FF6F5007E30` at `0x7FF6F5007E30`:

1. Generates HWID string
2. Creates User-Agent: `Agent_{HWID}` (then wide-char converted for WinHTTP)
3. Constructs POST body: `edition=v4&hwid={HWID}`
4. HTTPS POST to `www.vape.gg` at `/api/v1/app-auth/generate` via `sub_7FF6F5126C40` (WinHTTP wrapper)
5. Parses JSON response, extracts `"token"` field (expected: 40-character string)
6. Stores token in global buffer `byte_7FF6F53FCE30` (256 bytes)
7. Sets atomic flags to signal token readiness

**Browser Launch** — `sub_7FF6F5007C20` at `0x7FF6F5007C20`:

1. Constructs URL: `https://www.vape.gg/app-auth/proceed/{token}`
2. Calls `ShellExecuteA(NULL, "open", url, ...)` to open the user's default browser
3. Records `GetTickCount64()` timestamp for timeout detection

**Status Polling** — `sub_7FF6F50085D0` at `0x7FF6F50085D0`:

1. HTTPS POST to `www.vape.gg` at `/api/v1/app-auth/status` with body `token={stored_token}`
2. Parses JSON response, checks `"status"` field:
   - `"pending"` → continue polling
   - `"timed out"` → clear token, show timeout message
   - `"success"` → extract `"token"` from response → call `sub_7FF6F506CAA0` (stores auth token) → call `sub_7FF6F506CA20` (triggers next stage)
3. If `GetTickCount64() - launch_time > 12000ms` (12 seconds), shows "Browser did not appear?" warning

### 4.3 Credential-Based Auth (Legacy)

Referenced at `0x7FF6F53323E0`:

- POST to `www.vape.gg` at `/auth.php` with `&hwid={HWID}` and username/password
- Error messages: "Invalid username or password" / "Your HWID or IP update timer is on cooldown"
- This code path is in the VMProtect-virtualized section

### 4.4 Network Fingerprint

- **User-Agent:** `Vape4/Launcher` (hardcoded at `0x7FF6F532F2A8` and `0x7FF6F532FA18`)
- **Connection header:** `Connection: close`
- **API endpoints:**
  - `GET/POST www.vape.gg/api/v1/app-auth/generate`
  - `GET/POST www.vape.gg/api/v1/app-auth/status`
  - `GET/POST www.vape.gg/auth.php`
  - `GET http://www.vape.gg/update.php?edition=V4`

**Detection IOC:** Network traffic with User-Agent `Vape4/Launcher` or `Agent_{hex_volume_serial}`, or DNS/TLS connections to `vape.gg` from a process that also holds a handle to `javaw.exe`.

---

## 5. Update Mechanism

Update URL at `0x7FF6F53484F8`:

```
http://www.vape.gg/update.php?edition=V4
```

Note: uses **plain HTTP** (not HTTPS) for the update check. The actual payload download likely uses HTTPS with the auth token.

---

## 6. Cryptographic Infrastructure

### 6.1 RSA Public Key

Embedded at `0x7FF6F5330260`:

```
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7kJUiwVLlB4b8/iicQB5zvaMhIL7T8pE5aptzneouhyfz4zYOADMP031C/WF1Q7VLemKwDbPxZGcB8Av/eTujei4l7FZQsJ8zmXIHy+ejNboFUtBP/Jr2AGI7...
```

This is a 1024-bit RSA public key (PKCS#1) used to verify server-signed payloads. The use of Crypto++ `PK_MessageAccumulatorImpl<SHA1>` (RTTI at `0x7FF6F53EA930`) indicates RSA-SHA1 signature verification.

### 6.2 Payload Encryption

Crypto++ classes present in RTTI:
- `AuthenticatedSymmetricCipher` — likely AES-GCM or AES-CBC-HMAC
- `StreamTransformationFilter` — symmetric cipher wrapper
- `ArrayXorSink` — XOR-based operations

The error string "is not a valid key length" at `0x7FF6F52FFF48` indicates runtime key validation for the symmetric cipher used for payload decryption.

---

## 7. Injection Pipeline

### 7.1 Win32 API Usage

The IAT and string references confirm a classic `CreateRemoteThread` injection:

| API | String Address | Purpose |
|-----|---------------|---------|
| `VirtualAllocEx` | `0x7FF6F5381240` | Allocate memory in target process |
| `WriteProcessMemory` | `0x7FF6F5381252` | Write payload to allocated memory |
| `VirtualProtectEx` | `0x7FF6F5381268` | Change memory protection |
| `CreateRemoteThread` | `0x7FF6F538127C` | Execute payload in target |
| `ReadProcessMemory` | `0x7FF6F53812D8` | Read target process memory |
| `OpenProcessToken` | `0x7FF6F53821D6` | Token manipulation |
| `AdjustTokenPrivileges` | `0x7FF6F5382202` | Privilege escalation |

**Note:** The actual injection orchestration function is VMProtect-virtualized. The strings are referenced from within the `.vlizer` section, making the exact injection sequence opaque to static analysis.

### 7.2 Target Process Discovery

`sub_7FF6F500B8E0` at `0x7FF6F500B8E0`:

1. Receives a PID as parameter
2. Calls `sub_7FF6F501CFD0(pid)` to get the window handle (likely `EnumWindows` + `GetWindowThreadProcessId`)
3. Calls `GetWindowTextA(hwnd, buffer, 256)` to retrieve the window title
4. Formats display string: `"Already Injected [%i]"` (if already injected) or `"PID %i"` (if available)
5. Renders the process entry in the ImGui UI with selectable buttons

**Detection IOC:** The loader enumerates windows and reads their titles to identify Minecraft instances. An anti-cheat can monitor for `EnumWindows` calls followed by `OpenProcess` with debug privileges from a non-system process.

### 7.3 Post-Injection Communication

Named pipe: `\\.\pipe\vapeclient.v4.{suffix}` (string at `0x7FF6F534B660`)

The loader creates a named pipe (`CreateNamedPipeA` at `0x7FF6F53815DA`) to communicate with the injected DLL. The pipe creation failure message at `0x7FF6F534BA68` confirms this is the primary IPC mechanism.

**Detection IOC:** Monitor for named pipes matching the pattern `\\.\pipe\vapeclient.v4.*`. The pipe is created by the loader and connected to by the injected module.

### 7.4 Payload Handling

Strings at `0x7FF6F5341878` and `0x7FF6F53418B0`:
```
Payload Bytes: 
 payload bytes
```

This suggests the loader logs the size of downloaded payloads during injection. The payload is downloaded from `vape.gg`, decrypted using the RSA-verified symmetric key, decompressed (zlib/inflate), and written into the target process.

---

## 8. UI Framework

### 8.1 ImGui Overlay

The loader uses Dear ImGui with OpenGL (legacy immediate mode) for its GUI:

- OpenGL imports: `glEnable`, `glDisable`, `glClear`, `glBindTexture`, `glDrawElements`, etc.
- ImGui overlay window: `##Overlay` (string at `0x7FF6F534B9F0`)
- GLFW window creation for the launcher UI
- Embedded font: Proxima Nova Semibold (copyright at `0x7FF6F53CDBDD`)

### 8.2 UI States

Login screen states identified from strings:
- `login` / `login2` — main login views
- `login_default` / `login_default_btn` — "Login with browser" button
- `login_creds` / `login_creds_btn` — "Login with credentials" button
- Loading animation: 4-element float array at `0x7FF6F53FEC68` with animated opacity (0.0–1.0), cycling through indices

### 8.3 UI Textures

Referenced texture names: `Mask_Top`, `Mask_Bottom`, `Rect` — loaded via a texture manager (`sub_7FF6F501D930` + `sub_7FF6F50278A0`).

---

## 9. VMProtect Analysis

### 9.1 Section Structure

The `.vlizer` section (0x70C000 bytes) contains VMProtect's virtualized bytecode. No recognized functions exist within it according to IDA's analysis, confirming the handlers use opaque predication and indirect jumps.

The `.fptable` section (0x1000 bytes) contains the VMProtect function pointer table — an indirection layer that routes calls from `.text` to virtualized implementations in `.vlizer`.

### 9.2 What's Virtualized

Based on failed decompilation attempts and xref analysis, the following are protected:

- **`sub_7FF6F5067CF0`** — Main initialization (386 bytes in .text, but jumps into .vlizer)
- **Credential auth flow** — `/auth.php` handler (xref from `0x7FF6F5019CE4` in unknown territory)
- **Payload download & decryption** — "Payload Bytes" referenced from `0x7FF6F50BFF50`
- **Injection orchestration** — The actual `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` call chain
- **Anti-debug / environment checks** — Likely in the init path
- **Overlay rendering** — `##Overlay` referenced from `0x7FF6F502BEDF`
- **Pipe communication** — Pipe creation failure at `0x7FF6F50671D9`
- **WinHTTP session management** — "opening WinHTTP session" at `0x7FF6F5126D63`

### 9.3 What's NOT Virtualized

The following are in cleartext `.text` and fully decompilable:
- HWID generation (`sub_7FF6F5136390`)
- Browser auth token generation (`sub_7FF6F5007E30`)
- Auth status polling (`sub_7FF6F50085D0`)
- Browser launch (`sub_7FF6F5007C20`)
- SeDebugPrivilege escalation (`sub_7FF6F506CAE0`)
- Process listing UI (`sub_7FF6F500B8E0`)
- Login UI rendering (`sub_7FF6F5008E70`)
- ImGui window framework (`sub_7FF6F503CD10`)
- Fatal error handler (`sub_7FF6F5067530`)
- All GLFW / OpenGL / ImGui library code

---

## 10. Detection Summary for Anti-Cheat Engines

### 10.1 Static Signatures

| Indicator | Value |
|-----------|-------|
| Section name | `.vlizer` (VMProtect) |
| Section name | `.fptable` (VMProtect) |
| String | `Vape V4 Loader` |
| String | `\\.\pipe\vapeclient.v4.` |
| String | `Vape4/Launcher` (User-Agent) |
| String | `www.vape.gg` |
| String | `/api/v1/app-auth/generate` |
| String | `Already Injected` |
| RTTI | `.?AVAuthenticatedSymmetricCipher@CryptoPP@@` |
| RSA key prefix | `MIGfMA0GCSqGSIb3DQEBA...` |
| OpenSSL version | `OpenSSL 1.0.2o  27 Mar 2018` |
| Font | `Proxima Nova` + `Semibold` + `Mark Simonson` |
| Window title trick | `MojangTricksIntelDriversForPerformance` |

### 10.2 Behavioral IOCs

1. **Process creates named pipe** matching `\\.\pipe\vapeclient.v4.*`
2. **SeDebugPrivilege** acquired followed by `OpenProcess` on `javaw.exe`
3. **VirtualAllocEx** → **WriteProcessMemory** → **CreateRemoteThread** targeting a Java process
4. **DNS/TLS to `vape.gg`** from a process that also holds handles to game processes
5. **User-Agent `Vape4/Launcher`** in HTTP headers
6. **HTTP GET to `http://www.vape.gg/update.php?edition=V4`** (plain HTTP)
7. **GetVolumeInformationA("C:\\")** called for HWID — correlate with subsequent network exfiltration of the serial
8. **ShellExecuteA** opening `https://www.vape.gg/app-auth/proceed/` URLs
9. **EnumWindows** + **GetWindowTextA** scanning for Minecraft window titles
10. **ImGui overlay window** (`##Overlay`) created in a non-game process

### 10.3 Memory Signatures

- Pipe name pattern in process memory: `vapeclient.v4.` (UTF-8)
- RSA public key blob in memory: `MIGfMA0GCSqGSIb3DQEBA`
- Auth token buffer at fixed global offset (256 bytes, always 40 chars when valid)
- HWID format: hex string of C: volume serial number

### 10.4 Network Signatures

```
POST /api/v1/app-auth/generate HTTP/1.1
Host: www.vape.gg
User-Agent: Vape4/Launcher
Connection: close
Content-Type: application/x-www-form-urlencoded

edition=v4&hwid={hex_volume_serial}
```

```
POST /api/v1/app-auth/status HTTP/1.1
Host: www.vape.gg
User-Agent: Vape4/Launcher
Connection: close

token={40_char_token}
```

---

## 11. Function Reference

| Address | Name | Size | Description |
|---------|------|------|-------------|
| `0x7FF6F506CBD0` | `main` | 151 | Entry: exception handlers, init, UI loop |
| `0x7FF6F5067CF0` | *(vmprotected)* | 386 | Core initialization — decompilation fails |
| `0x7FF6F506CAE0` | `enable_debug_priv` | 235 | SeDebugPrivilege escalation |
| `0x7FF6F5136390` | `generate_hwid` | — | HWID from volume serial number |
| `0x7FF6F5007E30` | `auth_generate_token` | 1903 | Browser auth: POST /api/v1/app-auth/generate |
| `0x7FF6F50085D0` | `auth_poll_status` | 1947 | Poll /api/v1/app-auth/status for success |
| `0x7FF6F5007C20` | `launch_browser_auth` | 521 | ShellExecuteA to open auth URL |
| `0x7FF6F500B8E0` | `render_process_entry` | 1047 | ImGui process list item (shows PID / "Already Injected") |
| `0x7FF6F5008E70` | `render_login_screen` | 4617 | Full login UI (browser + creds buttons, animations) |
| `0x7FF6F503CD10` | `imgui_window_render` | 15940 | ImGui window framework (Begin/End, scrollbars, resize) |
| `0x7FF6F5067530` | `fatal_error` | 199 | [FATAL] logging + exit |
| `0x7FF6F5067780` | `TopLevelExceptionFilter` | 191 | Unhandled exception handler |
| `0x7FF6F5067720` | `Handler` | 94 | Vectored exception handler |
| `0x7FF6F5126C40` | `winhttp_request` | — | WinHTTP HTTPS request wrapper |

---

## 12. Limitations

- **~90% of logic is VMProtect-virtualized** — the injection sequence, payload crypto, anti-debug, and much of the auth flow cannot be statically analyzed without dynamic unpacking or VM handler reconstruction
- **No dynamic analysis** was performed — runtime behavior may differ from static findings
- **The payload DLL itself was not analyzed** — this document covers only the loader/injector
- Import table shows duplicate entries (IAT duplicated for two copies of user32/kernel32 imports), suggesting the binary may have been repacked or contains two independent code paths (GLFW + loader)

---

*Analysis performed via IDA Pro with Hex-Rays decompiler. VMProtect-protected functions were identified by decompilation failure and cross-reference into the `.vlizer` section.*
