<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078d4?style=for-the-badge&logo=windows" alt="Platform">
  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus" alt="C++17">
  <img src="https://img.shields.io/badge/tests-119%20passing-brightgreen?style=for-the-badge" alt="Tests">
</p>

<h1 align="center">Black Hole (B-H)</h1>

<p align="center">
  <strong>Windows system utility for safe deletion of locked, stubborn, and leftover files</strong>
</p>

<p align="center">
  <a href="https://github.com/axs-offcl/Black-Hole/releases/latest"><strong>Download Latest Release</strong></a>
  &nbsp;&middot;&nbsp;
  <a href="#features">Features</a>
  &nbsp;&middot;&nbsp;
  <a href="#build-from-source">Build</a>
  &nbsp;&middot;&nbsp;
  <a href="#how-it-works">How It Works</a>
</p>

---

## What It Does

Black Hole is a Windows utility that deletes files standard methods can't handle -- locked executables, active DLLs, PPL-protected processes, and orphaned leftovers from uninstalled programs.

It uses the Win32 `MoveFileExW` reboot-queue mechanism to schedule deletion at the next reboot, when file locks are released. No kernel drivers, no shady hooks -- pure user-mode Win32 API.

---

## Features

### File Deletion

- **6-strategy deletion engine** -- tries the gentlest approach first, escalates only on failure:
  1. Atomic handle delete (`DELETE_ON_CLOSE`)
  2. Direct `DeleteFileW`
  3. Restart Manager shutdown (RmStartSession / RmShutdown)
  4. Take ownership + strip attributes + delete
  5. Move to temp + delete (ADS cleanup)
  6. `MoveFileExW` reboot queue fallback
- **Drag-and-drop** -- drop files or folders onto the window
- **Risk assessment** -- pre-deletion impact analysis with 0-100 risk score gauge
- **Expandable analysis cards** -- locked-by processes, dependent apps, registry refs, services, related files, leftovers
- **Recycle Bin mode** -- optional soft-delete with restore capability
- **Context menu** -- right-click any file in Explorer for "Force Delete" or "Analyze & Inspect"

### Program Uninstaller

- **Complete inventory** -- enumerates all installed programs from 3 registry hives (HKLM x86/64, HKCU)
- **3-phase progressive scan** -- Phase 1 (basic entries), Phase 2 (orphan detection + enrichment), Phase 3 (extras)
- **Multi-depth leftover scanning:**
  - **Safe** -- registry entries only
  - **Moderate** -- registry + file system traces
  - **Advanced** -- registry + services + COM objects + firewall rules + scheduled tasks + orphaned installer files
- **BCU-parity scanners** -- Chocolatey packages, Scoop apps, Windows Features, Windows Updates, MSI features
- **Multi-select batch uninstall** -- remove multiple programs at once
- **Force Remove pipeline** -- kills locking processes, deletes files, purges registry entries, optional restore point
- **Certificate verification** -- highlights unsigned executables
- **PE metadata extraction** -- version, publisher, bitness from EXE headers
- **Cross-hive deduplication** -- merges entries appearing in multiple registry hives
- **Confidence scoring** -- each leftover rated Safe / Maybe / Risky with color-coded display
- **System Restore Point** -- optionally creates one before purging leftovers

### Safety System

- **Blacklist** -- 27+ critical system files permanently blocked from deletion:
  - Kernel: `ntoskrnl.exe`, `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `hal.dll`
  - Boot: `bootmgr`, `winload.exe`, `winresume.exe`
  - Registry hives: `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`
  - System processes: `csrss.exe`, `wininit.exe`, `lsass.exe`, `services.exe`, `smss.exe`, `svchost.exe`, `explorer.exe`, `cmd.exe`, `powershell.exe`
  - Windows Defender directories
- **Override** -- bypass requires typing `"I assume full liability"` (exact match, case-sensitive)
- **Override resets on restart** -- never persists across sessions
- **Audit logging** -- every operation logged to `%APPDATA%\BlackHole\audit.log` with JSON timestamps

### GUI

- **Dear ImGui v1.92.9** with DirectX 11 hardware-accelerated rendering
- **Fully custom-drawn** -- no native widgets, everything rendered via `ImDrawList`
- **Frameless window** with custom title bar (minimize, maximize, close circles)
- **Dark / Light theme** -- full theme system with 10+ color constants, conditional styling
- **Lucide icon font** -- subset-embedded for navigation icons (log-out, trash-2, file-text, settings)
- **Right dock navigation** -- 4-tab panel with glowing active indicator
- **Configurable sidebar** -- animated glow, collapsible, custom gradient text
- **Window transparency** -- adjustable alpha from 15% to 100%
- **Resizable mode** -- optional `WS_THICKFRAME` with min 600x400, max 1920x1080
- **Notifications** -- slide-in toasts with auto-dismiss and progress bars
- **System tray** -- minimize to tray, right-click context menu

### CLI Modes

```bash
# Headless deletion (shows toast notification, writes to audit.log)
BlackHole.exe --delete "C:\path\to\file"

# Open GUI with file pre-selected and auto-analysis started
BlackHole.exe --analyze "C:\path\to\file"
```

### Additional

- **Crash handler** -- `SetUnhandledExceptionFilter` + `std::terminate` handler, writes to `%TEMP%\BlackHole_crash.log` with full register state and stack trace
- **Update checker** -- queries GitHub API for latest release, downloads and launches installer
- **Config persistence** -- saves preferences to `%APPDATA%\BlackHole\config.ini`
- **Icon caching** -- LRU memory + on-disk cache (`%APPDATA%\BlackHole\IconCache`)
- **Embedded font** -- Roboto-Medium (162KB) included in the binary, no external files needed

---

## Getting Started

### Download

Grab `BlackHole.exe` from [Releases](https://github.com/axs-offcl/Black-Hole/releases/latest). Single exe, no installer needed. Requires Administrator privileges (UAC manifest embedded).

### Build from Source

**Requirements:**
- Windows 10/11 (x64)
- Visual Studio 2022 BuildTools or full IDE with MSVC v143+
- CMake 3.20+
- Windows SDK 10.0+

```bash
git clone https://github.com/axs-offcl/Black-Hole.git
cd Black-Hole
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Output: `build/bin/Release/BlackHole.exe`

> **Note:** Dear ImGui v1.92.9 is fetched automatically via CMake `FetchContent`. No vendored dependencies needed.

### Run Tests

```bash
build/tests/Release/BlackHoleTests.exe
```

119 unit tests covering blacklist logic, file deletion strategies, privilege management, audit logging, protected deletion, and uninstaller parsing.

---

## How It Works

### Deletion Strategy

```
1. Atomic Handle     Open file with DELETE_ON_CLOSE
2. Direct Delete     DeleteFileW
3. Restart Manager   RmStartSession -> RmRegisterResources -> RmShutdown
4. Take Ownership    Set owner to Administrators, strip ReadOnly/Hidden/System
5. Move + Delete     Move to temp directory, clean alternate data streams
6. Reboot Queue      MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)
```

Each step only runs if the previous one fails.

### Impact Analysis

Before deletion, the impact analyzer scores risk (0-100) based on:
- Process lock count, dependent app count, registry references
- Service dependencies, system file status, digital signature
- Related file count, leftover count after deletion

### Privilege Management

Runs with `requireAdministrator` UAC manifest. Acquires `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeTakeOwnershipPrivilege` at runtime for maximum file access.

---

## Project Structure

```
BlackHole/
├── src/
│   ├── gui_imgui.cpp              # GUI (7000+ lines, Dear ImGui + DX11)
│   ├── uninstaller.cpp            # Program enumeration + leftover scanning
│   ├── deletor.cpp                # 6-strategy file deletion engine
│   ├── blacklist.cpp              # 27+ critical file protection
│   ├── privilege.cpp              # UAC privilege escalation
│   ├── logger.cpp                 # JSON audit logging
│   ├── impact_analyzer.cpp        # Pre-deletion risk assessment
│   └── tests/                     # 119 unit tests
├── include/
│   ├── embedded_font.h            # Roboto-Medium (embedded)
│   ├── embedded_lucide.h          # Lucide icons (embedded)
│   └── *.h                        # Module headers
├── resources/
│   ├── BlackHole.manifest         # UAC requireAdministrator
│   └── BlackHole.rc               # Version resource
├── tests/
│   └── integration_tests.cpp      # Integration tests
└── CMakeLists.txt                 # Build configuration
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | C++17 (MSVC v143+) |
| GUI | [Dear ImGui](https://github.com/ocornut/imgui) v1.92.9 + DirectX 11 |
| Icons | [Lucide](https://lucide.dev) (subset-embedded) |
| Build | CMake + FetchContent |
| API | Raw Win32 (kernel32, advapi32, shell32, ntdll, psapi, shlwapi, rstrtmgr, wintrust, dwmapi) |
| Deletion | `MoveFileExW` reboot queue + Restart Manager |
| Logging | JSON to `%APPDATA%\BlackHole\audit.log` |

---

## License

Distributed under the GNU General Public License v3.0.

---

<p align="center">
  Built with Win32 API + Dear ImGui + DirectX 11
</p>
