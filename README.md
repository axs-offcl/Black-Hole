# Black Hole (B-H)

> Windows system utility that safely removes stubborn, locked, and leftover files using the Windows reboot-pending queue.

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/language-C%2B%2B17-00599C?style=flat-square&logo=cplusplus" alt="C++17">
  <img src="https://img.shields.io/badge/license-GPL--3.0-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/tests-119%20passing-brightgreen?style=flat-square" alt="Tests">
</p>

---

## What it does

Black Hole safely deletes files that normal methods can't touch — locked executables, active DLLs, protected registry keys, and orphaned leftovers from uninstalled programs. It uses the Windows `MoveFileExW` reboot-queue mechanism to schedule deletion at the next reboot, when file locks are released.

## Features

### Uninstaller Page
- **Full program inventory** — enumerates all installed programs from 3 registry hives (HKLM x86/64, HKCU)
- **Multi-select uninstall** — select multiple programs and batch-uninstall them
- **Force Remove** — kills locking processes and queues stubborn files for reboot deletion
- **Certificate verification** — shows WARN for unsigned or suspicious executables
- **PE metadata extraction** — reads version, publisher, and bitness from EXE headers
- **Icon caching** — loads program icons from disk cache for instant display
- **Sortable columns** — Program Name, Publisher, Size, Installed Date, Cert, Location, Bitness, Protected, System

### Leftovers Scanner
- **Multi-depth scan** — Moderate (registry only) or Advanced (registry + services + COM + firewall + scheduled tasks + orphaned installers)
- **Confidence scoring** — each leftover rated Safe / Maybe / Risky with color-coded display
- **Directory orphan detection** — finds install folders left behind after uninstall
- **Cleanable categories** — files, directories, and registry keys can be individually reviewed before purge

### Other Features
- **Drag-and-drop** — drop files directly onto the window to force-delete them
- **Context menu integration** — right-click any file in Explorer to analyze or force-delete
- **System Restore Point** — optionally creates a restore point before purging leftovers
- **Audit logging** — every deletion is logged with timestamp, result, and file path
- **Crash handler** — writes crash logs to `%TEMP%\BlackHole_crash.log`
- **Blacklist protection** — critical system files (ntoskrnl, hal, bootmgr, svchost, etc.) are always blocked
- **Override mode** — type `"I assume full liability"` to bypass the blacklist (resets on restart)

## Screenshots

<p align="center">
  <em>Uninstaller page with certificate warnings and column filters</em>
</p>

## Building

### Requirements
- **Windows 10/11** (x64)
- **Visual Studio 2022** with C++ Desktop workload
- **CMake 3.20+**

### Build

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

The output is a single self-contained executable at `build/bin/Release/BlackHole.exe` (~1.3 MB).

### Run Tests

```bash
build/tests/Release/BlackHoleTests.exe
```

## Project Structure

```
Black-Hole/
├── src/
│   ├── gui_imgui.cpp          # GUI (Dear ImGui + DX11)
│   ├── tests/
│   │   └── test_uninstaller.cpp  # Unit tests
│   └── ...
├── include/
│   ├── blacklist.h            # Critical file protection
│   ├── deletor.h              # File deletion engine
│   ├── logger.h               # Audit logging
│   ├── privilege.h            # UAC privilege escalation
│   ├── uninstaller.h          # Program enumeration & leftover scanning
│   └── embedded_font.h        # Roboto-Medium font (embedded)
├── resources/                 # App icon, manifest
├── tests/                     # Integration tests
├── CMakeLists.txt
├── LICENSE                    # GPL-3.0
└── README.md
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | C++17 (MSVC) |
| GUI | Dear ImGui v1.92.9 WIP (DX11 backend) |
| Build | CMake |
| API | Raw Win32 API (no MFC/Qt dependency) |
| Deletion | `MoveFileExW` reboot queue |
| Fonts | Embedded Roboto-Medium (no external files) |

## How deletion works

1. **Atomic handle delete** — opens the file with `DELETE_ON_CLOSE` and `FILE_FLAG_DELETE_ON_CLOSE`
2. **Direct delete** — attempts `DeleteFileW` directly
3. **Attribute stripping** — removes `FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM`
4. **Process termination** — identifies and kills locking processes
5. **Reboot queue** — calls `MoveFileExW` with `MOVEFILE_DELAY_UNTIL_REBOOT` for next-boot deletion

## Safety

- **Blacklist** — 25+ critical Windows system files are permanently blocked from deletion
- **Override resets** — bypass mode always resets on application restart
- **Confirmation required** — override requires typing the exact phrase `"I assume full liability"`
- **No persistence** — override state is never saved to disk or registry

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `cmake --build build --config Release` and verify tests pass
5. Open a pull request

All contributions must maintain the existing code conventions and pass the full test suite (119 tests).
