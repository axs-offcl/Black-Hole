<p align="center">
  <img src="resources/BlackHole-icon.png" width="120" alt="Black Hole Logo">
</p>

<h1 align="center">Black Hole</h1>

<p align="center">
  <strong>Safe deletion of locked, stubborn, and leftover files on Windows</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078d4?style=for-the-badge&logo=windows" alt="Platform">
  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus" alt="C++17">
  <img src="https://img.shields.io/badge/license-GPL--3.0-333?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/tests-119%20passing-brightgreen?style=for-the-badge" alt="Tests">
  <img src="https://github.com/axs-offcl/Black-Hole/actions/workflows/release.yml/badge.svg" alt="Build">
</p>

<p align="center">
  <a href="https://github.com/axs-offcl/Black-Hole/releases/latest"><strong>Download Latest Release</strong></a>
  &nbsp;&nbsp;·&nbsp;&nbsp;
  <a href="#features">Features</a>
  &nbsp;&nbsp;·&nbsp;&nbsp;
  <a href="#getting-started">Getting Started</a>
  &nbsp;&nbsp;·&nbsp;&nbsp;
  <a href="#contributing">Contributing</a>
</p>

---

## About

**Black Hole** is a Windows system utility built for developers, power users, and IT professionals who need to remove files that standard methods can't handle — locked executables, active DLLs, protected registry keys, and orphaned leftovers from uninstalled programs.

It uses the Windows `MoveFileExW` reboot-queue mechanism to schedule deletion at the next reboot, when file locks are released. No kernel drivers, no shady hooks — just a clean, safe, user-mode approach.

## Features

<table>
<tr>
<td width="50%">

### Program Management
- **Complete inventory** — enumerates all installed programs from 3 registry hives (HKLM x86/64, HKCU)
- **Multi-select uninstall** — batch-uninstall multiple programs at once
- **Force Remove** — kills locking processes and queues stubborn files for reboot deletion
- **Certificate verification** — highlights unsigned or suspicious executables with WARN
- **PE metadata extraction** — reads version, publisher, and bitness from EXE headers
- **Column filters** — filter by Microsoft, Store, System Components, Orphans, Chocolatey, Scoop

</td>
<td width="50%">

### Leftover Scanner
- **Multi-depth scan** — Moderate (registry only) or Advanced (registry + services + COM + firewall + scheduled tasks + orphaned installers)
- **Confidence scoring** — each leftover rated Safe / Maybe / Risky with color-coded display
- **Directory orphan detection** — finds install folders left behind after uninstall
- **Cleanable categories** — files, directories, and registry keys individually reviewable before purge
- **System Restore Point** — optionally creates a restore point before purging

</td>
</tr>
<tr>
<td>

### Safety & Protection
- **Blacklist** — 25+ critical system files (ntoskrnl, hal, bootmgr, svchost, etc.) permanently blocked
- **Override resets** — bypass mode always resets on restart
- **Confirmation required** — override requires typing `"I assume full liability"`
- **Audit logging** — every deletion logged with timestamp, result, and file path

</td>
<td>

### Quality of Life
- **Drag-and-drop** — drop files onto the window to force-delete
- **Context menu** — right-click any file in Explorer to analyze or delete
- **Crash handler** — writes crash logs to `%TEMP%\BlackHole_crash.log`
- **Embedded font** — Roboto-Medium included, no external dependencies
- **Single exe** — ~700 KB self-contained executable, no installer needed

</td>
</tr>
</table>

## Screenshots

> Screenshots coming soon.

## Getting Started

### Download

Grab the latest `BlackHole.exe` from [Releases](https://github.com/axs-offcl/Black-Hole/releases/latest). No installation needed — just run it.

### Build from Source

**Requirements:**
- Windows 10/11 (x64)
- Visual Studio 2022 with C++ Desktop workload
- CMake 3.20+

```bash
# Clone
git clone https://github.com/axs-offcl/Black-Hole.git
cd Black-Hole

# Configure
cmake -B build -G "Visual Studio 17 2022" -A x64

# Build
cmake --build build --config Release
```

The output is at `build/bin/Release/BlackHole.exe`.

### Run Tests

```bash
build/tests/Release/BlackHoleTests.exe
```

119 tests covering blacklist logic, file deletion, privilege escalation, logging, protected deletion, and uninstaller parsing.

## How It Works

Black Hole uses a layered deletion strategy:

```
1. Atomic Handle Delete    →  Opens file with DELETE_ON_CLOSE
2. Direct Delete           →  Attempts DeleteFileW
3. Attribute Stripping     →  Removes ReadOnly/Hidden/System flags
4. Process Termination     →  Identifies and kills locking processes
5. Reboot Queue            →  MoveFileExW with MOVEFILE_DELAY_UNTIL_REBOOT
```

Each step only runs if the previous one fails — the tool always tries the gentlest approach first.

## Project Structure

```
Black-Hole/
├── src/
│   ├── gui_imgui.cpp              # GUI (Dear ImGui + DX11)
│   ├── uninstaller.cpp            # Program enumeration & leftover scanning
│   ├── deletor.cpp                # File deletion engine
│   ├── blacklist.cpp              # Critical file protection
│   ├── privilege.cpp              # UAC privilege escalation
│   ├── logger.cpp                 # Audit logging
│   ├── impact_analyzer.cpp        # Deletion impact analysis
│   └── tests/                     # Unit tests (119 tests)
├── include/
│   ├── blacklist.h
│   ├── deletor.h
│   ├── uninstaller.h
│   ├── logger.h
│   ├── privilege.h
│   ├── impact_analyzer.h
│   └── embedded_font.h            # Roboto-Medium (embedded)
├── resources/                     # App manifest, icon, font
├── tests/                         # Integration tests
├── installer/                     # NSIS installer script
├── CMakeLists.txt
└── LICENSE                        # GPL-3.0
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | C++17 (MSVC) |
| GUI | [Dear ImGui](https://github.com/ocornut/imgui) v1.92.9 + DirectX 11 |
| Build System | CMake |
| System API | Raw Win32 API |
| Deletion Engine | `MoveFileExW` reboot queue |
| Font | Embedded Roboto-Medium |

## License

Distributed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for details.

## Contributing

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

All contributions must pass the full test suite (119 tests) and follow the existing code style.

---

<p align="center">
  Built with Win32 API + Dear ImGui
</p>
