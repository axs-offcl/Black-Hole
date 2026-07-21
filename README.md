<div align="center">

# 🕳️ Black Hole (B-H)

### Secure File Deletion Utility for Windows

**Delete stubborn, locked, and protected files safely — with military-grade system protection.**

[![GitHub Release](https://img.shields.io/github/v/release/axs-offcl/Black-Hole?style=for-the-badge&color=e884ff)](https://github.com/axs-offcl/Black-Hole/releases)
[![License](https://img.shields.io/github/license/axs-offcl/Black-Hole?style=for-the-badge&color=8e84ff)](https://github.com/axs-offcl/Black-Hole/blob/main/LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-00c853?style=for-the-badge)](#)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078d4?style=for-the-badge)](https://www.microsoft.com/windows)
[![C++](https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus)](https://isocpp.org/)
[![Tests](https://img.shields.io/badge/tests-101%2F101%20passing-00c853?style=for-the-badge)](#)

<br>

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [How It Works](#-how-it-works) • [Building](#-building-from-source) • [CLI](#-command-line-interface) • [Testing](#-testing) • [License](#-license)

<br>

</div>

---

## 📋 Overview

Black Hole (B-H) is a Windows system utility that safely deletes stubborn, locked, and protected files using a 7-stage deletion cascade. Built with native Win32 API and Dear ImGui, it provides both a modern GUI dashboard and full CLI support for scripting and automation.

> ⚠️ **This tool performs permanent file deletion.** Always verify file paths before confirming deletion. The blacklist protection system prevents accidental deletion of critical Windows system files.

---

## 🚀 Features

<table>
<tr>
<td>

**Core Deletion Engine**
- 🔒 7-stage deletion cascade
- 🛡️ Blacklist protection (26+ system files)
- ♻️ Recycle Bin integration with restore
- 📅 Reboot-queue via `MoveFileExW`

</td>
<td>

**Uninstaller Module**
- 🔍 21 left-over scanners (BCU-derived)
- 📊 Confidence scoring engine (10 factors)
- 🏪 Store App (UWP/AppX) discovery
- 🔗 Cross-hive registry merge

</td>
</tr>
<tr>
<td>

**Security & Safety**
- 🔐 `I assume full liability` override phrase
- 🛡️ Device path & reserved name shield
- 🔑 Path canonicalization & ADS stripping
- 📝 Forensic audit logging

</td>
<td>

**GUI & UX**
- 🌙 Dark/Light theme toggle
- 🎨 Muca-style Dear ImGui + DX11
- 📂 Dock navigation `[L] [D] [U] [S]`
- 🖱️ Windows Explorer context menu

</td>
</tr>
</table>

---

## 💾 Installation

### Pre-built Binaries

1. Download the latest release from [GitHub Releases](https://github.com/axs-offcl/Black-Hole/releases)
2. Extract `BlackHole.exe` and `BlackHoleCLI.exe` to any folder
3. Run `BlackHole.exe` as Administrator

### Build from Source

```cmd
git clone https://github.com/axs-offcl/Black-Hole.git
cd Black-Hole
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

---

## 🖥️ Usage

### GUI Dashboard

| Tab | Key | Description |
|-----|-----|-------------|
| **Logs** | `[L]` | View deletion history, restore from Recycle Bin |
| **Delete** | `[D]` | Select files, configure deletion mode |
| **Uninstaller** | `[U]` | Scan installed programs, force-remove leftovers |
| **Settings** | `[S]` | Theme, context menu, sidebar glow, safe mode |

### Override Mode

Override mode disables blacklist protection. Must be re-activated each session.

1. Open **Settings** tab
2. Toggle **SAFE** switch to ON
3. Type exactly: `I assume full liability`
4. Blacklist is now disabled (resets on restart)

### Recycle Bin Mode

1. Open **Settings** → Toggle **Send to Recycle Bin** ON
2. Deleted files go to Windows Recycle Bin
3. Click **Restore** in Logs tab to recover items

### Uninstaller

1. Open **Uninstaller** tab `[U]`
2. Browse/search installed programs with icons, publisher, size
3. **Uninstall** — runs standard uninstaller
4. **Force Remove** — scans for leftovers (registry, filesystem, COM, services)
5. Leftover popup shows confidence-scored items in Safe/Maybe/Risky groups

---

## ⚙️ How It Works

```
Input Path
    │
    ▼
┌─────────────────┐
│ Blacklist Check  │ ──► BLOCKED (ntoskrnl.exe, lsass.exe, etc.)
└────────┬────────┘
         │
    ▼
┌─────────────────┐
│ Privilege Elev.  │ ──► SE_BACKUP_NAME + SE_RESTORE_NAME
└────────┬────────┘
         │
    ▼
┌─────────────────┐
│ Reparse Point   │ ──► Detect symlinks/junctions, delete link only
└────────┬────────┘
         │
    ▼
┌─────────────────┐
│ Handle-Based    │ ──► SetFileInformationByHandle (atomic delete)
│ Deletion        │
└────────┬────────┘
         │
    ▼
┌─────────────────┐
│ ADS Detection   │ ──► Detect & delete alternate data streams
└────────┬────────┘
         │
    ▼
┌─────────────────┐
│ Process Kill    │ ──► Restart Manager API finds locking processes
└────────┬────────┘
         │
    ▼
┌─────────────────┐
│ Reboot Queue    │ ──► MoveFileExW MOVEFILE_DELAY_UNTIL_REBOOT
└─────────────────┘
```

---

## 🛠️ Building from Source

### Prerequisites

| Tool | Version |
|------|---------|
| **Visual Studio** | 2022 BuildTools (MSVC 19.44+) |
| **CMake** | 3.15+ |
| **Windows SDK** | 10.0.26100.0+ |

### Build Commands

```cmd
:: Clone and build
git clone https://github.com/axs-offcl/Black-Hole.git
cd Black-Hole

:: Generate project files
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64

:: Build Release
cmake --build . --config Release

:: Run tests
cd tests\Release
BlackHoleTests.exe
```

### Build Output

```
build\bin\Release\
├── BlackHole.exe                  # GUI application
├── BlackHoleCLI.exe               # Command-line interface
├── BlackHoleTests.exe             # 101 unit tests
├── BlackHoleIntegrationTests.exe  # Integration tests
└── file_holder.exe                # Test utilities

build\lib\Release\
└── BlackHoleCore.lib              # Static library
```

---

## 💻 Command Line Interface

```cmd
:: Delete a file
BlackHoleCLI.exe --delete "C:\path\to\file.txt"

:: Schedule for reboot deletion
BlackHoleCLI.exe --reboot "C:\path\to\locked.dll"

:: Check if file is blacklisted
BlackHoleCLI.exe --check "C:\Windows\System32\ntoskrnl.exe"

:: View pending reboot deletions
BlackHoleCLI.exe --status

:: Show help
BlackHoleCLI.exe --help
```

---

## 🧪 Testing

### Unit Tests — 101 Passing

```
╔══════════════════════════════════════════════════╗
║  MODULE               ║  TESTS  ║  STATUS       ║
╠══════════════════════════════════════════════════╣
║  Blacklist            ║   26    ║  ✅ PASS       ║
║  Privilege            ║    7    ║  ✅ PASS       ║
║  Deletor              ║   12    ║  ✅ PASS       ║
║  Logger               ║   12    ║  ✅ PASS       ║
║  Protected Deletion   ║   11    ║  ✅ PASS       ║
║  Uninstaller          ║   32    ║  ✅ PASS       ║
╠══════════════════════════════════════════════════╣
║  TOTAL                ║  101    ║  ✅ ALL PASS   ║
╚══════════════════════════════════════════════════╝
```

### Test Coverage

- **Blacklist:** Path normalization, override toggle, case sensitivity, drivers/defender blocking
- **Privilege:** Backup/Restore privilege acquisition, admin detection, non-copyable
- **Deletor:** Normal/delete/read-only/hidden/directory deletion, process protection, Restart Manager
- **Logger:** File initialization, deletion/override/privilege/PPL logging, recent entries
- **Protected Deletion:** ACL denial, nested dirs, symlinks, system+readonly combos
- **Uninstaller:** Registry merge, dedup, scoring, PE extraction, sort queue, cross-hive

---

## 🏗️ Tech Stack

<div align="center">

| | Technology |
|---|---|
| **Language** | ![C++](https://img.shields.io/badge/C++-17-00599C?style=flat&logo=cplusplus) |
| **GUI** | ![Dear ImGui](https://img.shields.io/badge/Dear_ImGui-1.92.9-8e84ff?style=flat) |
| **Graphics** | ![DirectX](https://img.shields.io/badge/DirectX_11-0078d4?style=flat&logo=microsoft) |
| **Build** | ![CMake](https://img.shields.io/badge/CMake-3.15+-064f8c?style=flat&logo=cmake) |
| **Compiler** | ![MSVC](https://img.shields.io/badge/MSVC-19.44-5c2d91?style=flat&logo=visualstudio) |
| **APIs** | ![Win32](https://img.shields.io/badge/Win32_API-0078d4?style=flat&logo=windows) |

</div>

---

## 📁 Project Structure

```
Black Hole/
├── src/
│   ├── gui_imgui.cpp              # ImGui + DX11 GUI
│   ├── main_cli.cpp               # CLI entry point
│   ├── deletor.cpp                # 7-stage deletion engine
│   ├── blacklist.cpp              # Blacklist + path canonicalization
│   ├── privilege.cpp              # Privilege management
│   ├── logger.cpp                 # Forensic audit logging
│   ├── uninstaller.cpp            # Uninstaller + 21 scanners
│   └── tests/
│       ├── test_blacklist.cpp     # 26 blacklist tests
│       ├── test_deletor.cpp       # 12 deletion tests
│       ├── test_logger.cpp        # 12 logger tests
│       ├── test_privilege.cpp     # 7 privilege tests
│       ├── test_protected_deletion.cpp  # 11 protected deletion tests
│       └── test_uninstaller.cpp   # 32 uninstaller tests
├── include/
│   ├── deletor.h
│   ├── blacklist.h
│   ├── privilege.h
│   ├── logger.h
│   └── uninstaller.h
├── resources/
│   └── BlackHole.manifest        # UAC requireAdministrator
├── imgui/                         # Dear ImGui library
├── CMakeLists.txt                 # Build configuration
└── README.md
```

---

## 🔐 Security Features

| Feature | Description |
|---------|-------------|
| **Blacklist Protection** | 26+ critical system files protected from deletion |
| **Path Canonicalization** | Resolves `\\?\` prefixes, ADS streams, relative paths |
| **Handle-Based Deletion** | Atomic `SetFileInformationByHandle` prevents TOCTOU |
| **Device Path Shield** | Blocks `\\.\PHYSICALDRIVE`, `CON`, `PRN`, `NUL` etc. |
| **Override Phrase** | Case-sensitive `I assume full liability` required |
| **Audit Logging** | Every deletion attempt logged with timestamp |
| **Admin Only** | UAC manifest requires Administrator elevation |

---

## ⚠️ Limitations

| Limitation | Workaround |
|------------|------------|
| PPL-protected files | Queued for reboot deletion |
| Admin required | GUI/CLI both require Administrator |
| Context menu install | Requires admin privileges |
| Broken symlinks | Requires admin or developer mode |

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

[![GPL v3](https://img.shields.io/badge/License-GPLv3-0078d4?style=for-the-badge)](https://www.gnu.org/licenses/gpl-3.0)

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting a Pull Request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/axs-offcl/Black-Hole/issues)
- **Discussions:** [GitHub Discussions](https://github.com/axs-offcl/Black-Hole/discussions)

---

<div align="center">

**Built with ❤️ for Windows power users**

[![Follow](https://img.shields.io/badge/follow-@axs--offcl-8e84ff?style=for-the-badge)](https://github.com/axs-offcl)

</div>
