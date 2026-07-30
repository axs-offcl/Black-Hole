# Black Hole (B-H) v2.0.0 - Release Notes

**Release Date:** 2026-07-15
**Version:** 2.0.0
**Status:** Stable Release

---

## What's New

Black Hole (B-H) v2.0.0 is the first production-ready release of a safe file deletion utility for Windows. This release includes a complete GUI application, command-line interface, and professional installer.

### Key Features

- **Safe Deletion:** Queue stubborn files for deletion on next system reboot
- **Blacklist Protection:** Prevents accidental deletion of critical system files
- **PPL Detection:** Identifies Protected Process Light processes
- **Override Mode:** Manual text confirmation for advanced users
- **Forensic Logging:** Complete audit trail of all operations
- **System Tray:** Non-intrusive background operation
- **Context Menu:** Right-click integration for quick access
- **Professional Installer:** One-click installation with UAC support

---

## System Requirements

- **Operating System:** Windows 8.1 or later
- **Architecture:** x64 (64-bit)
- **Privileges:** Administrator (for installation and certain operations)
- **Disk Space:** < 10 MB

---

## Installation

### Option 1: Installer (Recommended)
1. Download `BlackHoleInstaller.exe`
2. Right-click → "Run as administrator"
3. Follow the installation wizard
4. (Optional) Enable "Context Menu Integration"

### Option 2: Portable
1. Create folder `C:\Program Files\BlackHole`
2. Copy `BlackHole.exe` and `BlackHoleCLI.exe`
3. Run as Administrator

---

## Quick Start

### Delete a File
```cmd
BlackHole.exe --delete "C:\path\to\file.txt"
```

### Context Menu
1. Right-click any file in Explorer
2. Select "Send to Black Hole"
3. Confirm deletion

### GUI Dashboard
1. Launch `BlackHole.exe`
2. View logs and monitor activity
3. Use "Select File to Delete" for manual deletion

---

## What's Included

| File | Purpose |
|------|---------|
| `BlackHole.exe` | GUI application with system tray |
| `BlackHoleCLI.exe` | Command-line interface |
| `BlackHoleCore.lib` | Core library |
| `include/*.h` | Header files for development |
| `BlackHoleInstaller.exe` | Professional installer |
| `README.md` | User documentation |
| `LICENSE.txt` | MIT License |

---

## Testing Results

- **Unit Tests:** 62/62 passed (100%)
- **Integration Tests:** 10/10 passed (100%)
- **Manual Verification:** 11/11 passed (100%)

See `TEST_REPORT.md` for detailed results.

---

## Known Issues

1. **PPL-Protected Files:** Cannot be deleted in real-time; queued for reboot
2. **Windows Version:** Full PPL detection requires Windows 8.1+
3. **Context Menu:** Requires admin privileges to install/uninstall

---

## Security Notes

- **Override Mode:** Disables blacklist protection; resets on restart
- **Admin Required:** Certain operations require elevated privileges
- **Forensic Logging:** All actions logged to `%APPDATA%\BlackHole\audit.log`

---

## Support

- **Documentation:** See `README.md`
- **Issues:** Open issue on GitHub
- **License:** MIT License

---

## Acknowledgments

- Windows API documentation
- Microsoft Developer Network (MSDN)
- NSIS installer community

---

**Thank you for using Black Hole (B-H)!**
