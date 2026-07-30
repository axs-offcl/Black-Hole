# Changelog

All notable changes to Black Hole (B-H) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] - 2026-07-20

### Added

#### Uninstaller Engine — Production Safety Overhaul
- **Safety Blacklist:** 20 protected filesystem paths, 18 protected registry roots, 38 protected Windows service names. `PurgeLeftovers` and `ForceRemovalPipeline` double-check every delete target.
- **Confidence Scoring System:** 10-factor weighted scoring engine (BCUninstaller/DeepPurge-inspired). Factors: exact name match (+8), substring match (+6), publisher match (+3), install path match (+4), installer/client registry context (+2/+1), big-publisher penalty (-3), stop-word penalty (-4), depth penalty (-2/level), DirectoryStillUsed (-7), PublisherStillUsed (-4), IsStoreApp (-10). Thresholds: Safe (≥8), Moderate (≥4), Risky (<4).
- **Stop-Word Filtering:** 30+ generic terms (`tool`, `manager`, `free`, `runtime`, `redistributable`, etc.) + 4-character minimum length. Applied to both filesystem and registry enumeration loops to prevent false positives on shared runtime names.
- **Cross-Reference Validation:** Before flagging a leftover, checks all cached installed apps' `installPath` fields. Shared paths are un-checked automatically.
- **Reparse-Point Skip:** `FILE_ATTRIBUTE_REPARSE_POINT` (0x0400) check via `GetFileAttributesW` on every filesystem entry in `ScanDirectory`, `ScanDesktop`, and `ResolveInstallPath`. Prevents symlink/junction traversal loops.
- **Scan Depth Levels:** Safe (AppData + 3 registry hives), Moderate (+ Start Menu, Desktop, App Paths, Run/RunOnce, 2-level recursion), Advanced (+ Services, COM/CLSID, Firewall rules, Installer caches, full Program Files scan). UI selector via radio buttons in context menu.
- **Expanded Scan Locations:** 8 new scan types — Start Menu (per-user + all-users), Desktop shortcuts (.lnk), App Paths registry, Run/RunOnce/RunServices startup entries, Windows Services registry, COM/CLSID registrations, Windows Firewall rules, Installer caches (`$PatchCache$`, `Package Cache`).
- **Installer Type Detection:** Identifies Msi, InnoSetup, NSIS, InstallShield, PowerShell, SdbInst from registry values and uninstall string patterns. Sets `installerType` on every scanned entry during `ScanInstalled()`.
- **System Restore Point:** Created via `Checkpoint-Computer` PowerShell cmdlet before every force removal.
- **Registry Backup:** Exports target registry key to `%APPDATA%\BlackHole\RegistryBackups\<name>_<timestamp>.reg` before deletion.
- **Background Thread:** `ForceRemovalPipeline` runs in `std::thread` with `std::atomic<bool>` completion flag + `std::mutex` result transfer. UI remains responsive during restore point creation + scanning + deletion.
- **Deferred Force Removal:** Context menu handler sets flag + copies entry, closes popup, then processes on next frame. Eliminates dangling `selEntry` reference after entry erase.
- **Leftover Popup Always Shows:** Previously only appeared when leftovers existed. Now always opens (shows "No leftovers found" with OK button when empty). Entry erased only on popup close (OK/Purge/Cancel).
- **Confidence Display in Popup:** Each leftover item shows `[Safe]`/`[Maybe]`/`[Risky]` label with green/yellow/red color coding alongside existing `[F]`/`[D]`/`[R]` type indicators.

#### GUI Enhancements
- **Scan Depth Selector:** Radio buttons (Safe/Moderate/Advanced) in force removal context menu.
- **Date Validation:** Invalid YYYYMMDD dates (day 37, month 13, year outside 1990-2099) rejected during registry scan.
- **Real Folder Size:** Background thread calculates actual disk usage from `installPath` for every directory entry. `CalculateFolderSizeKB()` recursive function with `g_sizeCalcDone` cancellation check.
- **Icon Size:** Reduced from 20x20 to 16x16 to fit table rows.

### Fixed
- **Force Removal Crash:** Race condition — background icon/size thread iterates `g_uninstallEntries` while main thread erases from it. Fixed by setting cancel flags (`g_iconThreadRunning`, `g_sizeCalcDone`) before erasing, and checking flags inside background thread loops.
- **Force Removal Freeze:** `Sleep(16)` on UI thread blocked render loop. Removed; cancel flags checked on every file iteration provide sufficient safety.
- **Leftover Popup Not Appearing:** `g_showLeftoverPopup` was only set when `result.leftovers` was non-empty. Now always set.
- **Dangling Reference:** Entry was erased inside popup handler while ImGui still processed menu items referencing it. Fixed by deferring erase to popup close.
- **Uninstaller Context Menu Crash:** `BeginPopupContextItem` inside for loop returned true for ALL rows when popup was open, rendering menu items 200+ times. Fixed by detecting right-click inside loop and rendering popup outside `EndTable()`.

### Changed
- **Force Removal Pipeline:** Now accepts `ScanDepth` parameter (defaults to `Safe`).
- **ScanLeftovers:** Now accepts `ScanDepth` parameter. Registry and filesystem scans gated by depth level.
- **ScoreConfidence:** Expanded from 6 heuristics to 10 with cached-app cross-reference.
- **ScanRegistryForLeftovers:** Now calls `IsStopWord()` before match logic in both top-level and sub-key loops.
- **ScanDirectory:** Now checks `FILE_ATTRIBUTE_REPARSE_POINT` on parent dir, top-level entries, and recursive sub-entries.
- **PurgeLeftovers:** Now checks `IsProtectedPath()` and `IsProtectedRegistryKey()` before every delete.
- **UninstallEntry struct:** Added `installerType` field (`InstallerType` enum).

---

## [2.0.0] - 2026-07-15

### Added

#### Core Engine (Milestone 1)
- **BlacklistModule:** Hardcoded protection for 20+ critical system files
- **PrivilegeManager:** `SE_BACKUP_NAME` and `SE_RESTORE_NAME` privilege management
- **Deletor:** Safe file deletion with `MoveFileExW` reboot queue
- **Logger:** Forensic timestamped logging to `%APPDATA%\BlackHole\audit.log`
- **CLI Interface:** Command-line tool for testing and scripting

#### GUI Application (Milestone 2)
- **Win32 Dashboard:** ListView with columns for Time, Action, File Path, Details
- **System Tray:** Minimize to tray with right-click menu
- **Bottom-Edge Notifications:** Sliding popups for deletion status
- **Override Controls:** Text-based confirmation ("I assume full liability")
- **Context Menu Integration:** Right-click "Send to Black Hole"
- **Menu Bar:** File and Tools menus with all functionality

#### Integration & Testing (Milestone 3)
- **Unit Tests:** 62 tests covering all core modules
- **Integration Tests:** 10 tests for end-to-end verification
- **NSIS Installer:** Professional installer with UAC support
- **Documentation:** README.md, TEST_REPORT.md, CHANGELOG.md

### Security Features
- **Blacklist Protection:** Prevents deletion of ntoskrnl.exe, lsass.exe, bootmgr, etc.
- **Case-Sensitive Override:** Exact phrase required: "I assume full liability"
- **No Persistence:** Override resets on application restart
- **Forensic Logging:** Every action logged with timestamp
- **PPL Detection:** Identifies Protected Process Light processes
- **Admin Elevation:** Required for privileged operations

### Technical Details
- **Target:** Windows 8.1+ (for full PPL detection)
- **Build:** Visual Studio 2022, C++17, CMake 3.15+
- **Libraries:** advapi32, kernel32, shell32, ntdll, psapi, comctl32
- **Character Set:** Unicode (UNICODE, _UNICODE)

### Known Limitations
- PPL-protected files cannot be deleted in real-time; queued for reboot
- Context menu installation requires Administrator privileges
- Notification queue limited to 100 entries (oldest dropped on overflow)
- Requires Windows 8.1+ for `GetProcessProtectionLevel` API

---

## [1.0.0] - 2026-07-01

### Added
- Initial project planning and architecture design
- AI Protocol compliance framework
- Technical feasibility assessment

### Notes
- This version was never released
- Development began with Milestone 1 (Core Engine)

---

## [0.1.0] - 2026-06-15

### Added
- Project concept and requirements gathering
- Security review and constraint definition
- Blacklist file list compilation

### Notes
- Pre-development phase
- Architecture decisions documented

---

## Release History

| Version | Date | Status |
|---------|------|--------|
| 2.1.0 | 2026-07-20 | Current Release |
| 2.0.0 | 2026-07-15 | Stable |
| 1.0.0 | 2026-07-01 | Development Only |
| 0.1.0 | 2026-06-15 | Planning Only |

---

## Upgrade Notes

### From 1.0.0 to 2.0.0
- This is the first public release
- No upgrade path from previous versions
- Clean installation recommended

---

## Support

For issues and bug reports, please open an issue on GitHub.

---

**Maintained by:** Black Hole Project
**License:** MIT
