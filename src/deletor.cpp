#include "deletor.h"
#include "privilege.h"
#include <algorithm>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <mutex>
#include <restartmanager.h>
#include <ShlObj.h>
#include <sddl.h>
#include <objbase.h>
#include <shlwapi.h>

#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK 0xA000000C
#endif
#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003
#endif
#ifndef MAXIMUM_REPARSE_DATA_BUFFER_SIZE
#define MAXIMUM_REPARSE_DATA_BUFFER_SIZE 16384
#endif

#ifndef REPARSE_DATA_BUFFER
#pragma pack(push, 1)
typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;
    };
} REPARSE_DATA_BUFFER;
#pragma pack(pop)
#endif

namespace BlackHole {

typedef DWORD (WINAPI *pfnRmStartSession)(DWORD *pSessionHandle, DWORD dwSessionFlags, wchar_t *strSessionKey);
typedef DWORD (WINAPI *pfnRmRegisterResources)(DWORD dwSessionHandle, UINT nFiles, const wchar_t **rgsFileNames, UINT nApplications, RM_UNIQUE_PROCESS *rgApplications, UINT nServices, wchar_t **rgsServiceNames);
typedef DWORD (WINAPI *pfnRmGetList)(DWORD dwSessionHandle, UINT *pnProcInfoNeeded, UINT *pnProcInfo, RM_PROCESS_INFO *rgAffectedApps, DWORD *lpwServicesBuffer);
typedef DWORD (WINAPI *pfnRmEndSession)(DWORD dwSessionHandle);

static pfnRmStartSession fnRmStartSession = nullptr;
static pfnRmRegisterResources fnRmRegisterResources = nullptr;
static pfnRmGetList fnRmGetList = nullptr;
static pfnRmEndSession fnRmEndSession = nullptr;
static std::once_flag g_rmInitFlag;

static void LoadRestartManager() {
    std::call_once(g_rmInitFlag, []() {
        HMODULE hMod = LoadLibraryW(L"rstrtmgr.dll");
        if (hMod) {
            fnRmStartSession = (pfnRmStartSession)GetProcAddress(hMod, "RmStartSession");
            fnRmRegisterResources = (pfnRmRegisterResources)GetProcAddress(hMod, "RmRegisterResources");
            fnRmGetList = (pfnRmGetList)GetProcAddress(hMod, "RmGetList");
            fnRmEndSession = (pfnRmEndSession)GetProcAddress(hMod, "RmEndSession");
        }
    });
}

Deletor::Deletor()
    : m_lastErrorCode(0) {
}

Deletor::~Deletor() {
}

DeletionResultInfo Deletor::DeleteFileSafely(const std::wstring& path) {
    DeletionResultInfo info = {};
    info.filePath = path;
    info.result = DeletionResult::Error_Unknown;

    if (path.empty()) {
        info.result = DeletionResult::Failed_InvalidPath;
        info.errorMessage = L"Empty path";
        return info;
    }

    std::wstring normalizedPath = NormalizePath(path);

    if (!IsValidPath(normalizedPath)) {
        info.result = DeletionResult::Failed_InvalidPath;
        info.errorMessage = L"Invalid path format";
        return info;
    }

    DWORD attrs = GetFileAttributesW(normalizedPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        DWORD err = ::GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            info.result = DeletionResult::Failed_PathNotFound;
            info.errorMessage = L"File not found";
            info.errorCode = err;
            return info;
        }

        HANDLE hFile = CreateFileW(normalizedPath.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD reparseTag = 0;
            DWORD returned = 0;
            REPARSE_DATA_BUFFER* rdb = nullptr;
            BYTE buf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];

            if (DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0,
                buf, sizeof(buf), &returned, NULL)) {
                rdb = (REPARSE_DATA_BUFFER*)buf;
                reparseTag = rdb->ReparseTag;
            }

            if (reparseTag == IO_REPARSE_TAG_SYMLINK || reparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
                CloseHandle(hFile);
                if (DeleteFileW(normalizedPath.c_str())) {
                    info.result = DeletionResult::Success;
                    info.errorMessage = L"Broken symlink/link deleted";
                    return info;
                }
                if (RemoveDirectoryW(normalizedPath.c_str())) {
                    info.result = DeletionResult::Success;
                    info.errorMessage = L"Broken directory junction deleted";
                    return info;
                }
                DWORD removeErr = ::GetLastError();
                info.errorCode = removeErr;
                if (ScheduleDeletionOnReboot(normalizedPath)) {
                    info.result = DeletionResult::Scheduled_Reboot;
                    info.errorMessage = L"Broken link scheduled for reboot deletion";
                    return info;
                }
                info.result = DeletionResult::Error_Unknown;
                info.errorMessage = L"Failed to delete broken link";
                info.errorCode = ::GetLastError();
                return info;
            }
            CloseHandle(hFile);
        }
        info.result = DeletionResult::Failed_PathNotFound;
        info.errorMessage = L"File not found";
        info.errorCode = err;
        return info;
    }

    bool isDirectory = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;

    if (isDirectory) {
        return DeleteDirectoryRecursive(normalizedPath);
    }

    if (attrs & (FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY)) {
        SetFileAttributesW(normalizedPath.c_str(), attrs & ~(FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY));
    }

    HANDLE hFile = CreateFileW(normalizedPath.c_str(),
        DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD reparseTag = 0;
        DWORD returned = 0;
        BYTE buf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];

        if (DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0,
            buf, sizeof(buf), &returned, NULL)) {
            REPARSE_DATA_BUFFER* rdb = (REPARSE_DATA_BUFFER*)buf;
            reparseTag = rdb->ReparseTag;
        }

        if (reparseTag == IO_REPARSE_TAG_SYMLINK || reparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
            FILE_DISPOSITION_INFO fdi = {};
            fdi.DeleteFile = TRUE;
            if (SetFileInformationByHandle(hFile, FileDispositionInfo, &fdi, sizeof(fdi))) {
                CloseHandle(hFile);
                info.result = DeletionResult::Success;
                info.errorMessage = (reparseTag == IO_REPARSE_TAG_SYMLINK)
                    ? L"Symlink deleted" : L"Junction deleted";
                return info;
            }
            CloseHandle(hFile);
            if (ScheduleDeletionOnReboot(normalizedPath)) {
                info.result = DeletionResult::Scheduled_Reboot;
                info.errorMessage = L"Reparse point scheduled for reboot deletion";
                return info;
            }
            info.result = DeletionResult::Failed_AccessDenied;
            info.errorMessage = L"Failed to delete reparse point";
            info.errorCode = ::GetLastError();
            return info;
        }

        FILE_DISPOSITION_INFO fdi = {};
        fdi.DeleteFile = TRUE;
        if (SetFileInformationByHandle(hFile, FileDispositionInfo, &fdi, sizeof(fdi))) {
            CloseHandle(hFile);
            info.result = DeletionResult::Success;
            info.errorMessage = L"Deleted via handle (atomic)";
            return info;
        }

        DWORD handleErr = ::GetLastError();
        if (handleErr == ERROR_ACCESS_DENIED && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            FILE_DISPOSITION_INFO fdiEx = {};
            fdiEx.DeleteFile = TRUE;
            if (SetFileInformationByHandle(hFile, FileDispositionInfo, &fdiEx, sizeof(fdiEx))) {
                CloseHandle(hFile);
                info.result = DeletionResult::Success;
                info.errorMessage = L"Deleted via handle (retry)";
                return info;
            }
        }
        CloseHandle(hFile);
    }

    if (normalizedPath.find(L':') != std::wstring::npos) {
        size_t colonPos = normalizedPath.find(L':');
        size_t nextAfterDrive = (colonPos == 1) ? 2 : colonPos;
        if (normalizedPath.find(L':', nextAfterDrive) != std::wstring::npos) {
            HANDLE hAds = CreateFileW(normalizedPath.c_str(), DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
            if (hAds != INVALID_HANDLE_VALUE) {
                FILE_DISPOSITION_INFO adsFdi = {};
                adsFdi.DeleteFile = TRUE;
                if (SetFileInformationByHandle(hAds, FileDispositionInfo, &adsFdi, sizeof(adsFdi))) {
                    CloseHandle(hAds);
                    info.result = DeletionResult::Success;
                    info.errorMessage = L"ADS stream deleted";
                    return info;
                }
                CloseHandle(hAds);
            }
        }
    }

    if (DeleteFileW(normalizedPath.c_str())) {
        info.result = DeletionResult::Success;
        info.errorMessage = L"Deleted directly";
        return info;
    }
    DWORD directErr = ::GetLastError();

    std::wstring uncPath = L"\\\\?\\" + normalizedPath;
    if (DeleteFileW(uncPath.c_str())) {
        info.result = DeletionResult::Success;
        info.errorMessage = L"Deleted via UNC path";
        return info;
    }

    if (attrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(normalizedPath.c_str(), FILE_ATTRIBUTE_NORMAL);
        if (DeleteFileW(normalizedPath.c_str())) {
            info.result = DeletionResult::Success;
            info.errorMessage = L"Deleted after stripping attributes";
            return info;
        }
    }

    if (DeleteFileW(uncPath.c_str())) {
        info.result = DeletionResult::Success;
        info.errorMessage = L"Deleted via UNC with backup semantics";
        return info;
    }

    std::vector<ProcessInfo> lockingProcesses = GetProcessesLockingFile(normalizedPath);
    for (auto& proc : lockingProcesses) {
        if (!proc.isProtected) {
            if (TerminateProcessIfSafe(proc.pid)) {
                if (DeleteFileW(normalizedPath.c_str())) {
                    info.result = DeletionResult::Success;
                    info.errorMessage = L"Deleted after terminating process: " + proc.processName;
                    return info;
                }
            }
        }
    }

    if (ScheduleDeletionOnReboot(normalizedPath)) {
        info.result = DeletionResult::Scheduled_Reboot;
        info.errorMessage = L"Scheduled for reboot deletion";
        info.errorCode = directErr;
        return info;
    }

    info.result = DeletionResult::Failed_AccessDenied;
    info.errorMessage = L"Failed to delete file";
    info.errorCode = directErr;
    return info;
}

bool Deletor::ScheduleDeletionOnReboot(const std::wstring& path) {
    BlackHole::PrivilegeManager pm;
    pm.EnableBackupPrivilege();
    pm.EnableRestorePrivilege();

    std::wstring longPath = path;
    if (longPath.size() > MAX_PATH) {
        if (longPath.substr(0, 4) != L"\\\\?\\") {
            longPath = L"\\\\?\\" + longPath;
        }
    }

    BOOL result = MoveFileExW(longPath.c_str(), NULL,
        MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING);
    if (!result) {
        result = MoveFileExW(path.c_str(), NULL,
            MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING);
    }
    return result != FALSE;
}

bool Deletor::IsProcessProtected(DWORD pid) const {
    return GetProcessProtectionLevel(pid) > 0;
}

DWORD Deletor::GetProcessProtectionLevel(DWORD pid) const {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return 0;

    DWORD protectionLevel = 0;
    DWORD returnLength = 0;

    typedef NTSTATUS (WINAPI *pfnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static pfnNtQueryInformationProcess NtQueryInformationProcess = nullptr;
    static std::once_flag ntQueryInitFlag;
    std::call_once(ntQueryInitFlag, []() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        }
    });

    if (NtQueryInformationProcess) {
        NTSTATUS status = NtQueryInformationProcess(hProcess, 29, &protectionLevel,
            sizeof(protectionLevel), &returnLength);
        if (status != 0) {
            protectionLevel = 0;
        }
    }

    CloseHandle(hProcess);
    return protectionLevel;
}

std::vector<ProcessInfo> Deletor::GetProcessesLockingFile(const std::wstring& path) const {
    std::vector<ProcessInfo> result;
    LoadRestartManager();

    if (!fnRmStartSession || !fnRmRegisterResources || !fnRmGetList || !fnRmEndSession) {
        return result;
    }

    DWORD sessionHandle = 0;
    wchar_t sessionKey[CCH_RM_SESSION_KEY + 1] = {0};
    DWORD rmResult = fnRmStartSession(&sessionHandle, 0, sessionKey);
    if (rmResult != ERROR_SUCCESS) {
        return result;
    }

    const wchar_t* filePath = path.c_str();
    rmResult = fnRmRegisterResources(sessionHandle, 1, &filePath, 0, NULL, 0, NULL);
    if (rmResult != ERROR_SUCCESS) {
        fnRmEndSession(sessionHandle);
        return result;
    }

    UINT pnProcInfoNeeded = 0;
    UINT pnProcInfo = 0;
    rmResult = fnRmGetList(sessionHandle, &pnProcInfoNeeded, &pnProcInfo, NULL, NULL);
    if (rmResult == ERROR_SUCCESS && pnProcInfoNeeded > 0) {
        std::vector<RM_PROCESS_INFO> procInfo(pnProcInfoNeeded);
        rmResult = fnRmGetList(sessionHandle, &pnProcInfoNeeded, &pnProcInfo, procInfo.data(), NULL);
        if (rmResult == ERROR_SUCCESS) {
            for (UINT i = 0; i < pnProcInfo; ++i) {
                ProcessInfo pi = {};
                pi.pid = procInfo[i].Process.dwProcessId;
                pi.processName = std::wstring(procInfo[i].strAppName);
                pi.isProtected = false;
                pi.protectionLevel = 0;
                result.push_back(pi);
            }
        }
    }

    fnRmEndSession(sessionHandle);
    return result;
}

bool Deletor::TerminateProcessIfSafe(DWORD pid) {
    if (IsProcessProtected(pid)) {
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return false;

    BOOL result = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    return result != FALSE;
}

std::wstring Deletor::GetLastError() const {
    return m_lastError;
}

std::vector<std::wstring> Deletor::GetPendingRebootDeletions() const {
    std::vector<std::wstring> result;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD type = 0;
        DWORD dataSize = 0;
        if (RegQueryValueExW(hKey, L"PendingFileRenameOperations", NULL, &type, NULL, &dataSize) == ERROR_SUCCESS &&
            type == REG_MULTI_SZ) {
            std::vector<wchar_t> buffer(dataSize / sizeof(wchar_t));
            if (RegQueryValueExW(hKey, L"PendingFileRenameOperations", NULL, NULL,
                (LPBYTE)buffer.data(), &dataSize) == ERROR_SUCCESS) {
                const wchar_t* ptr = buffer.data();
                while (*ptr) {
                    result.push_back(ptr);
                    ptr += wcslen(ptr) + 1;
                }
            }
        }
        RegCloseKey(hKey);
    }
    return result;
}

bool Deletor::IsValidPath(const std::wstring& path) const {
    if (path.empty()) return false;
    if (path.size() < 3) return false;
    if (path[1] != L':' && path[0] != L'\\') return false;

    std::wstring upper = path;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::towupper);

    if (upper.find(L"\\\\.\\") == 0 || upper.find(L"\\\\?\\") == 0) {
        if (upper.find(L"\\\\.\\PHYSICALDRIVE") == 0 ||
            upper.find(L"\\\\.\\TAPE") == 0 ||
            upper.find(L"\\\\.\\CDROM") == 0 ||
            upper.find(L"\\\\.\\FLOPPY") == 0) {
            return false;
        }
    }

    static const wchar_t* reserved[] = {
        L"CON", L"PRN", L"AUX", L"NUL",
        L"COM1", L"COM2", L"COM3", L"COM4", L"COM5",
        L"COM6", L"COM7", L"COM8", L"COM9",
        L"LPT1", L"LPT2", L"LPT3", L"LPT4", L"LPT5",
        L"LPT6", L"LPT7", L"LPT8", L"LPT9",
        NULL
    };

    std::wstring filename;
    size_t lastSlash = path.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) {
        filename = path.substr(lastSlash + 1);
    } else {
        filename = path;
    }

    size_t dotPos = filename.find(L'.');
    std::wstring namePart = (dotPos != std::wstring::npos) ? filename.substr(0, dotPos) : filename;
    std::wstring nameUpper = namePart;
    std::transform(nameUpper.begin(), nameUpper.end(), nameUpper.begin(), ::towupper);

    for (const wchar_t** r = reserved; *r; ++r) {
        if (nameUpper == *r) return false;
    }

    return true;
}

std::wstring Deletor::NormalizePath(const std::wstring& path) const {
    std::wstring normalized = path;

    while (normalized.size() > 1 && normalized.back() == L'\\') {
        normalized.pop_back();
    }

    if (normalized.size() >= 4 && normalized.substr(0, 4) == L"\\\\?\\") {
        normalized = normalized.substr(4);
    }

    return normalized;
}

DeletionResultInfo Deletor::DeleteDirectoryRecursive(const std::wstring& dirPath) {
    DeletionResultInfo info = {};
    info.filePath = dirPath;

    std::error_code ec;

    // Phase 1: Enumerate all entries depth-first and collect paths
    std::vector<std::wstring> allFiles;
    std::vector<std::wstring> allDirs;

    for (auto& entry : std::filesystem::recursive_directory_iterator(dirPath, ec)) {
        std::wstring entryPath = entry.path().wstring();
        if (entry.is_regular_file(ec)) {
            allFiles.push_back(entryPath);
        } else if (entry.is_directory(ec)) {
            allDirs.push_back(entryPath);
        }
    }

    if (ec) {
        // Even if enumeration had errors, try to schedule what we can
        if (ScheduleDeletionOnReboot(dirPath)) {
            info.result = DeletionResult::Scheduled_Reboot;
            info.errorMessage = L"Directory scheduled for reboot deletion (partial enumeration)";
            info.errorCode = ec.value();
            return info;
        }
        info.result = DeletionResult::Failed_AccessDenied;
        info.errorMessage = L"Failed to enumerate directory contents";
        info.errorCode = ec.value();
        return info;
    }

    // Phase 2: Delete all files with full robust pipeline
    bool anyFailure = false;
    DWORD lastErr = 0;

    for (auto& filePath : allFiles) {
        DWORD fattrs = GetFileAttributesW(filePath.c_str());
        if (fattrs != INVALID_FILE_ATTRIBUTES && (fattrs & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN))) {
            SetFileAttributesW(filePath.c_str(), fattrs & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN));
        }

        if (DeleteFileW(filePath.c_str())) continue;

        std::wstring uncPath = L"\\\\?\\" + filePath;
        if (DeleteFileW(uncPath.c_str())) continue;

        SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_NORMAL);
        if (DeleteFileW(filePath.c_str())) continue;

        std::vector<ProcessInfo> lockers = GetProcessesLockingFile(filePath);
        bool killed = false;
        for (auto& proc : lockers) {
            if (!proc.isProtected && TerminateProcessIfSafe(proc.pid)) {
                if (DeleteFileW(filePath.c_str())) { killed = true; break; }
            }
        }
        if (killed) continue;

        if (ScheduleDeletionOnReboot(filePath)) continue;

        anyFailure = true;
        lastErr = ::GetLastError();
    }

    // Phase 3: Delete subdirectories bottom-up (deepest first)
    std::sort(allDirs.begin(), allDirs.end(), [](const std::wstring& a, const std::wstring& b) {
        return a.size() > b.size();
    });

    for (auto& dirEntry : allDirs) {
        DWORD dattrs = GetFileAttributesW(dirEntry.c_str());
        if (dattrs != INVALID_FILE_ATTRIBUTES && (dattrs & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN))) {
            SetFileAttributesW(dirEntry.c_str(), dattrs & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN));
        }

        if (RemoveDirectoryW(dirEntry.c_str())) continue;

        if (ScheduleDeletionOnReboot(dirEntry)) continue;

        anyFailure = true;
        lastErr = ::GetLastError();
    }

    // Phase 4: Remove the root directory itself
    DWORD rootAttrs = GetFileAttributesW(dirPath.c_str());
    if (rootAttrs != INVALID_FILE_ATTRIBUTES && (rootAttrs & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN))) {
        SetFileAttributesW(dirPath.c_str(), rootAttrs & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN));
    }

    if (RemoveDirectoryW(dirPath.c_str())) {
        info.result = anyFailure ? DeletionResult::Scheduled_Reboot : DeletionResult::Success;
        info.errorMessage = anyFailure
            ? L"Directory removed (some contents queued for reboot)"
            : L"Directory removed recursively";
        return info;
    }

    if (ScheduleDeletionOnReboot(dirPath)) {
        info.result = DeletionResult::Scheduled_Reboot;
        info.errorMessage = L"Directory root scheduled for reboot deletion";
        info.errorCode = ::GetLastError();
        return info;
    }

    info.result = anyFailure ? DeletionResult::Scheduled_Reboot : DeletionResult::Failed_AccessDenied;
    info.errorMessage = anyFailure
        ? L"Partial success: some contents queued for reboot"
        : L"Failed to remove directory";
    info.errorCode = anyFailure ? lastErr : ::GetLastError();
    return info;
}

bool Deletor::MoveToRecycleBin(const std::wstring& path) {
    if (path.empty()) return false;

    std::wstring fromBuf = path;
    fromBuf.push_back(L'\0');
    fromBuf.push_back(L'\0');

    SHFILEOPSTRUCTW op = {};
    op.wFunc = FO_DELETE;
    op.pFrom = fromBuf.c_str();
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;

    int result = SHFileOperationW(&op);
    return (result == 0);
}

bool Deletor::FileExists(const std::wstring& path) {
    if (path.empty()) return false;
    DWORD attrs = GetFileAttributesW(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES);
}

bool Deletor::RestoreFromRecycleBin(const std::wstring& originalPath) {
    if (originalPath.empty()) return false;

    wchar_t userName[256] = {};
    DWORD userNameLen = 256;
    GetUserNameW(userName, &userNameLen);

    SID_NAME_USE sidType;
    DWORD sidSize = 0, domainSize = 0;
    LookupAccountNameW(nullptr, userName, nullptr, &sidSize, nullptr, &domainSize, &sidType);
    std::vector<BYTE> sidBuf(sidSize);
    std::vector<wchar_t> domainBuf(domainSize);
    if (!LookupAccountNameW(nullptr, userName, sidBuf.data(), &sidSize, domainBuf.data(), &domainSize, &sidType))
        return false;

    wchar_t* sidStr = nullptr;
    if (!ConvertSidToStringSidW(sidBuf.data(), &sidStr))
        return false;

    std::wstring rbDir = L"C:\\$Recycle.Bin\\" + std::wstring(sidStr);
    LocalFree(sidStr);
    if (GetFileAttributesW(rbDir.c_str()) == INVALID_FILE_ATTRIBUTES)
        return false;

    std::wstring origLower = originalPath;
    std::transform(origLower.begin(), origLower.end(), origLower.begin(), ::towlower);

    std::error_code ec;
    for (auto& entry : std::filesystem::directory_iterator(rbDir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file(ec)) continue;
        std::wstring fname = entry.path().filename().wstring();
        if (fname.size() < 3 || fname[0] != L'$' || (fname[1] != L'I' && fname[1] != L'i')) continue;

        std::wstring rName = fname;
        rName[1] = L'R';
        std::wstring rPath = rbDir + L"\\" + rName;
        if (!std::filesystem::exists(rPath)) continue;

        std::ifstream ifs(entry.path(), std::ios::binary);
        if (!ifs) continue;
        std::vector<char> data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        ifs.close();
        if (data.size() < 84) continue;

        uint32_t version = *reinterpret_cast<uint32_t*>(&data[0]);
        std::wstring foundOrig;
        if (version == 2 && data.size() >= 32) {
            uint32_t pathLenBytes = *reinterpret_cast<uint32_t*>(&data[24]);
            const wchar_t* p = reinterpret_cast<const wchar_t*>(&data[28]);
            size_t maxChars = (data.size() - 28) / sizeof(wchar_t);
            size_t limit = pathLenBytes > 0 ? (size_t)pathLenBytes - 1 : maxChars;
            if (limit > maxChars) limit = maxChars;
            for (size_t i = 0; i < limit && p[i]; i++) foundOrig += p[i];
        } else if (version == 1 && data.size() >= 28) {
            const wchar_t* p = reinterpret_cast<const wchar_t*>(&data[24]);
            size_t maxChars = (data.size() - 24) / sizeof(wchar_t);
            for (size_t i = 0; i < maxChars && p[i]; i++) foundOrig += p[i];
        }
        if (foundOrig.empty()) continue;

        std::wstring foundLower = foundOrig;
        std::transform(foundLower.begin(), foundLower.end(), foundLower.begin(), ::towlower);

        if (foundLower == origLower) {
            std::wstring destDir = std::filesystem::path(foundOrig).parent_path().wstring();
            if (GetFileAttributesW(destDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
                SHCreateDirectoryExW(nullptr, destDir.c_str(), nullptr);
            }
            BOOL ok = MoveFileExW(rPath.c_str(), foundOrig.c_str(), MOVEFILE_REPLACE_EXISTING);
            if (ok) {
                SetFileAttributesW(entry.path().c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(entry.path().c_str());
                return true;
            }
        }
    }
    return false;
}

}  // namespace BlackHole
