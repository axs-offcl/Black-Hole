#ifndef BLACKHOLE_DELETOR_H
#define BLACKHOLE_DELETOR_H

#include <Windows.h>
#include <string>
#include <vector>

namespace BlackHole {

// Result of a deletion attempt
enum class DeletionResult {
    Success,              // File was successfully deleted in real-time
    Failed_AccessDenied,  // Access denied (file locked by process)
    Failed_PPLProtected,  // File is protected by Protected Process Light
    Failed_PathNotFound,  // File does not exist
    Failed_InvalidPath,   // Path is invalid or malformed
    Blocked_Blacklist,    // File is in the blacklist and was not deleted
    Scheduled_Reboot,     // File was queued for deletion on next reboot
    Error_Unknown         // Unexpected error occurred
};

// Detailed result information
struct DeletionResultInfo {
    DeletionResult result;
    DWORD errorCode;              // Win32 error code (GetLastError)
    std::wstring errorMessage;    // Human-readable error message
    std::wstring filePath;        // Original file path
    std::wstring details;         // Additional context
};

// Process information for a given PID
struct ProcessInfo {
    DWORD pid;
    std::wstring processName;
    bool isProtected;  // True if PPL-protected
    DWORD protectionLevel;
};

class Deletor {
public:
    Deletor();
    ~Deletor();

    // Non-copyable
    Deletor(const Deletor&) = delete;
    Deletor& operator=(const Deletor&) = delete;

    // Attempt to delete a file safely
    // 1. Check blacklist
    // 2. Attempt direct deletion
    // 3. If fails, check PPL status
    // 4. If PPL or locked, schedule reboot deletion
    DeletionResultInfo DeleteFileSafely(const std::wstring& path);

    // Schedule file for deletion on next reboot
    // Uses MoveFileExW with MOVEFILE_DELAY_UNTIL_REBOOT flag
    // Requires SE_BACKUP_NAME and SE_RESTORE_NAME privileges
    bool ScheduleDeletionOnReboot(const std::wstring& path);

    // Check if a process is Protected Process Light (PPL)
    // Requires Windows 8.1 or later
    bool IsProcessProtected(DWORD pid) const;

    // Get protection level for a process
    // Returns 0 if not protected, or protection level value
    DWORD GetProcessProtectionLevel(DWORD pid) const;

    // List processes that have a file locked
    std::vector<ProcessInfo> GetProcessesLockingFile(const std::wstring& path) const;

    // Attempt to terminate a process (only if not PPL-protected)
    // Returns true if process was terminated successfully
    bool TerminateProcessIfSafe(DWORD pid);

    // Get last error message
    std::wstring GetLastError() const;

    // Get the pending file rename operations from registry
    // This is what MoveFileExW writes to
    std::vector<std::wstring> GetPendingRebootDeletions() const;

    // Move a file/directory to the Windows Recycle Bin
    // Returns true on success
    bool MoveToRecycleBin(const std::wstring& path);

    // Restore a file from the Windows Recycle Bin by its original path
    bool RestoreFromRecycleBin(const std::wstring& originalPath);

    // Check if a file exists on disk
    static bool FileExists(const std::wstring& path);

    // Recursively delete a directory and all its contents
    DeletionResultInfo DeleteDirectoryRecursive(const std::wstring& dirPath);

private:
    // Internal helper to check if path is valid
    bool IsValidPath(const std::wstring& path) const;

    // Internal helper to normalize path for comparison
    std::wstring NormalizePath(const std::wstring& path) const;

    // Store last error for debugging
    std::wstring m_lastError;
    DWORD m_lastErrorCode;
};

}  // namespace BlackHole

#endif  // BLACKHOLE_DELETOR_H
