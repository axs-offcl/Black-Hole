#ifndef BLACKHOLE_PRIVILEGE_H
#define BLACKHOLE_PRIVILEGE_H

#include <Windows.h>
#include <string>

namespace BlackHole {

class PrivilegeManager {
public:
    PrivilegeManager();
    ~PrivilegeManager();

    // Non-copyable
    PrivilegeManager(const PrivilegeManager&) = delete;
    PrivilegeManager& operator=(const PrivilegeManager&) = delete;

    // Enable SE_BACKUP_NAME privilege (required for MoveFileExW with MOVEFILE_DELAY_UNTIL_REBOOT)
    // Returns true if privilege was successfully enabled
    bool EnableBackupPrivilege();

    // Enable SE_RESTORE_NAME privilege (required for MoveFileExW with MOVEFILE_DELAY_UNTIL_REBOOT)
    // Returns true if privilege was successfully enabled
    bool EnableRestorePrivilege();

    // Enable SE_TAKEOWNERSHIP_NAME privilege (allows taking ownership of protected files)
    // Returns true if privilege was successfully enabled
    bool EnableTakeOwnershipPrivilege();

    // Enable all privileges (backup, restore, take ownership)
    // Returns true if all privileges were successfully enabled
    bool EnableAllPrivileges();

    // Check if running with administrator privileges
    bool IsRunningAsAdmin() const;

    // Request UAC elevation (re-launches current process with runas verb)
    // Returns true if elevation was initiated (process will restart)
    bool RequestElevation();

    // Get last error message from privilege operation
    std::wstring GetLastError() const;

private:
    // Internal helper to enable a specific privilege
    bool EnablePrivilege(const std::wstring& privilegeName);

    // Get current process token
    HANDLE GetProcessToken() const;

    // Store last error for debugging
    std::wstring m_lastError;
    DWORD m_lastErrorCode;
};

}  // namespace BlackHole

#endif  // BLACKHOLE_PRIVILEGE_H
