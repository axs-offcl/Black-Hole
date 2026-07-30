#include "privilege.h"
#include <iostream>

namespace BlackHole {

PrivilegeManager::PrivilegeManager()
    : m_lastErrorCode(0) {
}

PrivilegeManager::~PrivilegeManager() {
}

bool PrivilegeManager::EnableBackupPrivilege() {
    return EnablePrivilege(SE_BACKUP_NAME);
}

bool PrivilegeManager::EnableRestorePrivilege() {
    return EnablePrivilege(SE_RESTORE_NAME);
}

bool PrivilegeManager::EnableTakeOwnershipPrivilege() {
    return EnablePrivilege(L"SeTakeOwnershipPrivilege");
}

bool PrivilegeManager::EnableAllPrivileges() {
    bool backup = EnableBackupPrivilege();
    bool restore = EnableRestorePrivilege();
    bool takeown = EnableTakeOwnershipPrivilege();
    return backup && restore && takeown;
}

bool PrivilegeManager::IsRunningAsAdmin() const {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

bool PrivilegeManager::RequestElevation() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = L"";
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = ::GetLastError();
        if (err == ERROR_CANCELLED) {
            m_lastError = L"User cancelled elevation request";
            m_lastErrorCode = err;
            return false;
        }
        m_lastError = L"ShellExecuteExW failed with error: " + std::to_wstring(err);
        m_lastErrorCode = err;
        return false;
    }
    return true;
}

std::wstring PrivilegeManager::GetLastError() const {
    return m_lastError;
}

bool PrivilegeManager::EnablePrivilege(const std::wstring& privilegeName) {
    HANDLE hToken = GetProcessToken();
    if (!hToken) {
        DWORD err = ::GetLastError();
        m_lastError = L"Failed to open process token: " + std::to_wstring(err);
        m_lastErrorCode = err;
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(NULL, privilegeName.c_str(), &tp.Privileges[0].Luid)) {
        DWORD err = ::GetLastError();
        m_lastError = L"LookupPrivilegeValueW failed for " + privilegeName + L": " + std::to_wstring(err);
        m_lastErrorCode = err;
        CloseHandle(hToken);
        return false;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        DWORD err = ::GetLastError();
        m_lastError = L"AdjustTokenPrivileges failed: " + std::to_wstring(err);
        m_lastErrorCode = err;
        CloseHandle(hToken);
        return false;
    }

    DWORD lastErr = ::GetLastError();
    if (lastErr == ERROR_NOT_ALL_ASSIGNED) {
        m_lastError = L"Not all privileges could be assigned for " + privilegeName;
        m_lastErrorCode = lastErr;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    m_lastError.clear();
    m_lastErrorCode = 0;
    return true;
}

HANDLE PrivilegeManager::GetProcessToken() const {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return NULL;
    }
    return hToken;
}

}  // namespace BlackHole
