#ifndef BLACKHOLE_BLACKLIST_H
#define BLACKHOLE_BLACKLIST_H

#include <string>
#include <vector>

namespace BlackHole {

// Hardcoded blacklist of critical Windows system files
// These files MUST NEVER be deleted, even with override active
const std::wstring SYSTEM_BLACKLIST[] = {
    L"\\Windows\\System32\\ntoskrnl.exe",
    L"\\Windows\\System32\\ntdll.dll",
    L"\\Windows\\System32\\kernel32.dll",
    L"\\Windows\\System32\\kernelbase.dll",
    L"\\Windows\\System32\\hal.dll",
    L"\\Windows\\System32\\bootmgr",
    L"\\Windows\\System32\\winload.exe",
    L"\\Windows\\System32\\winresume.exe",
    L"\\Windows\\System32\\config\\SYSTEM",
    L"\\Windows\\System32\\config\\SOFTWARE",
    L"\\Windows\\System32\\config\\SAM",
    L"\\Windows\\System32\\config\\SECURITY",
    L"\\Windows\\System32\\config\\DEFAULT",
    L"\\Windows\\System32\\drivers\\",  // Entire drivers directory
    L"\\Windows\\System32\\csrss.exe",
    L"\\Windows\\System32\\wininit.exe",
    L"\\Windows\\System32\\lsass.exe",
    L"\\Windows\\System32\\services.exe",
    L"\\Windows\\System32\\smss.exe",
    L"\\Windows\\System32\\svchost.exe",
    L"\\Windows\\explorer.exe",
    L"\\Windows\\System32\\cmd.exe",
    L"\\Windows\\System32\\powershell.exe",
    L"\\Windows\\System32\\WindowsPowerShell\\",
    L"\\Program Files\\Windows Defender\\",
    L"\\ProgramData\\Microsoft\\Windows Defender\\"
};

// Number of entries in the blacklist
constexpr size_t BLACKLIST_SIZE = sizeof(SYSTEM_BLACKLIST) / sizeof(SYSTEM_BLACKLIST[0]);

// Override state (in-memory only, no persistence)
struct OverrideState {
    bool isActive;
    std::wstring activatedAt;  // ISO 8601 timestamp
    std::wstring confirmationText;
};

class BlacklistModule {
public:
    BlacklistModule();
    ~BlacklistModule() = default;

    // Check if a file path is in the blacklist
    // Returns true if file is blacklisted and should be blocked
    bool IsInBlacklist(const std::wstring& path) const;

    // Check if a path is a blocked device path or reserved name
    static bool IsBlockedDevicePath(const std::wstring& path);

    // Get current override state
    bool IsOverrideActive() const;

    // Set override state with confirmation text validation
    // Returns true if override was successfully activated
    // confirmationText must be exactly "I assume full liability" (case-sensitive)
    bool SetOverride(bool active, const std::wstring& confirmationText);

    // Get override activation timestamp
    std::wstring GetOverrideTimestamp() const;

    // Reset override to inactive (called on application startup)
    void ResetOverride();

private:
    OverrideState m_override;
    static const std::wstring CONFIRMATION_PHRASE;
};

}  // namespace BlackHole

#endif  // BLACKHOLE_BLACKLIST_H
