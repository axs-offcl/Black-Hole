#include "test_shared.h"
#include "blacklist.h"
#include <string>

using namespace BlackHole;

void RegisterBlacklistTests(TestRunner& runner) {
    runner.AddTest("Blacklist_EmptyPath_NotBlocked", []() {
        BlacklistModule bl;
        return !bl.IsInBlacklist(L"");
    });

    runner.AddTest("Blacklist_Ntoskrnl_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\System32\\ntoskrnl.exe");
    });

    runner.AddTest("Blacklist_Lsass_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\System32\\lsass.exe");
    });

    runner.AddTest("Blacklist_Kernel32_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\System32\\kernel32.dll");
    });

    runner.AddTest("Blacklist_Hal_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\System32\\hal.dll");
    });

    runner.AddTest("Blacklist_Bootmgr_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\System32\\bootmgr");
    });

    runner.AddTest("Blacklist_Csrss_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\System32\\csrss.exe");
    });

    runner.AddTest("Blacklist_Smss_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\System32\\smss.exe");
    });

    runner.AddTest("Blacklist_Svchost_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\System32\\svchost.exe");
    });

    runner.AddTest("Blacklist_Explorer_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\explorer.exe");
    });

    runner.AddTest("Blacklist_Cmd_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\System32\\cmd.exe");
    });

    runner.AddTest("Blacklist_Powershell_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\System32\\WindowsPowerShell\\powershell.exe");
    });

    runner.AddTest("Blacklist_NormalFile_NotBlocked", []() {
        BlacklistModule bl;
        return !bl.IsInBlacklist(L"C:\\Users\\test\\Documents\\myfile.txt");
    });

    runner.AddTest("Blacklist_TempFile_NotBlocked", []() {
        BlacklistModule bl;
        return !bl.IsInBlacklist(L"C:\\temp\\test.dat");
    });

    runner.AddTest("Blacklist_CaseInsensitive_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"c:\\windows\\system32\\NTOSKRNL.EXE");
    });

    runner.AddTest("Blacklist_PartialPath_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"D:\\Backup\\Windows\\System32\\ntoskrnl.exe");
    });

    runner.AddTest("Blacklist_Override_Activates", []() {
        BlacklistModule bl;
        bl.SetOverride(true, L"I assume full liability");
        return bl.IsOverrideActive();
    });

    runner.AddTest("Blacklist_Override_BypassesBlacklist", []() {
        BlacklistModule bl;
        bl.SetOverride(true, L"I assume full liability");
        return !bl.IsInBlacklist(L"C:\\Windows\\System32\\ntoskrnl.exe");
    });

    runner.AddTest("Blacklist_Override_WrongPhrase_Fails", []() {
        BlacklistModule bl;
        return !bl.SetOverride(true, L"wrong phrase");
    });

    runner.AddTest("Blacklist_Override_CaseSensitive", []() {
        BlacklistModule bl;
        return !bl.SetOverride(true, L"i assume full liability");
    });

    runner.AddTest("Blacklist_Override_Deactivates", []() {
        BlacklistModule bl;
        bl.SetOverride(true, L"I assume full liability");
        bl.SetOverride(false, L"");
        return !bl.IsOverrideActive();
    });

    runner.AddTest("Blacklist_Override_ResetOnStartup", []() {
        BlacklistModule bl;
        bl.ResetOverride();
        return !bl.IsOverrideActive();
    });

    runner.AddTest("Blacklist_Override_TimestampSet", []() {
        BlacklistModule bl;
        bl.SetOverride(true, L"I assume full liability");
        return !bl.GetOverrideTimestamp().empty();
    });

    runner.AddTest("Blacklist_DriversDir_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\System32\\drivers\\ntfs.sys");
    });

    runner.AddTest("Blacklist_WinDefender_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Program Files\\Windows Defender\\MsMpEng.exe");
    });

    runner.AddTest("Blacklist_RegistryConfigs_Blocked", []() {
        BlacklistModule bl;
        return bl.IsInBlacklist(L"C:\\Windows\\System32\\config\\SYSTEM");
    });
}
