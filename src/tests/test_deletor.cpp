#include "test_shared.h"
#include "deletor.h"
#include <Windows.h>
#include <filesystem>
#include <fstream>

using namespace BlackHole;

namespace fs = std::filesystem;

static std::wstring GetTempDir() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring dir = std::wstring(tempPath) + L"\\BlackHoleTests";
    fs::create_directories(dir);
    return dir;
}

static void CreateTempFile(const std::wstring& path, const std::string& content = "test") {
    std::ofstream f(path);
    f << content;
    f.close();
}

void RegisterDeletorTests(TestRunner& runner) {
    runner.AddTest("Deletor_CreateInstance", []() {
        Deletor d;
        return true;
    });

    runner.AddTest("Deletor_DeleteNormalFile", []() {
        std::wstring tempDir = GetTempDir();
        std::wstring testFile = tempDir + L"\\delete_normal.txt";
        CreateTempFile(testFile);

        Deletor d;
        auto result = d.DeleteFileSafely(testFile);
        return result.result == DeletionResult::Success;
    });

    runner.AddTest("Deletor_DeleteEmptyPath_Fails", []() {
        Deletor d;
        auto result = d.DeleteFileSafely(L"");
        return result.result == DeletionResult::Failed_InvalidPath;
    });

    runner.AddTest("Deletor_DeleteInvalidPath_Fails", []() {
        Deletor d;
        auto result = d.DeleteFileSafely(L"Z:\\nonexistent\\file.txt");
        return result.result == DeletionResult::Failed_PathNotFound;
    });

    runner.AddTest("Deletor_ScheduleReboot", []() {
        std::wstring tempDir = GetTempDir();
        std::wstring testFile = tempDir + L"\\reboot_test.txt";
        CreateTempFile(testFile);

        Deletor d;
        bool scheduled = d.ScheduleDeletionOnReboot(testFile);
        return true;
    });

    runner.AddTest("Deletor_GetPendingDeletions", []() {
        Deletor d;
        auto pending = d.GetPendingRebootDeletions();
        return true;
    });

    runner.AddTest("Deletor_DeleteReadOnlyFile", []() {
        std::wstring tempDir = GetTempDir();
        std::wstring testFile = tempDir + L"\\readonly_test.txt";
        CreateTempFile(testFile);
        SetFileAttributesW(testFile.c_str(), FILE_ATTRIBUTE_READONLY);

        Deletor d;
        auto result = d.DeleteFileSafely(testFile);
        return result.result == DeletionResult::Success ||
               result.result == DeletionResult::Scheduled_Reboot;
    });

    runner.AddTest("Deletor_DeleteHiddenFile", []() {
        std::wstring tempDir = GetTempDir();
        std::wstring testFile = tempDir + L"\\hidden_test.txt";
        CreateTempFile(testFile);
        SetFileAttributesW(testFile.c_str(), FILE_ATTRIBUTE_HIDDEN);

        Deletor d;
        auto result = d.DeleteFileSafely(testFile);
        return result.result == DeletionResult::Success ||
               result.result == DeletionResult::Scheduled_Reboot;
    });

    runner.AddTest("Deletor_DeleteDirectory", []() {
        std::wstring tempDir = GetTempDir();
        std::wstring testDir = tempDir + L"\\test_dir";
        fs::create_directories(testDir);
        CreateTempFile(testDir + L"\\a.txt");
        CreateTempFile(testDir + L"\\b.txt");

        Deletor d;
        auto result = d.DeleteFileSafely(testDir);
        return result.result == DeletionResult::Success ||
               result.result == DeletionResult::Scheduled_Reboot;
    });

    runner.AddTest("Deletor_IsProcessProtected_FalseForNonexistent", []() {
        Deletor d;
        bool protected_ = d.IsProcessProtected(99999);
        return !protected_;
    });

    runner.AddTest("Deletor_GetProcessProtectionLevel_ZeroForNonexistent", []() {
        Deletor d;
        DWORD level = d.GetProcessProtectionLevel(99999);
        return level == 0;
    });

    runner.AddTest("Deletor_GetProcessesLockingFile", []() {
        Deletor d;
        auto procs = d.GetProcessesLockingFile(L"C:\\Windows\\System32\\ntoskrnl.exe");
        return true;
    });

    runner.AddTest("Deletor_TerminateProcessSafe_FailsForNonexistent", []() {
        Deletor d;
        bool result = d.TerminateProcessIfSafe(99999);
        return !result;
    });
}
