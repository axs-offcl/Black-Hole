#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <functional>
#include <filesystem>
#include <chrono>
#include <thread>
#include <shlobj.h>

#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

struct IntegrationTestResult {
    std::string testName;
    bool passed;
    std::string message;
};

class IntegrationTestRunner {
public:
    static IntegrationTestRunner& Instance() {
        static IntegrationTestRunner instance;
        return instance;
    }

    void AddTest(const std::string& name, std::function<IntegrationTestResult()> testFunc) {
        tests.push_back({name, testFunc});
    }

    int RunAll() {
        int passed = 0;
        int failed = 0;

        std::cout << "Black Hole (B-H) v2.0 - Integration Tests\n";
        std::cout << "==========================================\n\n";

        for (auto& test : tests) {
            std::cout << "Running: " << test.name << "... ";
            
            IntegrationTestResult result;
            try {
                result = test.func();
            } catch (const std::exception& e) {
                result.passed = false;
                result.message = "Exception: " + std::string(e.what());
            } catch (...) {
                result.passed = false;
                result.message = "Unknown exception";
            }

            if (result.passed) {
                std::cout << "PASS\n";
                passed++;
            } else {
                std::cout << "FAIL\n";
                std::cout << "  Error: " << result.message << "\n";
                failed++;
            }
        }

        std::cout << "\n==========================================\n";
        std::cout << "Results: " << passed << " passed, " << failed << " failed\n";
        std::cout << "Pass Rate: " << (passed * 100 / tests.size()) << "%\n";

        return failed == 0 ? 0 : 1;
    }

    void GenerateReport(const std::string& filename) {
        std::ofstream report(filename);
        if (!report.is_open()) return;

        report << "# Black Hole - Integration Test Report\n\n";
        report << "**Date:** " << __DATE__ << " " << __TIME__ << "\n";
        report << "**Version:** 2.0.0\n\n";
        report << "## Test Results\n\n";
        report << "| # | Test Name | Status | Details |\n";
        report << "|---|-----------|--------|---------|\n";

        int passed = 0;
        int failed = 0;

        for (size_t i = 0; i < tests.size(); ++i) {
            IntegrationTestResult result;
            try {
                result = tests[i].func();
            } catch (...) {
                result.passed = false;
                result.message = "Exception";
            }

            report << "| " << (i + 1) << " | " << tests[i].name 
                   << " | " << (result.passed ? "PASS" : "FAIL")
                   << " | " << result.message << " |\n";

            if (result.passed) passed++;
            else failed++;
        }

        report << "\n## Summary\n\n";
        report << "- **Total Tests:** " << tests.size() << "\n";
        report << "- **Passed:** " << passed << "\n";
        report << "- **Failed:** " << failed << "\n";
        report << "- **Pass Rate:** " << (passed * 100 / tests.size()) << "%\n\n";

        if (failed == 0) {
            report << "## Conclusion\n\n";
            report << "All integration tests passed. The application is ready for release.\n";
        } else {
            report << "## Issues Found\n\n";
            report << "Some tests failed. Please review the failures before release.\n";
        }

        report.close();
    }

private:
    struct Test {
        std::string name;
        std::function<IntegrationTestResult()> func;
    };

    std::vector<Test> tests;
};

std::wstring GetTempDir() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring testDir = std::wstring(tempPath) + L"BlackHoleTests";
    CreateDirectoryW(testDir.c_str(), NULL);
    return testDir;
}

std::wstring CreateTestFile(const std::wstring& dir, const std::wstring& name, const std::wstring& content = L"test content") {
    std::wstring path = dir + L"\\" + name;
    std::wofstream file(path);
    if (file.is_open()) {
        file << content;
        file.close();
    }
    return path;
}

bool FileExists(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES);
}

int RunCommand(const std::wstring& command, std::wstring& output) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags = STARTF_USESTDHANDLES;
    ZeroMemory(&pi, sizeof(pi));

    std::vector<wchar_t> cmdLine(command.begin(), command.end());
    cmdLine.push_back(0);

    if (!CreateProcessW(NULL, cmdLine.data(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return -1;
    }

    CloseHandle(hWritePipe);

    char buffer[4096];
    DWORD bytesRead;
    output.clear();

    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = 0;
        output += std::wstring(buffer, buffer + bytesRead);
    }

    WaitForSingleObject(pi.hProcess, 10000);

    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    return static_cast<int>(exitCode);
}

std::wstring GetExePath() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);
    size_t lastSlash = path.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        return path.substr(0, lastSlash) + L"\\BlackHole.exe";
    }
    return L"BlackHole.exe";
}

bool CheckLogFile(const std::wstring& expectedAction, const std::wstring& expectedFile) {
    wchar_t appDataPath[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appDataPath) != S_OK) {
        return false;
    }

    std::wstring logPath = std::wstring(appDataPath) + L"\\BlackHole\\audit.log";
    std::wifstream logFile(logPath);
    if (!logFile.is_open()) {
        return false;
    }

    std::wstring line;
    while (std::getline(logFile, line)) {
        if (line.find(expectedAction) != std::wstring::npos &&
            line.find(expectedFile) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

bool CheckRegistryKey(const std::wstring& keyPath) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CLASSES_ROOT, keyPath.c_str(), 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

IntegrationTestRunner& GetRunner() {
    static IntegrationTestRunner runner;
    return runner;
}

#define INTEGRATION_TEST(testName) \
    IntegrationTestResult testName(); \
    namespace { \
        struct Register_##testName { \
            Register_##testName() { \
                GetRunner().AddTest(#testName, testName); \
            } \
        } register_##testName; \
    } \
    IntegrationTestResult testName()

INTEGRATION_TEST(TestDeleteRegularFile) {
    IntegrationTestResult result;
    result.testName = "Delete Regular File";

    std::wstring tempDir = GetTempDir();
    std::wstring testFile = CreateTestFile(tempDir, L"test_regular.txt");

    if (!FileExists(testFile)) {
        result.passed = false;
        result.message = "Failed to create test file";
        return result;
    }

    std::wstring exePath = GetExePath();
    std::wstring command = L"\"" + exePath + L"\" --delete \"" + testFile + L"\"";
    std::wstring output;
    int exitCode = RunCommand(command, output);

    result.passed = !FileExists(testFile);
    result.message = result.passed ? "File deleted successfully" : "File still exists after deletion";
    return result;
}

INTEGRATION_TEST(TestDeleteReadOnlyFile) {
    IntegrationTestResult result;
    result.testName = "Delete Read-Only File";

    std::wstring tempDir = GetTempDir();
    std::wstring testFile = CreateTestFile(tempDir, L"test_readonly.txt");
    SetFileAttributesW(testFile.c_str(), FILE_ATTRIBUTE_READONLY);

    if (!FileExists(testFile)) {
        result.passed = false;
        result.message = "Failed to create test file";
        return result;
    }

    std::wstring exePath = GetExePath();
    std::wstring command = L"\"" + exePath + L"\" --delete \"" + testFile + L"\"";
    std::wstring output;
    int exitCode = RunCommand(command, output);

    result.passed = !FileExists(testFile);
    result.message = result.passed ? "Read-only file deleted" : "Read-only file still exists";
    return result;
}

INTEGRATION_TEST(TestBlacklistBlock) {
    IntegrationTestResult result;
    result.testName = "Blacklist Block";

    std::wstring exePath = GetExePath();
    std::wstring command = L"\"" + exePath + L"\" --delete \"C:\\Windows\\System32\\ntoskrnl.exe\"";
    std::wstring output;
    int exitCode = RunCommand(command, output);

    result.passed = (exitCode == 1);
    result.message = result.passed ? "Blacklist correctly blocked deletion" : "Blacklist did not block deletion";
    return result;
}

INTEGRATION_TEST(TestCheckBlacklistedFile) {
    IntegrationTestResult result;
    result.testName = "Check Blacklisted File";

    std::wstring exePath = GetExePath();
    std::wstring command = L"\"" + exePath + L"\" --check \"C:\\Windows\\System32\\ntoskrnl.exe\"";
    std::wstring output;
    int exitCode = RunCommand(command, output);

    result.passed = (output.find(L"Blacklisted: YES") != std::wstring::npos);
    result.message = result.passed ? "Check correctly identified blacklisted file" : "Check failed to identify blacklisted file";
    return result;
}

INTEGRATION_TEST(TestCheckNonBlacklistedFile) {
    IntegrationTestResult result;
    result.testName = "Check Non-Blacklisted File";

    std::wstring tempDir = GetTempDir();
    std::wstring testFile = CreateTestFile(tempDir, L"test_check.txt");

    std::wstring exePath = GetExePath();
    std::wstring command = L"\"" + exePath + L"\" --check \"" + testFile + L"\"";
    std::wstring output;
    int exitCode = RunCommand(command, output);

    result.passed = (output.find(L"Blacklisted: NO") != std::wstring::npos);
    result.message = result.passed ? "Check correctly identified non-blacklisted file" : "Check failed";
    return result;
}

INTEGRATION_TEST(TestLogEntryCreated) {
    IntegrationTestResult result;
    result.testName = "Log Entry Created";

    std::wstring tempDir = GetTempDir();
    std::wstring testFile = CreateTestFile(tempDir, L"test_log.txt");

    std::wstring exePath = GetExePath();
    std::wstring command = L"\"" + exePath + L"\" --delete \"" + testFile + L"\"";
    std::wstring output;
    RunCommand(command, output);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    result.passed = CheckLogFile(L"DELETION_SUCCESS", L"test_log.txt");
    result.message = result.passed ? "Log entry created" : "Log entry not found";
    return result;
}

INTEGRATION_TEST(TestDeleteNonExistentFile) {
    IntegrationTestResult result;
    result.testName = "Delete Non-Existent File";

    std::wstring exePath = GetExePath();
    std::wstring command = L"\"" + exePath + L"\" --delete \"C:\\NonExistent\\file.txt\"";
    std::wstring output;
    int exitCode = RunCommand(command, output);

    result.passed = (exitCode != 0);
    result.message = result.passed ? "Correctly returned error for non-existent file" : "Did not return error";
    return result;
}

INTEGRATION_TEST(TestScheduleRebootDeletion) {
    IntegrationTestResult result;
    result.testName = "Schedule Reboot Deletion";

    std::wstring tempDir = GetTempDir();
    std::wstring testFile = CreateTestFile(tempDir, L"test_reboot.txt");

    std::wstring exePath = GetExePath();
    std::wstring command = L"\"" + exePath + L"\" --reboot \"" + testFile + L"\"";
    std::wstring output;
    int exitCode = RunCommand(command, output);

    result.passed = (exitCode == 0);
    result.message = result.passed ? "Reboot deletion scheduled" : "Failed to schedule reboot deletion";
    return result;
}

INTEGRATION_TEST(TestStatusCommand) {
    IntegrationTestResult result;
    result.testName = "Status Command";

    std::wstring exePath = GetExePath();
    std::wstring command = L"\"" + exePath + L"\" --status";
    std::wstring output;
    int exitCode = RunCommand(command, output);

    result.passed = (output.find(L"Pending Reboot Deletions") != std::wstring::npos);
    result.message = result.passed ? "Status command works" : "Status command failed";
    return result;
}

INTEGRATION_TEST(TestHelpCommand) {
    IntegrationTestResult result;
    result.testName = "Help Command";

    std::wstring exePath = GetExePath();
    std::wstring command = L"\"" + exePath + L"\" --help";
    std::wstring output;
    int exitCode = RunCommand(command, output);

    result.passed = (output.find(L"Black Hole") != std::wstring::npos);
    result.message = result.passed ? "Help command works" : "Help command failed";
    return result;
}

int main() {
    int result = GetRunner().RunAll();
    
    GetRunner().GenerateReport("integration_test_report.md");
    
    return result;
}
