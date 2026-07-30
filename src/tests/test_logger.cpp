#include "test_shared.h"
#include "logger.h"
#include <Windows.h>
#include <filesystem>
#include <fstream>

using namespace BlackHole;

namespace fs = std::filesystem;

void RegisterLoggerTests(TestRunner& runner) {
    runner.AddTest("Logger_CreateInstance", []() {
        Logger& l = GetLogger();
        return true;
    });

    runner.AddTest("Logger_Initialize", []() {
        Logger l;
        bool result = l.Initialize();
        return result;
    });

    runner.AddTest("Logger_InitializeCustomPath", []() {
        Logger l;
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring logPath = std::wstring(tempPath) + L"\\test_audit.log";
        bool result = l.Initialize(logPath);
        fs::remove(logPath);
        return result;
    });

    runner.AddTest("Logger_LogDeletion", []() {
        Logger l;
        l.Initialize();
        l.LogDeletion(LogEventType::DeletionSuccess, L"test.txt");
        l.Flush();
        return true;
    });

    runner.AddTest("Logger_LogDeletionFailed", []() {
        Logger l;
        l.Initialize();
        l.LogDeletion(LogEventType::DeletionFailed, L"test.txt", L"access denied", 5);
        l.Flush();
        return true;
    });

    runner.AddTest("Logger_LogOverride", []() {
        Logger l;
        l.Initialize();
        l.LogOverride(true, L"I assume full liability");
        l.LogOverride(false);
        l.Flush();
        return true;
    });

    runner.AddTest("Logger_LogPrivilege", []() {
        Logger l;
        l.Initialize();
        l.LogPrivilege(true, L"SE_BACKUP_NAME");
        l.LogPrivilege(false, L"SE_RESTORE_NAME", 1312);
        l.Flush();
        return true;
    });

    runner.AddTest("Logger_LogPPLDetection", []() {
        Logger l;
        l.Initialize();
        l.LogPPLDetection(1234, L"lsass.exe", 4);
        l.Flush();
        return true;
    });

    runner.AddTest("Logger_GetLogFilePath", []() {
        Logger l;
        l.Initialize();
        std::wstring path = l.GetLogFilePath();
        return !path.empty();
    });

    runner.AddTest("Logger_GetRecentEntries", []() {
        Logger l;
        l.Initialize();
        l.LogDeletion(LogEventType::DeletionSuccess, L"test.txt");
        l.Flush();
        auto entries = l.GetRecentEntries(10);
        return !entries.empty();
    });

    runner.AddTest("Logger_LogBlocked", []() {
        Logger l;
        l.Initialize();
        l.LogDeletion(LogEventType::DeletionBlocked, L"C:\\Windows\\System32\\ntoskrnl.exe");
        l.Flush();
        return true;
    });

    runner.AddTest("Logger_LogScheduled", []() {
        Logger l;
        l.Initialize();
        l.LogDeletion(LogEventType::DeletionScheduled, L"locked.dll");
        l.Flush();
        return true;
    });
}
