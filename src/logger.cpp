#include "logger.h"
#include <shlobj.h>
#include <filesystem>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "shell32.lib")

namespace BlackHole {

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &result[0], size, NULL, NULL);
    return result;
}

static std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), NULL, 0);
    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &result[0], size);
    return result;
}

Logger::Logger()
    : m_initialized(false) {
}

Logger::~Logger() {
}

bool Logger::Initialize(const std::wstring& logFilePath) {
    std::lock_guard<std::mutex> lock(m_logMutex);

    if (m_initialized) {
        return true;
    }

    if (logFilePath.empty()) {
        m_logFilePath = GetDefaultLogPath();
    } else {
        m_logFilePath = logFilePath;
    }

    if (!EnsureLogDirectoryExists()) {
        return false;
    }

    m_initialized = true;

    SetFileAttributesW(m_logFilePath.c_str(), FILE_ATTRIBUTE_NORMAL);

    return true;
}

void Logger::LogDeletion(LogEventType eventType, const std::wstring& filePath,
                         const std::wstring& details, DWORD errorCode) {
    if (!m_initialized) return;

    std::lock_guard<std::mutex> lock(m_logMutex);

    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wstring line = FormatTimestamp(st) + L" | " +
                        FormatEventType(eventType) + L" | " +
                        filePath;
    if (!details.empty()) {
        line += L" | " + details;
    }
    if (errorCode != 0) {
        line += L" | Error: " + std::to_wstring(errorCode);
    }

    WriteLogLine(line);
}

void Logger::LogOverride(bool activated, const std::wstring& confirmationText) {
    if (!m_initialized) return;

    std::lock_guard<std::mutex> lock(m_logMutex);

    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wstring eventType = activated ? L"OverrideActivated" : L"OverrideDeactivated";
    std::wstring line = FormatTimestamp(st) + L" | " + eventType;
    if (activated && !confirmationText.empty()) {
        line += L" | Confirmation: " + confirmationText;
    }

    WriteLogLine(line);
}

void Logger::LogPrivilege(bool acquired, const std::wstring& privilegeName,
                          DWORD errorCode) {
    if (!m_initialized) return;

    std::lock_guard<std::mutex> lock(m_logMutex);

    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wstring eventType = acquired ? L"PrivilegeAcquired" : L"PrivilegeFailed";
    std::wstring line = FormatTimestamp(st) + L" | " + eventType +
                        L" | " + privilegeName;
    if (!acquired && errorCode != 0) {
        line += L" | Error: " + std::to_wstring(errorCode);
    }

    WriteLogLine(line);
}

void Logger::LogPPLDetection(DWORD pid, const std::wstring& processName,
                             DWORD protectionLevel) {
    if (!m_initialized) return;

    std::lock_guard<std::mutex> lock(m_logMutex);

    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wstring line = FormatTimestamp(st) + L" | PPLDetected | PID: " +
                        std::to_wstring(pid) + L" | " + processName +
                        L" | Protection Level: " + std::to_wstring(protectionLevel);

    WriteLogLine(line);
}

void Logger::LogUninstall(const std::wstring& programName, bool forceRemoved) {
    if (!m_initialized) return;

    std::lock_guard<std::mutex> lock(m_logMutex);

    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wstring action = forceRemoved ? L"ForceRemoved" : L"Uninstalled";
    std::wstring line = FormatTimestamp(st) + L" | " + action + L" | " + programName;

    WriteLogLine(line);
}

void Logger::Flush() {
    std::lock_guard<std::mutex> lock(m_logMutex);
}

std::wstring Logger::GetLogFilePath() const {
    return m_logFilePath;
}

std::vector<LogEntry> Logger::GetRecentEntries(size_t count) const {
    std::vector<LogEntry> entries;
    if (!m_initialized) return entries;

    std::lock_guard<std::mutex> lock(m_logMutex);

    std::string path8 = WideToUtf8(m_logFilePath);
    std::ifstream readFile(path8);
    if (!readFile.is_open()) return entries;

    std::vector<std::wstring> lines;
    std::string line;
    while (std::getline(readFile, line)) {
        if (!line.empty()) {
            lines.push_back(Utf8ToWide(line));
        }
    }
    readFile.close();

    size_t start = (lines.size() > count) ? (lines.size() - count) : 0;
    for (size_t i = start; i < lines.size(); ++i) {
        LogEntry entry = {};
        entry.details = lines[i];
        entries.push_back(entry);
    }

    return entries;
}

std::wstring Logger::FormatTimestamp(const SYSTEMTIME& st) const {
    std::wstringstream ss;
    ss << std::setfill(L'0')
       << std::setw(4) << st.wYear << L"-"
       << std::setw(2) << st.wMonth << L"-"
       << std::setw(2) << st.wDay << L" "
       << std::setw(2) << st.wHour << L":"
       << std::setw(2) << st.wMinute << L":"
       << std::setw(2) << st.wSecond << L"."
       << std::setw(3) << st.wMilliseconds;
    return ss.str();
}

std::wstring Logger::FormatEventType(LogEventType type) const {
    switch (type) {
        case LogEventType::DeletionSuccess:   return L"Deleted";
        case LogEventType::DeletionFailed:    return L"Failed";
        case LogEventType::DeletionBlocked:   return L"Blocked (Blacklist)";
        case LogEventType::DeletionScheduled: return L"Scheduled (Reboot)";
        case LogEventType::OverrideActivated: return L"Override ON";
        case LogEventType::OverrideDeactivated: return L"Override OFF";
        case LogEventType::PrivilegeAcquired: return L"Privilege OK";
        case LogEventType::PrivilegeFailed:   return L"Privilege FAIL";
        case LogEventType::PPLDetected:       return L"PPL Detected";
        case LogEventType::ProcessTerminated: return L"Process Terminated";
        default: return L"Unknown";
    }
}

void Logger::WriteLogLine(const std::wstring& line) {
    SetFileAttributesW(m_logFilePath.c_str(), FILE_ATTRIBUTE_NORMAL);
    std::string entry8 = WideToUtf8(line) + "\n";
    for (int attempt = 0; attempt < 3; attempt++) {
        HANDLE hFile = CreateFileW(m_logFilePath.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
        if (hFile == INVALID_HANDLE_VALUE) { Sleep(50); continue; }
        SetFilePointer(hFile, 0, NULL, FILE_END);
        DWORD written = 0;
        WriteFile(hFile, entry8.data(), (DWORD)entry8.size(), &written, NULL);
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
        return;
    }
}

std::wstring Logger::GetDefaultLogPath() const {
    PWSTR appDataPath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appDataPath))) {
        std::wstring path(appDataPath);
        CoTaskMemFree(appDataPath);
        path += L"\\BlackHole\\audit.log";
        return path;
    }
    return L"BlackHole_audit.log";
}

bool Logger::EnsureLogDirectoryExists() {
    PWSTR appDataPath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appDataPath))) {
        std::wstring dir(appDataPath);
        CoTaskMemFree(appDataPath);
        dir += L"\\BlackHole";
        return CreateDirectoryW(dir.c_str(), NULL) || ::GetLastError() == ERROR_ALREADY_EXISTS;
    }
    return false;
}

Logger& GetLogger() {
    static Logger instance;
    return instance;
}

}  // namespace BlackHole
