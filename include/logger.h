#ifndef BLACKHOLE_LOGGER_H
#define BLACKHOLE_LOGGER_H

#include <Windows.h>
#include <string>
#include <fstream>
#include <mutex>
#include <vector>

namespace BlackHole {

// Log event types
enum class LogEventType {
    DeletionSuccess,      // File successfully deleted
    DeletionFailed,       // Deletion attempt failed
    DeletionBlocked,      // File blocked by blacklist
    DeletionScheduled,    // File queued for reboot deletion
    OverrideActivated,    // Blacklist override was activated
    OverrideDeactivated,  // Blacklist override was deactivated
    PrivilegeAcquired,    // Required privilege was acquired
    PrivilegeFailed,      // Failed to acquire privilege
    PPLDetected,          // Protected Process Light detected
    ProcessTerminated     // Process was terminated
};

// Log entry structure
struct LogEntry {
    SYSTEMTIME timestamp;
    LogEventType eventType;
    std::wstring filePath;
    std::wstring details;
    DWORD errorCode;  // Win32 error code (0 if not applicable)
};

class Logger {
public:
    Logger();
    ~Logger();

    // Non-copyable
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // Initialize logger with log file path
    // Default: %APPDATA%\BlackHole\audit.log
    bool Initialize(const std::wstring& logFilePath = L"");

    // Log a deletion event
    void LogDeletion(LogEventType eventType, const std::wstring& filePath,
                     const std::wstring& details = L"", DWORD errorCode = 0);

    // Log an override event
    void LogOverride(bool activated, const std::wstring& confirmationText = L"");

    // Log a privilege event
    void LogPrivilege(bool acquired, const std::wstring& privilegeName,
                      DWORD errorCode = 0);

    // Log a PPL detection event
    void LogPPLDetection(DWORD pid, const std::wstring& processName,
                         DWORD protectionLevel);

    // Log an uninstall event
    void LogUninstall(const std::wstring& programName, bool forceRemoved);

    // Flush log to disk
    void Flush();

    // Get log file path
    std::wstring GetLogFilePath() const;

    // Read recent log entries (for GUI display)
    std::vector<LogEntry> GetRecentEntries(size_t count = 100) const;

private:
    // Format timestamp as ISO 8601 string
    std::wstring FormatTimestamp(const SYSTEMTIME& st) const;

    // Format log event type as string
    std::wstring FormatEventType(LogEventType type) const;

    // Write a raw log line
    void WriteLogLine(const std::wstring& line);

    // Get default log file path
    std::wstring GetDefaultLogPath() const;

    // Ensure log directory exists
    bool EnsureLogDirectoryExists();

    std::wstring m_logFilePath;
    mutable std::mutex m_logMutex;
    bool m_initialized;
};

// Global logger instance (singleton)
Logger& GetLogger();

}  // namespace BlackHole

#endif  // BLACKHOLE_LOGGER_H
