#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>

namespace BlackHole {

struct MonitoredFile {
    std::wstring path;
    DWORD action; // 0=added, 1=modified, 2=removed
    FILETIME timestamp;
};

struct MonitoredRegistry {
    std::wstring keyPath;
    std::wstring valueName;
    DWORD action;
    FILETIME timestamp;
};

struct InstallSession {
    DWORD processId;
    DWORD parentPid;
    std::wstring processName;
    std::wstring commandLine;
    FILETIME startTime;
    std::vector<MonitoredFile> files;
    std::vector<MonitoredRegistry> registry;
    bool active;
};

class InstallMonitor {
public:
    InstallMonitor();
    ~InstallMonitor();

    bool StartMonitoring();
    void StopMonitoring();
    bool IsRunning() const { return m_running.load(); }

    std::vector<InstallSession> GetSessions() const;
    void ClearSessions();

    bool SaveSessionLog(const InstallSession& session) const;
    std::vector<std::wstring> GetSavedLogs() const;
    bool DeleteSavedLog(const std::wstring& filename) const;

private:
    unsigned __stdcall MonitorThread();
    void OnProcessCreated(DWORD parentPid, DWORD childPid, const std::wstring& processName);
    void OnProcessTerminated(DWORD pid);
    void TrackProcessTree(DWORD pid);
    bool IsInstallerProcess(const std::wstring& name) const;
    bool IsInstallerProcess(DWORD pid) const;
    void StartTrackingSession(DWORD pid, const std::wstring& name, DWORD parentPid);
    void StopTrackingSession(DWORD pid);

    std::atomic<bool> m_running{false};
    HANDLE m_threadHandle = NULL;
    mutable std::mutex m_sessionMutex;
    std::vector<InstallSession> m_sessions;

    HANDLE m_wmiEventHandle = NULL;
    void* m_wmiServices = nullptr;
    void* m_wmiLocator = nullptr;
    bool m_comInitialized = false;
};

InstallMonitor& GetInstallMonitor();

} // namespace BlackHole
