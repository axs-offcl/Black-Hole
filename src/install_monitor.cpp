#include "install_monitor.h"
#include "app_util.h"
#include <process.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <tlhelp32.h>
#include <ShlObj.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <restartmanager.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

extern void PushNotification(const std::wstring& title, const std::wstring& detail, bool isError);

namespace BlackHole {

static const wchar_t* kInstallerNames[] = {
    L"msiexec.exe", L"setup.exe", L"setup32.exe", L"setup64.exe",
    L"inseng.exe", L"stubeng.exe", L"stubinstaller.exe",
    L"light.exe", L"dark.exe",
    L"winget.exe",
    NULL
};

typedef DWORD (WINAPI *pfnRmStartSession)(DWORD*, DWORD, wchar_t*);
typedef DWORD (WINAPI *pfnRmRegisterResources)(DWORD, UINT, const wchar_t**, UINT, RM_UNIQUE_PROCESS*, UINT, wchar_t**);
typedef DWORD (WINAPI *pfnRmGetList)(DWORD, UINT*, UINT*, RM_PROCESS_INFO*, LPDWORD);
typedef DWORD (WINAPI *pfnRmEndSession)(DWORD);

static HMODULE g_hRstrtmgr = nullptr;
static pfnRmStartSession fnRmStartSession = nullptr;
static pfnRmRegisterResources fnRmRegisterResources = nullptr;
static pfnRmGetList fnRmGetList = nullptr;
static pfnRmEndSession fnRmEndSession = nullptr;
static std::once_flag g_rmInitFlag;

static void LoadRestartManager() {
    std::call_once(g_rmInitFlag, []() {
        g_hRstrtmgr = LoadLibraryW(L"rstrtmgr.dll");
        if (g_hRstrtmgr) {
            fnRmStartSession = (pfnRmStartSession)GetProcAddress(g_hRstrtmgr, "RmStartSession");
            fnRmRegisterResources = (pfnRmRegisterResources)GetProcAddress(g_hRstrtmgr, "RmRegisterResources");
            fnRmGetList = (pfnRmGetList)GetProcAddress(g_hRstrtmgr, "RmGetList");
            fnRmEndSession = (pfnRmEndSession)GetProcAddress(g_hRstrtmgr, "RmEndSession");
        }
    });
}

static std::wstring GetExePathForPid(DWORD pid) {
    std::wstring path;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        wchar_t buf[MAX_PATH] = {};
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, buf, &sz)) {
            path = buf;
        }
        CloseHandle(hProc);
    }
    return path;
}

static std::wstring GetProcessNameForPid(DWORD pid) {
    std::wstring name;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    name = pe.szExeFile;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return name;
}

InstallMonitor::InstallMonitor() {}

InstallMonitor::~InstallMonitor() {
    StopMonitoring();
}

bool InstallMonitor::StartMonitoring() {
    if (m_running.load()) return true;

    LoadRestartManager();

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) {
        m_comInitialized = true;
    }

    if (m_comInitialized) {
        CoInitializeSecurity(NULL, -1, NULL, NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL, EOAC_NONE, NULL);
    }

    m_running.store(true);
    m_threadHandle = (HANDLE)_beginthreadex(NULL, 0,
        [](void* param) -> unsigned {
            return ((InstallMonitor*)param)->MonitorThread();
        }, this, 0, NULL);

    if (!m_threadHandle) {
        m_running.store(false);
        return false;
    }

    OutputDebugStringA("InstallMonitor: Started\n");
    return true;
}

void InstallMonitor::StopMonitoring() {
    if (!m_running.load()) return;

    m_running.store(false);

    if (m_threadHandle) {
        WaitForSingleObject(m_threadHandle, 5000);
        CloseHandle(m_threadHandle);
        m_threadHandle = NULL;
    }

    if (m_wmiServices) {
        ((IWbemServices*)m_wmiServices)->Release();
        m_wmiServices = nullptr;
    }
    if (m_wmiLocator) {
        ((IWbemLocator*)m_wmiLocator)->Release();
        m_wmiLocator = nullptr;
    }
    if (m_comInitialized) {
        CoUninitialize();
        m_comInitialized = false;
    }

    OutputDebugStringA("InstallMonitor: Stopped\n");
}

unsigned __stdcall InstallMonitor::MonitorThread() {
    std::vector<DWORD> knownInstallerPids;
    std::vector<DWORD> trackedPids;

    while (m_running.load()) {
        {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = {};
                pe.dwSize = sizeof(pe);
                if (Process32FirstW(hSnap, &pe)) {
                    do {
                        std::wstring exeName = pe.szExeFile;
                        for (const wchar_t** p = kInstallerNames; *p; p++) {
                            if (_wcsicmp(exeName.c_str(), *p) == 0) {
                                bool alreadyKnown = false;
                                for (DWORD kpid : knownInstallerPids) {
                                    if (kpid == pe.th32ProcessID) { alreadyKnown = true; break; }
                                }
                                if (!alreadyKnown) {
                                    knownInstallerPids.push_back(pe.th32ProcessID);
                                    OnProcessCreated(pe.th32ParentProcessID, pe.th32ProcessID, exeName);
                                    trackedPids.push_back(pe.th32ProcessID);
                                    OutputDebugStringA("InstallMonitor: Installer detected\n");
                                }
                                break;
                            }
                        }
                    } while (Process32NextW(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
        }

        {
            std::lock_guard<std::mutex> lock(m_sessionMutex);
            for (auto& session : m_sessions) {
                if (!session.active) continue;

                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, session.processId);
                if (!hProc) {
                    session.active = false;
                    continue;
                }
                DWORD exitCode = 0;
                if (GetExitCodeProcess(hProc, &exitCode) && exitCode != STILL_ACTIVE) {
                    session.active = false;
                }
                CloseHandle(hProc);
            }
        }

        std::vector<DWORD> deadPids;
        for (DWORD pid : trackedPids) {
            bool found = false;
            {
                std::lock_guard<std::mutex> lock(m_sessionMutex);
                for (auto& s : m_sessions) {
                    if (s.processId == pid && s.active) { found = true; break; }
                }
            }
            if (!found) {
                StopTrackingSession(pid);
                deadPids.push_back(pid);
            }
        }
        for (DWORD dpid : deadPids) {
            knownInstallerPids.erase(
                std::remove(knownInstallerPids.begin(), knownInstallerPids.end(), dpid),
                knownInstallerPids.end());
            trackedPids.erase(
                std::remove(trackedPids.begin(), trackedPids.end(), dpid),
                trackedPids.end());
        }

        Sleep(2000);
    }

    return 0;
}

bool InstallMonitor::IsInstallerProcess(const std::wstring& name) const {
    for (const wchar_t** p = kInstallerNames; *p; p++) {
        if (_wcsicmp(name.c_str(), *p) == 0) return true;
    }
    return false;
}

bool InstallMonitor::IsInstallerProcess(DWORD pid) const {
    std::wstring name = GetProcessNameForPid(pid);
    return IsInstallerProcess(name);
}

void InstallMonitor::OnProcessCreated(DWORD parentPid, DWORD childPid, const std::wstring& processName) {
    OutputDebugStringA("InstallMonitor: Process created, tracking\n");
    StartTrackingSession(childPid, processName, parentPid);
    TrackProcessTree(childPid);
}

void InstallMonitor::TrackProcessTree(DWORD rootPid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ParentProcessID == rootPid) {
                std::wstring childName = pe.szExeFile;
                bool alreadyTracked = false;
                {
                    std::lock_guard<std::mutex> lock(m_sessionMutex);
                    for (auto& s : m_sessions) {
                        if (s.processId == pe.th32ProcessID) { alreadyTracked = true; break; }
                    }
                }
                if (!alreadyTracked) {
                    StartTrackingSession(pe.th32ProcessID, childName, rootPid);
                    TrackProcessTree(pe.th32ProcessID);
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

void InstallMonitor::StartTrackingSession(DWORD pid, const std::wstring& name, DWORD parentPid) {
    LoadRestartManager();

    InstallSession session;
    session.processId = pid;
    session.parentPid = parentPid;
    session.processName = name;
    session.active = true;
    GetSystemTimeAsFileTime(&session.startTime);

    if (fnRmStartSession && fnRmRegisterResources && fnRmEndSession) {
        DWORD sessionId = 0;
        wchar_t sessionKey[CCH_RM_SESSION_KEY + 1] = {};
        DWORD rmResult = fnRmStartSession(&sessionId, 0, sessionKey);
        if (rmResult == ERROR_SUCCESS) {
            RM_UNIQUE_PROCESS procInfo = {};
            procInfo.dwProcessId = pid;
            GetSystemTimeAsFileTime(&procInfo.ProcessStartTime);

            fnRmRegisterResources(sessionId, 0, NULL, 1, &procInfo, 0, NULL);
            fnRmEndSession(sessionId);
        }
    }

    std::lock_guard<std::mutex> lock(m_sessionMutex);
    m_sessions.push_back(session);

    std::wstring notifTitle = L"Installation Detected";
    std::wstring notifDetail = L"Tracking: " + name;
    PushNotification(notifTitle, notifDetail, false);

    OutputDebugStringA("InstallMonitor: Session started\n");
}

void InstallMonitor::OnProcessTerminated(DWORD pid) {
    StopTrackingSession(pid);
}

void InstallMonitor::StopTrackingSession(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    for (auto& session : m_sessions) {
        if (session.processId == pid && session.active) {
            session.active = false;
            OutputDebugStringA("InstallMonitor: Session ended\n");

            if (!session.files.empty() || !session.registry.empty()) {
                SaveSessionLog(session);
            }
            break;
        }
    }
}

std::vector<InstallSession> InstallMonitor::GetSessions() const {
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    return m_sessions;
}

void InstallMonitor::ClearSessions() {
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    m_sessions.clear();
}

static std::wstring GetInstallLogsDir() {
    wchar_t appData[MAX_PATH] = {};
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData);
    std::wstring dir = std::wstring(appData) + L"\\BlackHole\\InstallLogs";
    std::filesystem::create_directories(dir);
    return dir;
}

static std::wstring FileTimeToString(const FILETIME& ft) {
    SYSTEMTIME st = {};
    FileTimeToSystemTime(&ft, &st);
    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

bool InstallMonitor::SaveSessionLog(const InstallSession& session) const {
    std::wstring dir = GetInstallLogsDir();

    SYSTEMTIME st = {};
    FileTimeToSystemTime(&session.startTime, &st);

    wchar_t filename[128];
    swprintf_s(filename, L"install_%04d%02d%02d_%02d%02d%02d_%ls.json",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        session.processName.c_str());

    for (wchar_t* p = filename; *p; p++) {
        if (*p == L' ' || *p == L':' || *p == L'/' || *p == L'\\') *p = L'_';
    }

    std::wstring fullPath = dir + L"\\" + filename;

    std::ofstream ofs(fullPath, std::ios::binary);
    if (!ofs.is_open()) return false;

    ofs << "{\n";
    ofs << "  \"process\": \"" << WideToUtf8(session.processName) << "\",\n";
    ofs << "  \"pid\": " << session.processId << ",\n";
    ofs << "  \"parentPid\": " << session.parentPid << ",\n";
    ofs << "  \"startTime\": \"" << WideToUtf8(FileTimeToString(session.startTime)) << "\",\n";

    ofs << "  \"files\": [\n";
    for (size_t i = 0; i < session.files.size(); i++) {
        ofs << "    {\"path\": \"" << WideToUtf8(session.files[i].path)
            << "\", \"action\": " << session.files[i].action << "}";
        if (i + 1 < session.files.size()) ofs << ",";
        ofs << "\n";
    }
    ofs << "  ],\n";

    ofs << "  \"registry\": [\n";
    for (size_t i = 0; i < session.registry.size(); i++) {
        ofs << "    {\"key\": \"" << WideToUtf8(session.registry[i].keyPath)
            << "\", \"value\": \"" << WideToUtf8(session.registry[i].valueName)
            << "\", \"action\": " << session.registry[i].action << "}";
        if (i + 1 < session.registry.size()) ofs << ",";
        ofs << "\n";
    }
    ofs << "  ]\n";

    ofs << "}\n";
    ofs.close();

    OutputDebugStringA("InstallMonitor: Session log saved\n");
    return true;
}

std::vector<std::wstring> InstallMonitor::GetSavedLogs() const {
    std::vector<std::wstring> logs;
    std::wstring dir = GetInstallLogsDir();

    for (auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().extension() == L".json") {
            logs.push_back(entry.path().wstring());
        }
    }
    return logs;
}

bool InstallMonitor::DeleteSavedLog(const std::wstring& filename) const {
    return std::filesystem::remove(filename);
}

InstallMonitor& GetInstallMonitor() {
    static InstallMonitor instance;
    return instance;
}

} // namespace BlackHole
