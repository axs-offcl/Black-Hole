#include "uninstaller.h"
#include "deletor.h"
#include "privilege.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Shlobj.h>
#include <shellapi.h>
#include <GdiPlus.h>
#include <wincrypt.h>
#include <msi.h>
#include <filesystem>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <chrono>
#include <fstream>
#include <atomic>
#include <process.h>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "msi.lib")

// ── Diagnostic timing helpers ─────────────────────────────────────────
static LARGE_INTEGER g_perfFreq = {};
static bool g_perfFreqInit = false;
static void EnsurePerfFreq() {
    if (!g_perfFreqInit) { QueryPerformanceFrequency(&g_perfFreq); g_perfFreqInit = true; }
}
static double NowMs() {
    EnsurePerfFreq();
    LARGE_INTEGER li; QueryPerformanceCounter(&li);
    return (double)li.QuadPart * 1000.0 / (double)g_perfFreq.QuadPart;
}

#define BH_TIMER_START(var) double var = NowMs()
#define BH_TIMER_RESTART(var) (var) = NowMs()
#define BH_TIMER_END_MS(var, label) do { \
    double _end = NowMs(); \
    char _buf[256]; \
    snprintf(_buf, sizeof(_buf), "TIMING: %s took %.3f ms\n", label, _end - (var)); \
    OutputDebugStringA(_buf); \
} while(0)

// ── Blocked-item trace ──────────────────────────────────────────────
#define BH_TRACE_BLOCKED(what, reason, name) do { \
    char _b[512]; \
    snprintf(_b, sizeof(_b), "BLOCKED: %s filtered [%ls] reason=%s\n", what, (name), reason); \
    OutputDebugStringA(_b); \
} while(0)

// ── Registry handle leak tracking ───────────────────────────────────
static std::atomic<int> g_regOpenCount(0);
static std::atomic<int> g_regCloseCount(0);

#define BH_REG_OPEN(h, root, sub) do { \
    g_regOpenCount++; \
    char _b[512]; \
    snprintf(_b, sizeof(_b), "REG_OPEN: hKey=%p root=%ls sub=%ls (open=%d close=%d)\n", \
             (void*)(h), (root == HKEY_CURRENT_USER ? L"HKCU" : \
             (root == HKEY_LOCAL_MACHINE ? L"HKLM" : \
             (root == HKEY_CLASSES_ROOT ? L"HKCR" : L"???"))), \
             (sub), g_regOpenCount.load(), g_regCloseCount.load()); \
    OutputDebugStringA(_b); \
} while(0)

#define BH_REG_CLOSE(h) do { \
    g_regCloseCount++; \
    char _b[128]; \
    snprintf(_b, sizeof(_b), "REG_CLOSE: hKey=%p (open=%d close=%d leaked=%d)\n", \
             (void*)(h), g_regOpenCount.load(), g_regCloseCount.load(), \
             g_regOpenCount.load() - g_regCloseCount.load()); \
    OutputDebugStringA(_b); \
} while(0)

static void ScanLog(const char* msg) {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring path = std::wstring(tempPath) + L"BlackHole_crash.log";
    std::ofstream f(path, std::ios::app);
    if (f.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buf[256];
        snprintf(buf, sizeof(buf), "[%02d:%02d:%02d.%03d] %s\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
        f << buf;
    }
}

namespace BlackHole {

static const wchar_t* s_protectedPaths[] = {
    L"C:\\Windows",
    L"C:\\Windows\\System32",
    L"C:\\Windows\\SysWOW64",
    L"C:\\Windows\\WinSxS",
    L"C:\\Windows\\Boot",
    L"C:\\Windows\\Fonts",
    L"C:\\Windows\\Globalization",
    L"C:\\Windows\\IME",
    L"C:\\Windows\\rescache",
    L"C:\\Windows\\Resources",
    L"C:\\Windows\\servicing",
    L"C:\\Windows\\SystemResources",
    L"C:\\Windows\\Windows Defender",
    L"C:\\Windows\\Windows Security",
    L"C:\\Windows\\Recovery",
    L"C:\\Windows\\$Recycle.Bin",
    L"C:\\Program Files\\Common Files\\microsoft shared",
    L"C:\\Program Files (x86)\\Common Files\\microsoft shared",
    L"C:\\ProgramData\\Microsoft",
    L"C:\\ProgramData\\Package Cache",
    L"C:\\Recovery",
    NULL
};

static const wchar_t* s_protectedRegistryKeys[] = {
    L"HKLM\\SYSTEM\\CurrentControlSet\\Control",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Enum",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Hardware Profiles",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Component Based Servicing",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Setup",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Windows NT\\CurrentVersion",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Cryptography",
    L"HKLM\\SYSTEM\\CurrentControlSet\\Policies",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication",
    L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"HKLM\\SOFTWARE\\Classes",
    L"HKLM\\BCD00000000",
    L"HKLM\\SAM",
    L"HKLM\\SECURITY",
    L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
    L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
    NULL
};

static const wchar_t* s_stopWords[] = {
    L"tool", L"tools", L"free", L"pro", L"manager", L"editor",
    L"viewer", L"player", L"launcher", L"helper", L"service",
    L"update", L"updater", L"setup", L"install", L"runtime",
    L"redist", L"component", L"module", L"plugin", L"extension",
    L"driver", L"driver package", L"framework", L"sdk", L"debug",
    L"redistributable", L"c++", L"visual c", L"dotnet",
    L".net", L"java", L"oracle", L"microsoft corporation",
    L"intel", L"nvidia", L"amd", L"qualcomm", L"realtek",
    L"synaptics", L"broadcom", L"standard", L"system",
    L"generic", L"shared", L"common", L"library",
    NULL
};

static const wchar_t* s_protectedServices[] = {
    L"wuauserv", L"bits", L"Winmgmt", L"EventLog", L"PlugPlay",
    L"RpcSs", L"DcomLaunch", L"SamSs", L"lanmanworkstation",
    L"lanmanserver", L"RpcEptMapper", L"nsi", L"mpsdrv",
    L"MpsSvc", L"WdiServiceHost", L"WdiSystemHost", L"SysMain",
    L"Schedule", L"SessionEnv", L"TermService", L"UmRdpService",
    L"spoolsv", L"Fax", L"RemoteRegistry", L"WSearch",
    L"SecurityHealthService", L"WdNisSvc", L"WinDefend",
    L"Sense", L"MPSSVC", L"BthServ", L"Audiosrv",
    L"AudioEndpointBuilder", L"TabletInputService", L"PrintNotify",
    L"StorSvc", L"iphlpsvc", L"dot3svc", L"WlanSvc",
    NULL
};

Uninstaller::Uninstaller() {}

LeftoverConfidence Uninstaller::TestScoreConfidence(const std::wstring& cand, const std::wstring& kw,
                                                     const std::wstring& pub, const std::wstring& inst,
                                                     bool isReg, int depth) {
    int rawScore = 0;
    LeftoverConfidence conf = ScoreConfidence(cand, kw, pub, inst, isReg, depth, rawScore);
    char dbg[1024];
    snprintf(dbg, sizeof(dbg), "TEST_SCORE: cand=[%ls] kw=[%ls] pub=[%ls] inst=[%ls] reg=%d depth=%d → score=%d result=%d\n",
             cand.c_str(), kw.c_str(), pub.c_str(), inst.c_str(), isReg ? 1 : 0, depth, rawScore, (int)conf);
    OutputDebugStringA(dbg);
    return conf;
}

int Sift4Distance(const std::wstring& s1, const std::wstring& s2, int maxOffset) {
    if (s1.empty()) return (int)s2.length();
    if (s2.empty()) return (int)s1.length();

    int l1 = (int)s1.length(), l2 = (int)s2.length();
    int c1 = 0, c2 = 0, lcss = 0, local_cs = 0, local_ce = 0;
    int p1[2] = {0, 0}, p2[2] = {0, 0};
    std::vector<int> vett(maxOffset * 2 + 2, 0);

    for (int i = 0; i < l1; i++) {
        int jStart = (std::max)(0, i - maxOffset);
        int jEnd = (std::min)(l2, i + maxOffset + 1);
        for (int j = jStart; j < jEnd; j++) {
            if (s1[i] == s2[j]) {
                int k = (i == 0 || j == 0) ? 0 : vett[maxOffset + j - i + 1];
                int ce = i - k;
                int cs = j - k;
                if (p1[1] == cs && p2[1] == ce) {
                    local_cs++;
                    local_ce = i + 1;
                } else {
                    local_cs = 1;
                    local_ce = i + 1;
                    p1[1] = cs;
                    p2[1] = ce;
                }
                vett[maxOffset + j - i + 1] = j + 1;
                if (local_cs > lcss) {
                    lcss = local_cs;
                    c1 = local_ce;
                }
            }
        }
        if (i == 0) {
            for (int j = 0; j < maxOffset + 1; j++) vett[j] = 0;
        }
    }
    return l1 + l2 - 2 * lcss;
}

std::wstring Uninstaller::NormalizeName(const std::wstring& name) {
    std::wstring result = name;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i] == L'_' || result[i] == L'-') result[i] = L' ';
    }
    while (!result.empty() && result.back() == L' ') result.pop_back();
    while (!result.empty() && result.front() == L' ') result.erase(result.begin());
    return result;
}

bool Uninstaller::IsExecutableMatch(const std::wstring& fileName, const UninstallEntry& entry) {
    std::wstring fnLower = fileName;
    std::transform(fnLower.begin(), fnLower.end(), fnLower.begin(), ::towlower);
    for (auto& exe : entry.sortedExecutables) {
        if (fnLower == exe) return true;
        if (fnLower.find(exe) != std::wstring::npos) return true;
    }
    return false;
}

std::wstring Uninstaller::ReadRegString(HKEY hKey, const std::wstring& name) {
    wchar_t buf[4096];
    DWORD bufSize = sizeof(buf);
    DWORD type = 0;
    if (RegQueryValueExW(hKey, name.c_str(), NULL, &type, (LPBYTE)buf, &bufSize) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        if (type == REG_EXPAND_SZ) {
            wchar_t expanded[4096];
            DWORD expLen = ExpandEnvironmentStringsW(buf, expanded, 4096);
            if (expLen > 0 && expLen < 4096) return std::wstring(expanded);
        }
        return std::wstring(buf);
    }
    return L"";
}

DWORD Uninstaller::ReadRegDword(HKEY hKey, const std::wstring& name) {
    DWORD val = 0;
    DWORD size = sizeof(DWORD);
    DWORD type = 0;
    if (RegQueryValueExW(hKey, name.c_str(), NULL, &type, (LPBYTE)&val, &size) == ERROR_SUCCESS &&
        type == REG_DWORD) {
        return val;
    }
    return 0;
}

bool Uninstaller::IsProtectedPath(const std::wstring& path) {
    std::wstring pathLower = path;
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
    for (int i = 0; s_protectedPaths[i] != NULL; i++) {
        std::wstring protLower = s_protectedPaths[i];
        std::transform(protLower.begin(), protLower.end(), protLower.begin(), ::towlower);
        if (pathLower == protLower || pathLower.find(protLower + L"\\") == 0) {
            return true;
        }
    }
    return false;
}

bool Uninstaller::IsProtectedRegistryKey(const std::wstring& regPath) {
    std::wstring regLower = regPath;
    std::transform(regLower.begin(), regLower.end(), regLower.begin(), ::towlower);
    for (int i = 0; s_protectedRegistryKeys[i] != NULL; i++) {
        std::wstring protLower = s_protectedRegistryKeys[i];
        std::transform(protLower.begin(), protLower.end(), protLower.begin(), ::towlower);
        if (regLower == protLower || regLower.find(protLower + L"\\") == 0) {
            return true;
        }
    }
    return false;
}

bool Uninstaller::IsStopWord(const std::wstring& word) {
    std::wstring wordLower = word;
    std::transform(wordLower.begin(), wordLower.end(), wordLower.begin(), ::towlower);
    for (int i = 0; s_stopWords[i] != NULL; i++) {
        if (wordLower.find(s_stopWords[i]) != std::wstring::npos) {
            return true;
        }
    }
    if (wordLower.size() <= 3) return true;
    return false;
}

bool Uninstaller::IsUsedByOtherApp(const std::wstring& path,
                                   const std::vector<UninstallEntry>& allApps,
                                   const std::wstring& currentName) {
    std::wstring pathLower = path;
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
    for (auto& app : allApps) {
        if (app.displayName == currentName) continue;
        if (!app.installPath.empty()) {
            std::wstring appPathLower = app.installPath;
            std::transform(appPathLower.begin(), appPathLower.end(), appPathLower.begin(), ::towlower);
            if (pathLower == appPathLower || pathLower.find(appPathLower + L"\\") == 0) {
                return true;
            }
        }
    }
    return false;
}

    LeftoverConfidence Uninstaller::ScoreConfidence(const std::wstring& candidateName,
                                                 const std::wstring& keyword,
                                                 const std::wstring& publisher,
                                                 const std::wstring& installPath,
                                                 bool isRegistry, int depth,
                                                 int& outRawScore) {
    int score = 0;

    std::wstring candNorm = NormalizeName(candidateName);
    std::wstring kwNorm = NormalizeName(keyword);
    std::wstring pubNorm = NormalizeName(publisher);
    std::wstring kwOrigLower = keyword;
    std::transform(kwOrigLower.begin(), kwOrigLower.end(), kwOrigLower.begin(), ::towlower);

    if (candNorm == kwNorm) {
        score += 8;
    } else if (candNorm.find(kwNorm) != std::wstring::npos) {
        score += 6;
    } else if (!kwNorm.empty() && kwNorm.find(candNorm) == 0) {
        score += 7;
    } else if (kwNorm.find(candNorm) != std::wstring::npos) {
        score += 6;
    } else {
        if (!kwOrigLower.empty() && candNorm.find(kwOrigLower) != std::wstring::npos) {
            score += 6;
        } else if (!kwOrigLower.empty() && kwOrigLower.find(candNorm) == 0) {
            score += 6;
        } else if (!kwOrigLower.empty() && kwOrigLower.find(candNorm) != std::wstring::npos) {
            score += 5;
        } else {
            int siftDist = Sift4Distance(candNorm, kwNorm);
            int candLen = (int)candNorm.size();
            int kwLen = (int)kwNorm.size();
            int minLen = (candLen < kwLen) ? candLen : kwLen;
            if (minLen > 4 && siftDist <= minLen / 3) {
                score += 3;
            } else if (minLen > 4 && siftDist <= minLen / 2) {
                score += 1;
            } else {
                score -= 2;
            }
        }
    }

    if (!installPath.empty()) {
        std::wstring instLower = installPath;
        std::transform(instLower.begin(), instLower.end(), instLower.begin(), ::towlower);
        if (!kwNorm.empty() && instLower.find(kwNorm) != std::wstring::npos) score += 6;
        if (!kwOrigLower.empty() && instLower.find(kwOrigLower) != std::wstring::npos) score += 6;
        if (instLower.find(candNorm) != std::wstring::npos) score += 4;
        if (candNorm.find(instLower) != std::wstring::npos) score += 3;

        if (!pubNorm.empty() && pubNorm.size() > 2 && instLower.find(pubNorm) != std::wstring::npos) {
            score += 4;
        }

        std::wstring parentDir = instLower;
        size_t lastSlash = parentDir.find_last_of(L'\\');
        if (lastSlash != std::wstring::npos) {
            parentDir = parentDir.substr(0, lastSlash);
            if (!kwNorm.empty() && parentDir.find(kwNorm) != std::wstring::npos) score += 2;
            if (!kwOrigLower.empty() && parentDir.find(kwOrigLower) != std::wstring::npos) score += 2;
        }
    }

    if (!pubNorm.empty()) {
        if (candNorm.find(pubNorm) != std::wstring::npos) score += 3;
        if (kwNorm.find(pubNorm) == std::wstring::npos && candNorm.find(pubNorm) == std::wstring::npos) {
            score -= 2;
        }
        if (candNorm == pubNorm && candNorm != kwNorm &&
            kwNorm.find(candNorm) == std::wstring::npos) {
            score -= 3;
        }
    }

    if (isRegistry) {
        if (candNorm.find(L"uninstall") != std::wstring::npos) score += 2;
        if (candNorm.find(L"classes") != std::wstring::npos) score -= 6;
        if (candNorm.find(L"wow6432node") != std::wstring::npos) score -= 2;
        if (candNorm.find(L"installer") != std::wstring::npos) score += 2;
        if (candNorm.find(L"client") != std::wstring::npos) score += 1;
        if (candNorm.find(kwNorm) != std::wstring::npos) score += 6;
        if (!kwNorm.empty() && kwNorm.find(candNorm) == 0) score += 3;
    }

    if (!m_cachedApps.empty()) {
        bool usedByOther = false;
        bool publisherStillUsed = false;
        bool similarNameUsed = false;
        bool isStoreApp = false;
        for (auto& app : m_cachedApps) {
            if (app.displayName == keyword) continue;
            std::wstring appInstallLower = app.installPath;
            std::transform(appInstallLower.begin(), appInstallLower.end(),
                           appInstallLower.begin(), ::towlower);
            if (!appInstallLower.empty() &&
                (appInstallLower == candNorm || appInstallLower.find(candNorm + L"\\") == 0)) {
                usedByOther = true;
                break;
            }
            if (!publisher.empty() && !app.publisher.empty() && app.publisher != publisher) {
                std::wstring appPubLower = NormalizeName(app.publisher);
                if (appPubLower == pubNorm) {
                    publisherStillUsed = true;
                }
            }
            if (app.isSystemComponent) {
                std::wstring appPathLower = app.installPath;
                std::transform(appPathLower.begin(), appPathLower.end(),
                               appPathLower.begin(), ::towlower);
                if (!appPathLower.empty() && appPathLower.find(candNorm) != std::wstring::npos) {
                    isStoreApp = true;
                }
            }
            std::wstring otherNorm = NormalizeName(app.displayName);
            int nameDist = Sift4Distance(candNorm, otherNorm);
            int candLen2 = (int)candNorm.size();
            int otherLen = (int)otherNorm.size();
            int minLen2 = (candLen2 < otherLen) ? candLen2 : otherLen;
            if (minLen2 > 4 && nameDist <= minLen2 / 3 && otherNorm != kwNorm) {
                similarNameUsed = true;
            }
        }
        if (usedByOther) score -= 7;
        if (publisherStillUsed) score -= 4;
        if (similarNameUsed) score -= 2;
        if (isStoreApp) score -= 10;
    }

    score -= depth * 2;

    if (IsStopWord(candidateName)) score -= 4;

    static const wchar_t* genericNames[] = {
        L"install", L"settings", L"config", L"data", L"users",
        L"common", L"shared", L"cache", L"temp", L"tmp", NULL
    };
    for (int i = 0; genericNames[i]; i++) {
        if (candNorm == genericNames[i]) {
            score -= 3;
            break;
        }
    }

    outRawScore = score;
    LeftoverConfidence result;
    if (score >= 8) result = LeftoverConfidence::Safe;
    else if (score >= 4) result = LeftoverConfidence::Moderate;
    else result = LeftoverConfidence::Risky;
    {
        char dbg[1024];
        snprintf(dbg, sizeof(dbg), "ScoreConfidence: cand=[%ls] kw=[%ls] pub=[%ls] inst=[%ls] reg=%d candNorm=[%ls] kwNorm=[%ls] pubNorm=[%ls] score=%d result=%d\n",
                 candidateName.c_str(), keyword.c_str(), publisher.c_str(), installPath.c_str(),
                 isRegistry ? 1 : 0, candNorm.c_str(), kwNorm.c_str(), pubNorm.c_str(),
                 score, (int)result);
        OutputDebugStringA(dbg);
    }
    return result;
}

InstallerType Uninstaller::DetectInstallerType(const std::wstring& uninstallString,
                                                 HKEY rootKey, const std::wstring& regPath) {
    if (uninstallString.empty()) return InstallerType::Unknown;

    std::wstring cmdLower = uninstallString;
    std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::towlower);

    if (cmdLower.find(L"msiexec") != std::wstring::npos) return InstallerType::Msi;
    if (cmdLower.find(L"powershell") != std::wstring::npos ||
        cmdLower.find(L".ps1") != std::wstring::npos) return InstallerType::PowerShell;
    if (cmdLower.find(L"sdbinst") != std::wstring::npos) return InstallerType::SdbInst;

    size_t uninsPos = cmdLower.find(L"unins");
    if (uninsPos != std::wstring::npos) {
        size_t digitStart = uninsPos + 5;
        if (digitStart < cmdLower.size() && iswdigit(cmdLower[digitStart])) {
            size_t digitEnd = digitStart;
            while (digitEnd < cmdLower.size() && iswdigit(cmdLower[digitEnd])) digitEnd++;
            if (digitEnd - digitStart == 3) {
                std::wstring exeName = cmdLower.substr(digitStart - 5, digitEnd - digitStart + 9);
                if (exeName.find(L".exe") != std::wstring::npos) {
                    std::wstring dir = cmdLower.substr(0, cmdLower.find_last_of(L'\\'));
                    std::wstring datFile = dir + L"\\unins000.dat";
                    DWORD attr = GetFileAttributesW(datFile.c_str());
                    if (attr != INVALID_FILE_ATTRIBUTES) return InstallerType::InnoSetup;
                }
            }
        }
    }

    if (cmdLower.find(L"inno") != std::wstring::npos) return InstallerType::InnoSetup;

    HKEY hKey;
    if (RegOpenKeyExW(rootKey, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD type = 0;
        DWORD size = 0;
        if (RegQueryValueExW(hKey, L"WindowsInstaller", NULL, &type, NULL, &size) == ERROR_SUCCESS &&
            type == REG_DWORD) {
            DWORD val = 0;
            size = sizeof(DWORD);
            RegQueryValueExW(hKey, L"WindowsInstaller", NULL, NULL, (LPBYTE)&val, &size);
            if (val == 1) { RegCloseKey(hKey); return InstallerType::Msi; }
        }

        DWORD index = 0;
        wchar_t valName[256];
        DWORD valNameLen = 256;
        BYTE valData[2048];
        DWORD valDataLen = sizeof(valData);
        type = 0;

        while (RegEnumValueW(hKey, index, valName, &valNameLen, NULL, &type,
                              valData, &valDataLen) == ERROR_SUCCESS) {
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                std::wstring val((wchar_t*)valData, valDataLen / sizeof(wchar_t));
                std::wstring valLower = val;
                std::transform(valLower.begin(), valLower.end(), valLower.begin(), ::towlower);
                if (valLower.find(L"inno setup:") != std::wstring::npos) {
                    RegCloseKey(hKey);
                    return InstallerType::InnoSetup;
                }
                if (valLower.find(L"installshield") != std::wstring::npos) {
                    RegCloseKey(hKey);
                    return InstallerType::InstallShield;
                }
            }
            valNameLen = 256;
            valDataLen = sizeof(valData);
            index++;
        }
        RegCloseKey(hKey);
    }

    if (cmdLower.find(L"nsis") != std::wstring::npos ||
        cmdLower.find(L"nullsoft") != std::wstring::npos) return InstallerType::Nsis;

    if (cmdLower.find(L"installshield") != std::wstring::npos) return InstallerType::InstallShield;

    if (uninstallString.find(L"Package Cache") != std::wstring::npos) return InstallerType::Msi;

    return InstallerType::Unknown;
}

void Uninstaller::ScanRegistryKey(HKEY rootKey, const std::wstring& subKey,
                                   std::vector<UninstallEntry>& results) {
    HKEY hKey;
    if (RegOpenKeyExW(rootKey, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    DWORD index = 0;
    wchar_t keyName[256];
    DWORD keyNameLen = 256;

    while (RegEnumKeyExW(hKey, index, keyName, &keyNameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        HKEY hSubKey;
        std::wstring fullPath = subKey + L"\\" + std::wstring(keyName);
        if (RegOpenKeyExW(rootKey, fullPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
            std::wstring name = ReadRegString(hSubKey, L"DisplayName");
            if (!name.empty()) {
                UninstallEntry entry;
                entry.displayName = name;
                entry.displayVersion = ReadRegString(hSubKey, L"DisplayVersion");
                entry.publisher = ReadRegString(hSubKey, L"Publisher");
                entry.installPath = ReadRegString(hSubKey, L"InstallLocation");
                entry.uninstallString = ReadRegString(hSubKey, L"UninstallString");
                entry.displayIcon = ReadRegString(hSubKey, L"DisplayIcon");
                entry.registryKey = fullPath;
                entry.estimatedSize = ReadRegDword(hSubKey, L"EstimatedSize");
                entry.installDate = ReadRegString(hSubKey, L"InstallDate");
                entry.quietUninstallString = ReadRegString(hSubKey, L"QuietUninstallString");
                entry.aboutUrl = ReadRegString(hSubKey, L"URLInfoAbout");
                entry.installSource = ReadRegString(hSubKey, L"InstallSource");
                entry.modifyPath = ReadRegString(hSubKey, L"ModifyPath");
                entry.isProtected = ReadRegDword(hSubKey, L"NoRemove") == 1;
                entry.isUpdate = !ReadRegString(hSubKey, L"ParentKeyName").empty();
                if (entry.installDate.size() == 8) {
                    int yr = _wtoi(entry.installDate.substr(0, 4).c_str());
                    int mo = _wtoi(entry.installDate.substr(4, 2).c_str());
                    int dy = _wtoi(entry.installDate.substr(6, 2).c_str());
                    if (yr < 1990 || yr > 2099 || mo < 1 || mo > 12 || dy < 1 || dy > 31)
                        entry.installDate.clear();
                } else if (!entry.installDate.empty()) {
                    entry.installDate.clear();
                }
                entry.isSystemComponent = ReadRegDword(hSubKey, L"SystemComponent") == 1;
                entry.isMsiInstaller = ReadRegDword(hSubKey, L"WindowsInstaller") == 1;
                entry.installerType = DetectInstallerType(entry.uninstallString, rootKey, fullPath);

                if (entry.installPath.empty()) {
                    entry.installPath = ReadRegString(hSubKey, L"InstallSource");
                }

                if (!entry.installPath.empty() && std::filesystem::exists(entry.installPath)) {
                    std::error_code ec;
                    std::filesystem::directory_iterator it(entry.installPath, ec);
                    std::filesystem::directory_iterator end;
                    for (; it != end; it.increment(ec)) {
                        if (ec) break;
                        auto& f = *it;
                        if (!f.is_directory(ec)) {
                            std::wstring ext = f.path().extension().wstring();
                            std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
                            if (ext == L".exe" || ext == L".dll") {
                                std::wstring fn = f.path().filename().wstring();
                                std::transform(fn.begin(), fn.end(), fn.begin(), ::towlower);
                                entry.sortedExecutables.push_back(fn);
                            }
                        }
                    }
                    std::sort(entry.sortedExecutables.begin(), entry.sortedExecutables.end());
                }

                entry.displayNameLower = entry.displayName;
                std::transform(entry.displayNameLower.begin(), entry.displayNameLower.end(),
                                entry.displayNameLower.begin(), ::towlower);
                entry.publisherLower = entry.publisher;
                std::transform(entry.publisherLower.begin(), entry.publisherLower.end(),
                                entry.publisherLower.begin(), ::towlower);
                entry.registryKeyLower = entry.registryKey;
                std::transform(entry.registryKeyLower.begin(), entry.registryKeyLower.end(),
                                entry.registryKeyLower.begin(), ::towlower);

                results.push_back(entry);
            }
            RegCloseKey(hSubKey);
        }
        keyNameLen = 256;
        index++;
    }
    RegCloseKey(hKey);
}

std::vector<UninstallEntry> Uninstaller::ScanInstalled() {
    std::vector<UninstallEntry> results;

    ScanRegistryKey(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", results);
    ScanRegistryKey(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", results);
    ScanRegistryKey(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", results);

    for (auto& entry : results) {
        if (entry.bitness == Bitness::Unknown &&
            entry.registryKey.find(L"WOW6432Node") != std::wstring::npos)
            entry.bitness = Bitness::X86;

        if (entry.bitness == Bitness::Unknown && !entry.displayNameLower.empty()) {
            if (entry.displayNameLower.find(L"(x64)") != std::wstring::npos ||
                entry.displayNameLower.find(L" 64-bit") != std::wstring::npos ||
                entry.displayNameLower.find(L" (amd64)") != std::wstring::npos)
                entry.bitness = Bitness::X64;
            else if (entry.displayNameLower.find(L"(x86)") != std::wstring::npos ||
                     entry.displayNameLower.find(L" 32-bit") != std::wstring::npos ||
                     entry.displayNameLower.find(L" (x86)") != std::wstring::npos)
                entry.bitness = Bitness::X86;
            else if (entry.displayNameLower.find(L"(arm64)") != std::wstring::npos)
                entry.bitness = Bitness::ARM64;
        }

        if (entry.publisher.empty() && !entry.installPath.empty()) {
            std::wstring parentDir = entry.installPath;
            size_t lastSlash = parentDir.find_last_of(L'\\');
            if (lastSlash != std::wstring::npos) {
                entry.publisher = parentDir.substr(lastSlash + 1);
                entry.publisherLower = entry.publisher;
                std::transform(entry.publisherLower.begin(), entry.publisherLower.end(),
                                entry.publisherLower.begin(), ::towlower);
            }
        }
    }

    std::sort(results.begin(), results.end(), [](const UninstallEntry& a, const UninstallEntry& b) {
        return _wcsicmp(a.displayName.c_str(), b.displayName.c_str()) < 0;
    });

    m_cachedApps = results;
    return results;
}

void Uninstaller::EnrichEntriesBackground(std::vector<UninstallEntry>& entries) {
    for (auto& entry : entries) {
        std::wstring exePath;

        if (!entry.sortedExecutables.empty() && !entry.installPath.empty()) {
            exePath = entry.installPath + L"\\" + entry.sortedExecutables[0];
            if (GetFileAttributesW(exePath.c_str()) == INVALID_FILE_ATTRIBUTES)
                exePath.clear();
        }

        if (exePath.empty() && !entry.displayIcon.empty()) {
            std::wstring iconPath = entry.displayIcon;
            size_t commaPos = iconPath.find_last_of(L',');
            if (commaPos != std::wstring::npos)
                iconPath = iconPath.substr(0, commaPos);
            while (!iconPath.empty() && iconPath[0] == L'"')
                iconPath.erase(iconPath.begin());
            while (!iconPath.empty() && (iconPath.back() == L'"' || iconPath.back() == L' '))
                iconPath.pop_back();
            if (!iconPath.empty() && GetFileAttributesW(iconPath.c_str()) != INVALID_FILE_ATTRIBUTES)
                exePath = iconPath;
        }

        if (exePath.empty() && !entry.uninstallString.empty()) {
            std::wstring cmd = entry.uninstallString;
            size_t q1 = cmd.find(L'\"');
            if (q1 != std::wstring::npos) {
                size_t q2 = cmd.find(L'\"', q1 + 1);
                cmd = (q2 != std::wstring::npos) ? cmd.substr(q1 + 1, q2 - q1 - 1) : cmd.substr(q1 + 1);
            } else {
                size_t space = cmd.find(L' ');
                if (space != std::wstring::npos) cmd = cmd.substr(0, space);
            }
            std::wstring cmdLower = cmd;
            std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::towlower);
            if (cmdLower.find(L"msiexec") == std::wstring::npos &&
                GetFileAttributesW(cmd.c_str()) != INVALID_FILE_ATTRIBUTES)
                exePath = cmd;
        }

        if (exePath.empty() && !entry.installSource.empty()) {
            if (GetFileAttributesW(entry.installSource.c_str()) != INVALID_FILE_ATTRIBUTES) {
                std::error_code ec;
                for (auto& f : std::filesystem::directory_iterator(entry.installSource, ec)) {
                    if (ec) break;
                    if (!f.is_directory()) {
                        std::wstring ext = f.path().extension().wstring();
                        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
                        if (ext == L".exe") {
                            exePath = f.path().wstring();
                            break;
                        }
                    }
                }
            }
        }

        if (!exePath.empty()) {
            if (entry.certStatus == CertStatus::Unknown)
                entry.certStatus = VerifyCertificate(exePath);
            if (entry.bitness == Bitness::Unknown)
                entry.bitness = DetectBitness(exePath);
            EnrichEntryFromPE(entry);

            if (entry.installDate.empty()) {
                WIN32_FILE_ATTRIBUTE_DATA fad = {};
                if (GetFileAttributesExW(exePath.c_str(), GetFileExInfoStandard, &fad)) {
                    FILETIME ft = fad.ftCreationTime;
                    SYSTEMTIME st;
                    if (FileTimeToSystemTime(&ft, &st)) {
                        wchar_t dateBuf[32];
                        swprintf_s(dateBuf, L"%02d/%02d/%04d", st.wMonth, st.wDay, st.wYear);
                        entry.installDate = dateBuf;
                    }
                }
            }
        }
    }
}

std::vector<UninstallEntry> Uninstaller::ScanExtras() {
    std::vector<UninstallEntry> results;

    auto choco = ScanChocolateyPackages();
    results.insert(results.end(), choco.begin(), choco.end());

    auto scoopPkgs = ScanScoopPackages();
    results.insert(results.end(), scoopPkgs.begin(), scoopPkgs.end());

    auto winFeatures = ScanWindowsFeatures();
    results.insert(results.end(), winFeatures.begin(), winFeatures.end());

    return results;
}

static std::vector<std::wstring> RunCommandCapture(const std::wstring& cmd, DWORD timeoutMs = 5000) {
    std::vector<std::wstring> lines;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return lines;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(0);
    if (!CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return lines;
    }
    CloseHandle(hWrite);
    char buf[4096];
    std::string accum;
    DWORD bytesRead = 0;
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    DWORD startTime = GetTickCount();
    while (true) {
        DWORD elapsed = GetTickCount() - startTime;
        if (elapsed >= timeoutMs) break;
        DWORD remaining = timeoutMs - elapsed;
        DWORD avail = 0;
        if (PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            if (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buf[bytesRead] = 0;
                accum += buf;
                continue;
            }
        }
        if (WaitForSingleObject(pi.hProcess, 100) == WAIT_OBJECT_0) {
            while (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buf[bytesRead] = 0;
                accum += buf;
            }
            break;
        }
    }
    if (ov.hEvent) CloseHandle(ov.hEvent);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    std::wstring waccum(accum.begin(), accum.end());
    std::wistringstream iss(waccum);
    std::wstring line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == L'\r')
            line.pop_back();
        if (!line.empty())
            lines.push_back(line);
    }
    return lines;
}

static std::string RunCommandCaptureA(const std::wstring& cmd, DWORD timeoutMs = 5000) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return "";
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(0);
    if (!CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return "";
    }
    CloseHandle(hWrite);
    char buf[4096];
    std::string accum;
    DWORD bytesRead = 0;
    DWORD startTime = GetTickCount();
    while (true) {
        DWORD elapsed = GetTickCount() - startTime;
        if (elapsed >= timeoutMs) break;
        DWORD avail = 0;
        if (PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            if (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buf[bytesRead] = 0;
                accum += buf;
                continue;
            }
        }
        if (WaitForSingleObject(pi.hProcess, 100) == WAIT_OBJECT_0) {
            while (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buf[bytesRead] = 0;
                accum += buf;
            }
            break;
        }
    }
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return accum;
}

std::vector<UninstallEntry> Uninstaller::ScanChocolateyPackages() {
    std::vector<UninstallEntry> results;
    auto lines = RunCommandCapture(L"cmd.exe /c choco list --local-only --detail 2>nul");
    if (lines.empty() || lines.size() < 2) return results;

    UninstallEntry current;
    for (auto& line : lines) {
        if (line.find(L"Chocolatey ") != std::wstring::npos ||
            line.find(L"Chocolatey v") != std::wstring::npos)
            continue;
        if (line.empty() && !current.displayName.empty()) {
            results.push_back(current);
            current = UninstallEntry();
            continue;
        }
        size_t eqPos = line.find(L'=');
        if (eqPos == std::wstring::npos) continue;
        std::wstring key = line.substr(0, eqPos);
        std::wstring value = line.substr(eqPos + 1);
        while (!key.empty() && key.back() == L' ')
            key.pop_back();
        while (!value.empty() && value[0] == L' ')
            value.erase(value.begin());

        if (key == L"Name") {
            current.displayName = value;
            current.displayNameLower = value;
            std::transform(current.displayNameLower.begin(), current.displayNameLower.end(),
                           current.displayNameLower.begin(), ::towlower);
        } else if (key == L"Version") {
            current.displayVersion = value;
        } else if (key == L"Summary") {
            current.aboutUrl = value;
        } else if (key == L"Install Location") {
            current.installPath = value;
        } else if (key == L"Uninstall Command" || key == L"Uninstall") {
            current.uninstallString = value;
        }
    }
    if (!current.displayName.empty())
        results.push_back(current);

    for (auto& entry : results) {
        entry.installerType = InstallerType::Chocolatey;
        entry.registryKey = L"Chocolatey\\" + entry.displayName;
        entry.registryKeyLower = entry.registryKey;
        std::transform(entry.registryKeyLower.begin(), entry.registryKeyLower.end(),
                       entry.registryKeyLower.begin(), ::towlower);
        if (entry.uninstallString.empty())
            entry.uninstallString = L"choco uninstall \"" + entry.displayName + L"\" -y";
    }
    return results;
}

std::vector<UninstallEntry> Uninstaller::ScanScoopPackages() {
    std::vector<UninstallEntry> results;

    wchar_t userProfile[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH))
        return results;

    std::wstring scoopDir = std::wstring(userProfile) + L"\\scoop\\apps";
    if (GetFileAttributesW(scoopDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wstring scoopShim = std::wstring(userProfile) + L"\\scoop\\shims\\scoop.cmd";
        if (GetFileAttributesW(scoopShim.c_str()) == INVALID_FILE_ATTRIBUTES) {
            wchar_t scoopPath[MAX_PATH] = {};
            if (GetEnvironmentVariableW(L"SCOOP", scoopPath, MAX_PATH)) {
                scoopDir = std::wstring(scoopPath) + L"\\apps";
                if (GetFileAttributesW(scoopDir.c_str()) == INVALID_FILE_ATTRIBUTES)
                    return results;
            } else {
                return results;
            }
        } else {
            auto lines = RunCommandCapture(L"cmd.exe /c scoop export 2>nul");
            if (lines.empty()) {
                std::wstring scoopShimPath = std::wstring(userProfile) + L"\\scoop\\shims\\scoop.cmd";
                if (GetFileAttributesW(scoopShimPath.c_str()) == INVALID_FILE_ATTRIBUTES)
                    return results;
                scoopDir = std::wstring(userProfile) + L"\\scoop\\apps";
                if (GetFileAttributesW(scoopDir.c_str()) == INVALID_FILE_ATTRIBUTES)
                    return results;
            }
        }
    }

    std::error_code ec;
    for (auto& dirEntry : std::filesystem::directory_iterator(scoopDir, ec)) {
        if (ec) break;
        if (!dirEntry.is_directory()) continue;
        std::wstring dirName = dirEntry.path().filename().wstring();
        if (dirName == L"current" || dirName == L".cache") continue;

        UninstallEntry entry;
        entry.displayName = dirName;
        entry.displayNameLower = dirName;
        std::transform(entry.displayNameLower.begin(), entry.displayNameLower.end(),
                       entry.displayNameLower.begin(), ::towlower);

        std::wstring currentLink = dirEntry.path().wstring() + L"\\current";
        DWORD attrs = GetFileAttributesW(currentLink.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            entry.installPath = currentLink;
        } else {
            for (auto& versionDir : std::filesystem::directory_iterator(dirEntry.path(), ec)) {
                if (ec) break;
                if (versionDir.is_directory()) {
                    std::wstring vName = versionDir.path().filename().wstring();
                    if (vName != L"current" && vName != L".cache") {
                        entry.installPath = versionDir.path().wstring();
                        entry.displayVersion = vName;
                        break;
                    }
                }
            }
        }

        entry.installerType = InstallerType::Scoop;
        entry.registryKey = L"Scoop\\" + dirName;
        entry.registryKeyLower = entry.registryKey;
        std::transform(entry.registryKeyLower.begin(), entry.registryKeyLower.end(),
                       entry.registryKeyLower.begin(), ::towlower);
        entry.uninstallString = L"scoop uninstall \"" + dirName + L"\"";
        results.push_back(entry);
    }
    return results;
}

#include <WbemCli.h>
#pragma comment(lib, "wbemuuid.lib")

std::vector<UninstallEntry> Uninstaller::ScanWindowsFeatures() {
    std::vector<UninstallEntry> results;
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    bool comInited = SUCCEEDED(hr);
    if (!comInited && hr != RPC_E_CHANGED_MODE) return results;

    IWbemLocator* pLocator = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (void**)&pLocator);
    if (FAILED(hr) || !pLocator) {
        if (comInited) CoUninitialize();
        return results;
    }

    IWbemServices* pServices = nullptr;
    BSTR bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
    hr = pLocator->ConnectServer(bstrNamespace, NULL, NULL, 0, 0, 0, 0, &pServices);
    SysFreeString(bstrNamespace);
    if (FAILED(hr) || !pServices) {
        pLocator->Release();
        if (comInited) CoUninitialize();
        return results;
    }

    hr = CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) {
        pServices->Release();
        pLocator->Release();
        if (comInited) CoUninitialize();
        return results;
    }

    IEnumWbemClassObject* pEnumerator = nullptr;
    BSTR bstrWQL = SysAllocString(L"WQL");
    BSTR bstrQuery = SysAllocString(L"SELECT Name, InstallState FROM Win32_OptionalFeature");
    hr = pServices->ExecQuery(bstrWQL, bstrQuery,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    SysFreeString(bstrWQL);
    SysFreeString(bstrQuery);
    if (FAILED(hr) || !pEnumerator) {
        pServices->Release();
        pLocator->Release();
        if (comInited) CoUninitialize();
        return results;
    }

    IWbemClassObject* pObj = nullptr;
    ULONG returnedCount = 0;
    while (pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &returnedCount) == S_OK && returnedCount > 0) {
        VARIANT vtName, vtState;
        VariantInit(&vtName);
        VariantInit(&vtState);
        pObj->Get(L"Name", 0, &vtName, NULL, NULL);
        pObj->Get(L"InstallState", 0, &vtState, NULL, NULL);

        std::wstring featureName;
        if (vtName.bstrVal)
            featureName = vtName.bstrVal;

        if (!featureName.empty()) {
            UninstallEntry entry;
            entry.displayName = featureName;
            entry.displayNameLower = featureName;
            std::transform(entry.displayNameLower.begin(), entry.displayNameLower.end(),
                           entry.displayNameLower.begin(), ::towlower);
            entry.displayVersion = L"Windows Feature";
            int state = (vtState.vt == VT_I4) ? vtState.intVal : -1;
            entry.registryKey = L"WindowsFeature\\" + featureName;
            entry.registryKeyLower = entry.registryKey;
            std::transform(entry.registryKeyLower.begin(), entry.registryKeyLower.end(),
                           entry.registryKeyLower.begin(), ::towlower);
            entry.uninstallString = L"dism.exe /Online /Disable-Feature /FeatureName:" + featureName + L" /NoRestart";
            entry.quietUninstallString = entry.uninstallString;
            entry.installerType = InstallerType::WindowsFeature;
            entry.isSystemComponent = true;
            entry.isProtected = (state != 1);
            entry.registryKey = L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages\\" + featureName;
            results.push_back(entry);
        }

        VariantClear(&vtName);
        VariantClear(&vtState);
        pObj->Release();
    }

    pEnumerator->Release();
    pServices->Release();
    pLocator->Release();
    if (comInited) CoUninitialize();
    return results;
}

std::vector<StartupEntry> Uninstaller::ScanStartupEntries() {
    std::vector<StartupEntry> results;

    auto scanRegKey = [&](HKEY root, const std::wstring& subKey, StartupEntry::LocationType locType, const std::wstring& locName) {
        HKEY hKey;
        if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
        DWORD index = 0;
        wchar_t valueName[256];
        DWORD nameLen = 256;
        BYTE data[2048];
        DWORD dataLen = sizeof(data);
        DWORD type = 0;
        while (RegEnumValueW(hKey, index++, valueName, &nameLen, NULL, &type, data, &dataLen) == ERROR_SUCCESS) {
            if (type != REG_SZ && type != REG_EXPAND_SZ) {
                nameLen = 256;
                dataLen = sizeof(data);
                continue;
            }
            std::wstring cmd;
            if (type == REG_SZ) {
                cmd = (wchar_t*)data;
            } else {
                wchar_t expanded[2048] = {};
                ExpandEnvironmentStringsW((wchar_t*)data, expanded, 2048);
                cmd = expanded;
            }
            if (cmd.empty() || cmd[0] == L'@') {
                nameLen = 256;
                dataLen = sizeof(data);
                continue;
            }

            StartupEntry entry;
            entry.name = valueName;
            entry.command = cmd;
            entry.location = locName;
            entry.locationType = locType;
            entry.enabled = true;
            entry.isProtected = false;

            std::wstring cmdLower = cmd;
            std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::towlower);
            if (cmdLower.find(L"windows\\system32") != std::wstring::npos ||
                cmdLower.find(L"windows\\syswow64") != std::wstring::npos) {
                entry.isProtected = true;
            }

            results.push_back(entry);
            nameLen = 256;
            dataLen = sizeof(data);
        }
        RegCloseKey(hKey);
    };

    scanRegKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
               StartupEntry::RunKey, L"HKCU\\Run");
    scanRegKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
               StartupEntry::RunOnce, L"HKCU\\RunOnce");
    scanRegKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
               StartupEntry::RunKey, L"HKLM\\Run");
    scanRegKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
               StartupEntry::RunOnce, L"HKLM\\RunOnce");
    scanRegKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
               StartupEntry::RunKey, L"HKLM\\Run (x86)");
    scanRegKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
               StartupEntry::RunKey, L"HKCU\\StartupApproved");

    wchar_t startupPath[MAX_PATH] = {};
    if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, SHGFP_TYPE_CURRENT, startupPath) == S_OK) {
        std::error_code ec;
        for (auto& f : std::filesystem::directory_iterator(startupPath, ec)) {
            if (ec) break;
            if (f.is_regular_file()) {
                std::wstring ext = f.path().extension().wstring();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
                if (ext == L".lnk" || ext == L".url") {
                    StartupEntry entry;
                    entry.name = f.path().stem().wstring();
                    entry.command = f.path().wstring();
                    entry.location = L"Startup Folder (User)";
                    entry.locationType = StartupEntry::StartupFolder;
                    entry.enabled = true;
                    entry.isProtected = false;
                    results.push_back(entry);
                }
            }
        }
    }

    wchar_t commonStartup[MAX_PATH] = {};
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, SHGFP_TYPE_CURRENT, commonStartup) == S_OK) {
        std::error_code ec;
        for (auto& f : std::filesystem::directory_iterator(commonStartup, ec)) {
            if (ec) break;
            if (f.is_regular_file()) {
                std::wstring ext = f.path().extension().wstring();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
                if (ext == L".lnk" || ext == L".url") {
                    StartupEntry entry;
                    entry.name = f.path().stem().wstring();
                    entry.command = f.path().wstring();
                    entry.location = L"Startup Folder (All Users)";
                    entry.locationType = StartupEntry::StartupFolder;
                    entry.enabled = true;
                    entry.isProtected = false;
                    results.push_back(entry);
                }
            }
        }
    }

    return results;
}

bool Uninstaller::UninstallStandard(const UninstallEntry& entry) {
    if (entry.uninstallString.empty()) {
        m_lastError = L"No uninstall string available";
        return false;
    }

    std::wstring cmd = entry.uninstallString;

    if (entry.isMsiInstaller) {
        if (cmd.find(L"MsiExec") == std::wstring::npos &&
            cmd.find(L"msiexec") == std::wstring::npos &&
            cmd.find(L" /x") == std::wstring::npos &&
            cmd.find(L" /X") == std::wstring::npos &&
            cmd.find(L"/x{") == std::wstring::npos &&
            cmd.find(L"/X{") == std::wstring::npos) {
            cmd = L"msiexec.exe /x " + cmd;
        }
    }

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(cmd.c_str(), &argc);
    if (argc > 0 && argv) {
        std::wstring exePath = argv[0];
        DWORD attrs = GetFileAttributesW(exePath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            size_t lastSlash = exePath.find_last_of(L'\\');
            if (lastSlash != std::wstring::npos) {
                std::wstring baseName = exePath.substr(lastSlash + 1);
                wchar_t sysDir[MAX_PATH] = {};
                GetSystemDirectoryW(sysDir, MAX_PATH);
                std::wstring sysExe = std::wstring(sysDir) + L"\\" + baseName;
                if (GetFileAttributesW(sysExe.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    exePath = sysExe;
                    cmd = exePath;
                    for (int i = 1; i < argc; i++) {
                        cmd += L" ";
                        cmd += argv[i];
                    }
                }
            }
        }
        LocalFree(argv);

        attrs = GetFileAttributesW(exePath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            m_lastError = L"Uninstaller executable not found: " + exePath;
            return false;
        }
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(0);

    if (CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 60000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }

    m_lastError = L"Failed to launch uninstaller: " + cmd;
    return false;
}

bool Uninstaller::ForceRemove(const UninstallEntry& entry) {
    Deletor deletor;

    if (!entry.installPath.empty() && std::filesystem::exists(entry.installPath)) {
        auto procs = deletor.GetProcessesLockingFile(entry.installPath);
        for (auto& proc : procs) {
            deletor.TerminateProcessIfSafe(proc.pid);
        }

        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (LookupPrivilegeValueW(NULL, SE_TAKE_OWNERSHIP_NAME, &tp.Privileges[0].Luid))
                AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
            if (LookupPrivilegeValueW(NULL, SE_RESTORE_NAME, &tp.Privileges[0].Luid))
                AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

            CloseHandle(hToken);
        }

        DWORD fileAttr = GetFileAttributesW(entry.installPath.c_str());
        if (fileAttr != INVALID_FILE_ATTRIBUTES) {
            deletor.DeleteFileSafely(entry.installPath);
        }

        std::wstring parentPath = std::filesystem::path(entry.installPath).parent_path().wstring();
        if (!parentPath.empty() && std::filesystem::exists(parentPath)) {
            std::error_code ec;
            for (auto& sub : std::filesystem::directory_iterator(parentPath, ec)) {
                if (ec) break;
                std::wstring subName = sub.path().filename().wstring();
                std::wstring kwLower = entry.displayName;
                std::wstring nameLower = subName;
                std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
                std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
                if (nameLower.find(kwLower) != std::wstring::npos ||
                    (!entry.publisher.empty())) {
                    std::wstring pubLower = entry.publisher;
                    std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);
                    if (!pubLower.empty() && nameLower.find(pubLower) != std::wstring::npos) {
                        deletor.DeleteFileSafely(sub.path().wstring());
                    } else if (nameLower.find(kwLower) != std::wstring::npos) {
                        deletor.DeleteFileSafely(sub.path().wstring());
                    }
                }
            }
        }
    }

    if (!entry.registryKey.empty()) {
        HKEY rootKey = HKEY_LOCAL_MACHINE;
        std::wstring regPath = entry.registryKey;
        if (regPath.find(L"HKCU\\") == 0 || regPath.find(L"HKEY_CURRENT_USER\\") == 0) {
            rootKey = HKEY_CURRENT_USER;
            if (regPath.find(L"HKCU\\") == 0) regPath = regPath.substr(5);
            else regPath = regPath.substr(18);
        } else {
            size_t firstSlash = regPath.find(L'\\');
            if (firstSlash != std::wstring::npos) {
                std::wstring root = regPath.substr(0, firstSlash);
                regPath = regPath.substr(firstSlash + 1);
                if (root == L"HKLM" || root == L"HKEY_LOCAL_MACHINE") rootKey = HKEY_LOCAL_MACHINE;
                else if (root == L"HKCU" || root == L"HKEY_CURRENT_USER") rootKey = HKEY_CURRENT_USER;
            }
        }
        RegDeleteTreeW(rootKey, regPath.c_str());
    }

    auto leftovers = ScanLeftovers(entry, ScanDepth::Advanced);
    for (auto& item : leftovers) {
        if (!item.checked) continue;
        if (IsProtectedPath(item.path)) continue;
        if (item.type == LeftoverItem::RegistryKey && IsProtectedRegistryKey(item.path))
            continue;
        if (item.type == LeftoverItem::RegistryKey) {
            HKEY rk = HKEY_LOCAL_MACHINE;
            std::wstring rp = item.path;
            size_t fs = rp.find(L'\\');
            bool isHKLM = true;
            if (fs != std::wstring::npos) {
                std::wstring root = rp.substr(0, fs);
                rp = rp.substr(fs + 1);
                if (root == L"HKCU" || root == L"HKEY_CURRENT_USER") { rk = HKEY_CURRENT_USER; isHKLM = false; }
            }
            if (isHKLM) {
                HKEY hKey = NULL;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, rp.c_str(), 0, KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                    RegDeleteTreeW(hKey, NULL);
                    RegCloseKey(hKey);
                }
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, rp.c_str(), 0, KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS) {
                    RegDeleteTreeW(hKey, NULL);
                    RegCloseKey(hKey);
                }
            } else {
                HKEY hKey = NULL;
                if (RegOpenKeyExW(rk, rp.c_str(), 0, KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE, &hKey) == ERROR_SUCCESS) {
                    RegDeleteTreeW(hKey, NULL);
                    RegCloseKey(hKey);
                }
            }
        } else {
            deletor.DeleteFileSafely(item.path);
        }
    }

    return true;
}

bool Uninstaller::RemoveRegistryEntry(const UninstallEntry& entry) {
    if (entry.registryKey.empty()) {
        m_lastError = L"No registry key path";
        return false;
    }

    HKEY rootKey = HKEY_LOCAL_MACHINE;
    std::wstring regPath = entry.registryKey;
    bool isHKLM = true;
    if (regPath.find(L"HKCU\\") == 0) {
        rootKey = HKEY_CURRENT_USER;
        regPath = regPath.substr(5);
        isHKLM = false;
    } else if (regPath.find(L"HKEY_CURRENT_USER\\") == 0) {
        rootKey = HKEY_CURRENT_USER;
        regPath = regPath.substr(18);
        isHKLM = false;
    } else if (regPath.find(L"HKLM\\") == 0) {
        regPath = regPath.substr(5);
    } else if (regPath.find(L"HKEY_LOCAL_MACHINE\\") == 0) {
        regPath = regPath.substr(20);
    }

    if (isHKLM && rootKey == HKEY_LOCAL_MACHINE) {
        HKEY hKey = NULL;
        LONG openRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0,
                                     KEY_READ | KEY_WOW64_64KEY, &hKey);
        if (openRes == ERROR_SUCCESS) {
            LONG delRes = RegDeleteTreeW(hKey, NULL);
            RegCloseKey(hKey);
            if (delRes != ERROR_SUCCESS) {
                m_lastError = L"RegDeleteTreeW failed: " + std::to_wstring(delRes);
                return false;
            }
            return true;
        }
        openRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0,
                                KEY_READ | KEY_WOW64_32KEY, &hKey);
        if (openRes == ERROR_SUCCESS) {
            LONG delRes = RegDeleteTreeW(hKey, NULL);
            RegCloseKey(hKey);
            if (delRes != ERROR_SUCCESS) {
                m_lastError = L"RegDeleteTreeW (32-bit) failed: " + std::to_wstring(delRes);
                return false;
            }
            return true;
        }
    }

    LONG res = RegDeleteTreeW(rootKey, regPath.c_str());
    if (res != ERROR_SUCCESS) {
        m_lastError = L"RegDeleteTreeW failed: " + std::to_wstring(res);
        return false;
    }
    return true;
}

void Uninstaller::ScanDirectory(const std::wstring& dir, const std::wstring& keyword,
                                std::vector<LeftoverItem>& results, ScanDepth depth) {
    if (dir.empty() || !std::filesystem::exists(dir) || !std::filesystem::is_directory(dir))
        return;
    if (IsProtectedPath(dir)) {
        BH_TRACE_BLOCKED("ScanDir", "protected_path", dir.c_str());
        return;
    }

    DWORD dirAttr = GetFileAttributesW(dir.c_str());
    if (dirAttr == INVALID_FILE_ATTRIBUTES) return;
    if (dirAttr & FILE_ATTRIBUTE_REPARSE_POINT) {
        BH_TRACE_BLOCKED("ScanDir", "reparse_point", dir.c_str());
        return;
    }

    BH_TIMER_START(t0);
    int scanned = 0, matched = 0, subMatched = 0, skippedRP = 0;

    try {
    std::error_code ec;
    std::filesystem::directory_iterator it(dir, ec);
    if (ec) return;
    std::filesystem::directory_iterator end;
    for (; it != end; it.increment(ec)) {
        if (ec) break;

        const auto& entry = *it;
        scanned++;

        DWORD entryAttr = GetFileAttributesW(entry.path().c_str());
        if (entryAttr != INVALID_FILE_ATTRIBUTES && (entryAttr & FILE_ATTRIBUTE_REPARSE_POINT))
            { skippedRP++; continue; }

        std::wstring name = entry.path().filename().wstring();

        std::wstring nameLower = name;
        std::wstring kwLower = keyword;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
        std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);

        if (nameLower.find(kwLower) != std::wstring::npos) {

            int rawScore = 0;
            LeftoverConfidence conf = ScoreConfidence(
                name, keyword, L"", entry.path().wstring(), false, 0, rawScore);

            if (conf == LeftoverConfidence::Risky && depth == ScanDepth::Safe) {
                BH_TRACE_BLOCKED("ScanDir", "risky_score", name.c_str());
                continue;
            }

            LeftoverItem item;
            item.path = entry.path().wstring();
            item.displayName = name;
            item.type = entry.is_directory() ? LeftoverItem::Directory : LeftoverItem::File;
            item.checked = (conf != LeftoverConfidence::Risky);
            item.confidence = conf;
            item.rawScore = rawScore;
            results.push_back(item);
            matched++;

            if (item.type == LeftoverItem::Directory) {
                int maxSubDepth = (depth == ScanDepth::Safe) ? 1 :
                                  (depth == ScanDepth::Moderate) ? 3 : 10;
                int subDepth = 0;
                std::filesystem::recursive_directory_iterator subIt(entry.path(), ec);
                if (!ec) {
                    std::filesystem::recursive_directory_iterator subEnd;
                    for (; subIt != subEnd; subIt.increment(ec)) {
                        if (ec) break;
                        if (subDepth >= maxSubDepth) break;

                        const auto& sub = *subIt;

                        DWORD subAttr = GetFileAttributesW(sub.path().c_str());
                        if (subAttr != INVALID_FILE_ATTRIBUTES && (subAttr & FILE_ATTRIBUTE_REPARSE_POINT))
                            continue;

                        int subRawScore = 0;
                        LeftoverConfidence subConf = ScoreConfidence(
                            sub.path().filename().wstring(), keyword, L"",
                            sub.path().wstring(), false, subDepth, subRawScore);

                        if (subConf == LeftoverConfidence::Risky && depth == ScanDepth::Safe)
                            continue;

                        LeftoverItem subItem;
                        subItem.path = sub.path().wstring();
                        subItem.displayName = sub.path().filename().wstring();
                        subItem.type = sub.is_directory() ? LeftoverItem::Directory : LeftoverItem::File;
                        subItem.checked = (subConf != LeftoverConfidence::Risky);
                        subItem.confidence = subConf;
                        subItem.rawScore = subRawScore;
                        results.push_back(subItem);
                        subMatched++;
                        subDepth++;
                    }
                }
            }
        }
    }
    } catch (...) {
        ScanLog("ScanDirectory: exception caught");
    }
    {
        char _buf[512];
        snprintf(_buf, sizeof(_buf), "ScanDir[%ls]: scanned=%d matched=%d subMatched=%d reparseSkip=%d results=%d\n",
                 dir.c_str(), scanned, matched, subMatched, skippedRP, (int)results.size());
        OutputDebugStringA(_buf);
    }
    BH_TIMER_END_MS(t0, "ScanDirectory");
}

void Uninstaller::ScanInstallDirContents(const std::wstring& dir, const std::wstring& keyword,
                                          const std::wstring& publisher,
                                          std::vector<LeftoverItem>& results, ScanDepth depth,
                                          int currentDepth) {
    if (dir.empty() || !std::filesystem::exists(dir) || !std::filesystem::is_directory(dir))
        return;
    if (IsProtectedPath(dir)) return;

    int maxDepth = (depth == ScanDepth::Safe) ? 3 :
                   (depth == ScanDepth::Moderate) ? 6 : 15;
    if (currentDepth > maxDepth) return;

    DWORD dirAttr = GetFileAttributesW(dir.c_str());
    if (dirAttr == INVALID_FILE_ATTRIBUTES) return;
    if (dirAttr & FILE_ATTRIBUTE_REPARSE_POINT) return;

    try {
    std::error_code ec;
    std::filesystem::directory_iterator it(dir, ec);
    if (ec) return;
    std::filesystem::directory_iterator end;
    for (; it != end; it.increment(ec)) {
        if (ec) break;

        const auto& entry = *it;

        DWORD entryAttr = GetFileAttributesW(entry.path().c_str());
        if (entryAttr != INVALID_FILE_ATTRIBUTES && (entryAttr & FILE_ATTRIBUTE_REPARSE_POINT))
            continue;

        std::wstring name = entry.path().filename().wstring();
        std::wstring fullPath = entry.path().wstring();

        int rawScore = 0;
        LeftoverConfidence conf = ScoreConfidence(
            name, keyword, publisher, fullPath, false, currentDepth, rawScore);

        if (conf == LeftoverConfidence::Risky && depth == ScanDepth::Safe)
            continue;

        LeftoverItem item;
        item.path = fullPath;
        item.displayName = name;
        item.type = entry.is_directory() ? LeftoverItem::Directory : LeftoverItem::File;
        item.checked = (conf != LeftoverConfidence::Risky);
        item.confidence = conf;
        item.rawScore = rawScore;
        results.push_back(item);

        if (item.type == LeftoverItem::Directory) {
            ScanInstallDirContents(fullPath, keyword, publisher, results, depth, currentDepth + 1);
        }
    }
    } catch (...) {
        ScanLog("ScanInstallDirContents: exception caught");
    }
}

void Uninstaller::ScanRegistryForLeftovers(HKEY rootKey, const std::wstring& subKey,
                                            const std::wstring& keyword,
                                            const std::wstring& publisher,
                                            const std::wstring& installPath,
                                            std::vector<LeftoverItem>& results,
                                            ScanDepth depth) {
    if (IsProtectedRegistryKey(subKey)) {
        BH_TRACE_BLOCKED("ScanReg", "protected_registry", subKey.c_str());
        return;
    }

    {
        const wchar_t* rootName = (rootKey == HKEY_CURRENT_USER ? L"HKCU" :
                                   (rootKey == HKEY_CLASSES_ROOT ? L"HKCR" : L"HKLM"));
        char dbg[256];
        snprintf(dbg, sizeof(dbg), "ScanReg: OPEN root=%ls sub=%ls kw=%ls pub=%ls inst=%ls\n",
                 rootName, subKey.c_str(), keyword.c_str(), publisher.c_str(), installPath.c_str());
        OutputDebugStringA(dbg);
    }

    BH_TIMER_START(t0);
    int enumerated = 0, stopWordSkip = 0, moreDataSkip = 0, matches = 0, subMatches = 0;

    HKEY hKey;
    if (RegOpenKeyExW(rootKey, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        OutputDebugStringA("ScanRegistryForLeftovers: RegOpenKeyExW failed for subKey\n");
        return;
    }
    BH_REG_OPEN(hKey, rootKey, subKey.c_str());

    DWORD index = 0;
    wchar_t keyName[512];
    DWORD keyNameLen = 512;
    DWORD ret;

    while ((ret = RegEnumKeyExW(hKey, index, keyName, &keyNameLen, NULL, NULL, NULL, NULL)) == ERROR_SUCCESS ||
           ret == ERROR_MORE_DATA) {
        if (ret == ERROR_MORE_DATA) {
            moreDataSkip++;
            keyNameLen = 512;
            index++;
            continue;
        }
        enumerated++;
        std::wstring name(keyName);

        if (IsStopWord(name)) {
            BH_TRACE_BLOCKED("ScanReg", "stop_word", name.c_str());
            stopWordSkip++;
            keyNameLen = 512;
            index++;
            continue;
        }

        std::wstring nameLower = name;
        std::wstring kwLower = keyword;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
        std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);

        std::wstring kwOrigLower = keyword;
        std::transform(kwOrigLower.begin(), kwOrigLower.end(), kwOrigLower.begin(), ::towlower);
        bool nameMatch = (nameLower.find(kwLower) != std::wstring::npos) ||
                         (kwLower.find(nameLower) != std::wstring::npos) ||
                         (!kwOrigLower.empty() && nameLower.find(kwOrigLower) != std::wstring::npos) ||
                         (!kwOrigLower.empty() && kwOrigLower.find(nameLower) != std::wstring::npos);
        if (nameMatch) {
            const wchar_t* rootName = (rootKey == HKEY_CURRENT_USER ? L"HKCU" :
                                       (rootKey == HKEY_CLASSES_ROOT ? L"HKCR" : L"HKLM"));
            {
                char dbg[256];
                snprintf(dbg, sizeof(dbg), "ScanReg: MATCH root=%ls sub=%ls name=%ls kw=%ls\n",
                         rootName, subKey.c_str(), name.c_str(), keyword.c_str());
                OutputDebugStringA(dbg);
            }

            int rawScore = 0;
            LeftoverConfidence conf = ScoreConfidence(
                name, keyword, publisher, installPath, true, 0, rawScore);

            if (conf == LeftoverConfidence::Risky && depth == ScanDepth::Safe) {
                BH_TRACE_BLOCKED("ScanReg", "risky_at_safe", name.c_str());
                keyNameLen = 512;
                index++;
                continue;
            }

            std::wstring fullPath;
            if (rootKey == HKEY_CURRENT_USER) fullPath = L"HKCU\\" + subKey;
            else if (rootKey == HKEY_CLASSES_ROOT) fullPath = L"HKCR\\" + subKey;
            else fullPath = L"HKLM\\" + subKey;

            LeftoverItem item;
            item.path = fullPath + L"\\" + name;
            item.displayName = name;
            item.type = LeftoverItem::RegistryKey;
            item.checked = (conf != LeftoverConfidence::Risky);
            item.confidence = conf;
            item.rawScore = rawScore;
            results.push_back(item);
            matches++;

            if (depth != ScanDepth::Safe) {
                int subDepth = 1;
                HKEY hSubKey;
                std::wstring subKeyName = subKey + L"\\" + name;
                if (RegOpenKeyExW(rootKey, subKeyName.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                    BH_REG_OPEN(hSubKey, rootKey, subKeyName.c_str());
                    DWORD subIndex = 0;
                    wchar_t subName[512];
                    DWORD subNameLen = 512;
                    DWORD subRet;
                    while ((subRet = RegEnumKeyExW(hSubKey, subIndex, subName, &subNameLen,
                                          NULL, NULL, NULL, NULL)) == ERROR_SUCCESS ||
                           subRet == ERROR_MORE_DATA) {
                        if (subRet == ERROR_MORE_DATA) {
                            subNameLen = 512;
                            subIndex++;
                            subDepth++;
                            continue;
                        }
                        if (depth == ScanDepth::Moderate && subDepth > 1) break;

                        if (IsStopWord(std::wstring(subName))) {
                            BH_TRACE_BLOCKED("ScanRegSub", "stop_word", subName);
                            subNameLen = 512;
                            subIndex++;
                            continue;
                        }

                        int subRawScore = 0;
                        LeftoverConfidence subConf = ScoreConfidence(
                            std::wstring(subName), keyword, L"", L"", true, subDepth, subRawScore);

                        if (subConf == LeftoverConfidence::Risky) {
                            BH_TRACE_BLOCKED("ScanRegSub", "risky", subName);
                            subNameLen = 512;
                            subIndex++;
                            continue;
                        }

                        LeftoverItem subItem;
                        subItem.path = fullPath + L"\\" + name + L"\\" + std::wstring(subName);
                        subItem.displayName = std::wstring(subName);
                        subItem.type = LeftoverItem::RegistryKey;
                        subItem.checked = (subConf != LeftoverConfidence::Risky);
                        subItem.confidence = subConf;
                        subItem.rawScore = subRawScore;
                        results.push_back(subItem);
                        subMatches++;

                        subNameLen = 512;
                        subIndex++;
                        subDepth++;
                    }
                    BH_REG_CLOSE(hSubKey);
                    RegCloseKey(hSubKey);
                }
            }
        }
        keyNameLen = 512;
        index++;
    }
    BH_REG_CLOSE(hKey);
    RegCloseKey(hKey);

    {
        const wchar_t* rootName = (rootKey == HKEY_CURRENT_USER ? L"HKCU" :
                                   (rootKey == HKEY_CLASSES_ROOT ? L"HKCR" : L"HKLM"));
        char _buf[512];
        snprintf(_buf, sizeof(_buf), "ScanReg[%ls\\%ls]: enumerated=%d stopWordSkip=%d moreDataSkip=%d matches=%d subMatches=%d\n",
                 rootName, subKey.c_str(), enumerated, stopWordSkip, moreDataSkip, matches, subMatches);
        OutputDebugStringA(_buf);
    }
    BH_TIMER_END_MS(t0, "ScanRegistryForLeftovers");
}

void Uninstaller::ScanStartMenu(std::vector<LeftoverItem>& results, const std::wstring& keyword) {
    wchar_t csidlPaths[][2] = {
        { CSIDL_PROGRAMS, 0 },
        { CSIDL_COMMON_PROGRAMS, 0 }
    };

    for (auto& csidl : csidlPaths) {
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, csidl[0], NULL, 0, path))) {
            ScanDirectory(path, keyword, results, ScanDepth::Advanced);
        }
    }
}

void Uninstaller::ScanDesktop(std::vector<LeftoverItem>& results, const std::wstring& keyword) {
    wchar_t paths[][2] = {
        { CSIDL_DESKTOP, 0 },
        { CSIDL_COMMON_DESKTOPDIRECTORY, 0 }
    };

    for (auto& csidl : paths) {
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, csidl[0], NULL, 0, path))) {
            std::error_code ec;
            for (auto& f : std::filesystem::directory_iterator(path, ec)) {
                if (ec) break;

                DWORD fAttr = GetFileAttributesW(f.path().c_str());
                if (fAttr != INVALID_FILE_ATTRIBUTES && (fAttr & FILE_ATTRIBUTE_REPARSE_POINT))
                    continue;

                if (f.path().extension().wstring() != L".lnk") continue;

                std::wstring name = f.path().stem().wstring();
                std::wstring nameLower = name;
                std::wstring kwLower = keyword;
                std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
                std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);

                if (nameLower.find(kwLower) != std::wstring::npos) {
                    LeftoverItem item;
                    item.path = f.path().wstring();
                    item.displayName = name;
                    item.type = LeftoverItem::File;
                    item.checked = true;
                    item.confidence = LeftoverConfidence::Safe;
                    results.push_back(item);
                }
            }
        }
    }
}

void Uninstaller::ScanAppPaths(std::vector<LeftoverItem>& results, const std::wstring& keyword) {
    const wchar_t* roots[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
        NULL
    };

    for (HKEY root : { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER }) {
        for (int i = 0; roots[i] != NULL; i++) {
            ScanRegistryForLeftovers(root, roots[i], keyword, L"", L"", results, ScanDepth::Advanced);
        }
    }
}

void Uninstaller::ScanRunKeys(std::vector<LeftoverItem>& results, const std::wstring& keyword) {
    BH_TIMER_START(t0);
    int matches = 0;
    const wchar_t* runKeys[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        NULL
    };

    for (HKEY root : { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER }) {
        for (int i = 0; runKeys[i] != NULL; i++) {
            HKEY hKey;
            if (RegOpenKeyExW(root, runKeys[i], 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;
            BH_REG_OPEN(hKey, root, runKeys[i]);

            DWORD index = 0;
            wchar_t valName[512];
            DWORD valNameLen = 512;
            wchar_t valData[4096];
            DWORD valDataLen = sizeof(valData);
            DWORD type = 0;

            while (RegEnumValueW(hKey, index, valName, &valNameLen, NULL, &type,
                                  (LPBYTE)valData, &valDataLen) == ERROR_SUCCESS) {
                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                    std::wstring data(valData, valDataLen / sizeof(wchar_t));
                    std::wstring dataLower = data;
                    std::wstring kwLower = keyword;
                    std::transform(dataLower.begin(), dataLower.end(), dataLower.begin(), ::towlower);
                    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);

                    if (dataLower.find(kwLower) != std::wstring::npos) {
                        std::wstring fullPath;
                        if (root == HKEY_CURRENT_USER)
                            fullPath = L"HKCU\\" + std::wstring(runKeys[i]);
                        else
                            fullPath = L"HKLM\\" + std::wstring(runKeys[i]);

                        LeftoverItem item;
                        item.path = fullPath + L"\\" + std::wstring(valName);
                        item.displayName = std::wstring(valName);
                        item.type = LeftoverItem::RegistryKey;
                        item.checked = true;
                        item.confidence = LeftoverConfidence::Safe;
                        results.push_back(item);
                        matches++;
                    }
                }
                valNameLen = 512;
                valDataLen = sizeof(valData);
                index++;
            }
            BH_REG_CLOSE(hKey);
            RegCloseKey(hKey);
        }
    }
    {
        char _buf[256];
        snprintf(_buf, sizeof(_buf), "ScanRunKeys: matches=%d results=%d\n", matches, (int)results.size());
        OutputDebugStringA(_buf);
    }
    BH_TIMER_END_MS(t0, "ScanRunKeys");
}

void Uninstaller::ScanServices(std::vector<LeftoverItem>& results, const std::wstring& keyword,
                                const std::wstring& publisher, const std::wstring& installPath) {
    BH_TIMER_START(t0);
    int enumerated = 0, protectedSkip = 0, matches = 0;
    const wchar_t* svcKey = L"SYSTEM\\CurrentControlSet\\Services";
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, svcKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
    BH_REG_OPEN(hKey, HKEY_LOCAL_MACHINE, svcKey);

    std::wstring kwLower = keyword;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring instLower = installPath;
    std::transform(instLower.begin(), instLower.end(), instLower.begin(), ::towlower);

    DWORD index = 0;
    wchar_t keyName[512];
    DWORD keyNameLen = 512;

    while (RegEnumKeyExW(hKey, index, keyName, &keyNameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        std::wstring name(keyName);
        enumerated++;
        HKEY hSubKey;
        std::wstring fullPath = std::wstring(svcKey) + L"\\" + name;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
            std::wstring imgPath = ReadRegString(hSubKey, L"ImagePath");
            std::wstring displayName = ReadRegString(hSubKey, L"DisplayName");
            RegCloseKey(hSubKey);

            std::wstring imgLower = imgPath;
            std::transform(imgLower.begin(), imgLower.end(), imgLower.begin(), ::towlower);

            bool isProtected = false;
            {
                std::wstring nameLower2 = name;
                std::transform(nameLower2.begin(), nameLower2.end(), nameLower2.begin(), ::towlower);
                for (int i = 0; s_protectedServices[i] != NULL; i++) {
                    std::wstring svcLower = s_protectedServices[i];
                    std::transform(svcLower.begin(), svcLower.end(), svcLower.begin(), ::towlower);
                    if (nameLower2 == svcLower) { isProtected = true; break; }
                }
            }

            if (isProtected) { protectedSkip++; keyNameLen = 512; index++; continue; }

            bool nameMatch = (imgLower.find(kwLower) != std::wstring::npos);
            bool pathMatch = (!instLower.empty() && !imgLower.empty() &&
                              (imgLower.find(instLower) != std::wstring::npos));

            if (nameMatch || pathMatch) {
                int rawScore = 0;
                LeftoverConfidence conf = ScoreConfidence(
                    name, keyword, publisher, installPath, true, 0, rawScore);
                if (pathMatch) rawScore += 8;
                if (nameMatch && pathMatch) rawScore += 2;
                if (rawScore >= 8) conf = LeftoverConfidence::Safe;
                else if (rawScore >= 4) conf = LeftoverConfidence::Moderate;
                else conf = LeftoverConfidence::Risky;

                LeftoverItem item;
                item.path = L"HKLM\\" + fullPath;
                item.displayName = name + (displayName.empty() ? L"" : L" (" + displayName + L")");
                item.type = LeftoverItem::RegistryKey;
                item.checked = (conf != LeftoverConfidence::Risky);
                item.confidence = conf;
                item.rawScore = rawScore;
                results.push_back(item);
                matches++;
            }
        }
        keyNameLen = 512;
        index++;
    }
    BH_REG_CLOSE(hKey);
    RegCloseKey(hKey);
    {
        char _buf[256];
        snprintf(_buf, sizeof(_buf), "ScanServices: enumerated=%d protectedSkip=%d matches=%d results=%d\n",
                 enumerated, protectedSkip, matches, (int)results.size());
        OutputDebugStringA(_buf);
    }
    BH_TIMER_END_MS(t0, "ScanServices");
}

void Uninstaller::ScanCOM(std::vector<LeftoverItem>& results, const std::wstring& keyword,
                           const std::wstring& publisher, const std::wstring& installPath) {
    BH_TIMER_START(t0);
    int enumerated = 0, moreDataSkip = 0, matches = 0;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
    BH_REG_OPEN(hKey, HKEY_CLASSES_ROOT, L"CLSID");

    std::wstring kwLower = keyword;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring instLower = installPath;
    std::transform(instLower.begin(), instLower.end(), instLower.begin(), ::towlower);

    DWORD index = 0;
    wchar_t keyName[512];
    DWORD keyNameLen = 512;
    DWORD ret;

    while ((ret = RegEnumKeyExW(hKey, index, keyName, &keyNameLen, NULL, NULL, NULL, NULL)) == ERROR_SUCCESS ||
           ret == ERROR_MORE_DATA) {
        if (ret == ERROR_MORE_DATA) {
            moreDataSkip++;
            keyNameLen = 512;
            index++;
            continue;
        }
        enumerated++;
        std::wstring clsid = L"CLSID\\" + std::wstring(keyName);
        HKEY hSubKey;
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, clsid.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
            BH_REG_OPEN(hSubKey, HKEY_CLASSES_ROOT, clsid.c_str());
            std::wstring desc = ReadRegString(hSubKey, L"");

            std::wstring inproc;
            HKEY hInproc = NULL;
            if (RegOpenKeyExW(hSubKey, L"InprocServer32", 0, KEY_READ, &hInproc) == ERROR_SUCCESS) {
                BH_REG_OPEN(hInproc, HKEY_CLASSES_ROOT, (clsid + L"\\InprocServer32").c_str());
                inproc = ReadRegString(hInproc, L"");
                BH_REG_CLOSE(hInproc);
                RegCloseKey(hInproc);
            }

            std::wstring localSrv;
            HKEY hLocalSrv = NULL;
            if (RegOpenKeyExW(hSubKey, L"LocalServer32", 0, KEY_READ, &hLocalSrv) == ERROR_SUCCESS) {
                BH_REG_OPEN(hLocalSrv, HKEY_CLASSES_ROOT, (clsid + L"\\LocalServer32").c_str());
                localSrv = ReadRegString(hLocalSrv, L"");
                BH_REG_CLOSE(hLocalSrv);
                RegCloseKey(hLocalSrv);
            }

            std::wstring allPaths = inproc + L" " + localSrv;
            std::wstring searchLower = desc + L" " + allPaths;
            std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), ::towlower);
            std::wstring allPathsLower = allPaths;
            std::transform(allPathsLower.begin(), allPathsLower.end(), allPathsLower.begin(), ::towlower);

            bool kwMatch = (searchLower.find(kwLower) != std::wstring::npos);
            bool pathMatch = (!instLower.empty() && !allPathsLower.empty() &&
                              (allPathsLower.find(instLower) != std::wstring::npos));

            if (kwMatch || pathMatch) {
                int rawScore = 0;
                LeftoverConfidence conf = ScoreConfidence(
                    desc.empty() ? keyName : desc, keyword, publisher, installPath, true, 0, rawScore);
                if (pathMatch) rawScore += 8;
                if (kwMatch && pathMatch) rawScore += 2;
                if (rawScore >= 8) conf = LeftoverConfidence::Safe;
                else if (rawScore >= 4) conf = LeftoverConfidence::Moderate;
                else conf = LeftoverConfidence::Risky;

                LeftoverItem item;
                item.path = L"HKCR\\" + clsid;
                item.displayName = desc.empty() ? keyName : desc;
                item.type = LeftoverItem::RegistryKey;
                item.checked = (conf != LeftoverConfidence::Risky);
                item.confidence = conf;
                item.rawScore = rawScore;
                results.push_back(item);
                matches++;
            }
            BH_REG_CLOSE(hSubKey);
            RegCloseKey(hSubKey);
        }
        keyNameLen = 512;
        index++;
    }
    BH_REG_CLOSE(hKey);
    RegCloseKey(hKey);
    {
        char _buf[256];
        snprintf(_buf, sizeof(_buf), "ScanCOM: enumerated=%d moreDataSkip=%d matches=%d results=%d\n",
                 enumerated, moreDataSkip, matches, (int)results.size());
        OutputDebugStringA(_buf);
    }
    BH_TIMER_END_MS(t0, "ScanCOM");
}

static void ScanFirewallHive(HKEY rootKey, const std::wstring& fwPath,
                              const std::wstring& kwLower,
                              const std::wstring& hivePrefix,
                              std::vector<LeftoverItem>& results) {
    HKEY hKey;
    if (RegOpenKeyExW(rootKey, fwPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

    DWORD index = 0;
    wchar_t valName[512];
    DWORD valNameLen = 512;
    BYTE valData[4096];
    DWORD valDataLen = sizeof(valData);
    DWORD type = 0;

    while (RegEnumValueW(hKey, index, valName, &valNameLen, NULL, &type,
                          valData, &valDataLen) == ERROR_SUCCESS) {
        if (type == REG_SZ) {
            std::wstring data((wchar_t*)valData, valDataLen / sizeof(wchar_t));

            std::wstring appPath;
            size_t appPos = data.find(L"|App=");
            if (appPos != std::wstring::npos) {
                size_t start = appPos + 6;
                size_t end = data.find(L'|', start);
                if (end == std::wstring::npos) end = data.length();
                appPath = data.substr(start, end - start);
            }

            bool match = false;
            int rawScore = 0;

            if (!appPath.empty()) {
                std::wstring appLower = appPath;
                std::transform(appLower.begin(), appLower.end(), appLower.begin(), ::towlower);
                std::wstring appBase = std::filesystem::path(appPath).filename().wstring();
                std::transform(appBase.begin(), appBase.end(), appBase.begin(), ::towlower);

                if (appBase.find(kwLower) != std::wstring::npos ||
                    kwLower.find(appBase) != std::wstring::npos) {
                    match = true;
                    rawScore = 12;
                } else if (appLower.find(kwLower) != std::wstring::npos ||
                           kwLower.find(appLower) != std::wstring::npos) {
                    match = true;
                    rawScore = 10;
                }
            }

            if (!match) {
                std::wstring dataLower = data;
                std::transform(dataLower.begin(), dataLower.end(), dataLower.begin(), ::towlower);
                if (dataLower.find(kwLower) != std::wstring::npos) {
                    match = true;
                    rawScore = 6;
                }
            }

            if (match) {
                LeftoverItem item;
                item.path = hivePrefix + L"\\" + fwPath + L"\\" + std::wstring(valName);
                item.displayName = std::wstring(valName);
                if (!appPath.empty()) {
                    item.displayName += L" → " + appPath;
                }
                item.type = LeftoverItem::RegistryKey;
                item.checked = false;
                int rs = rawScore;
                if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
                else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
                else item.confidence = LeftoverConfidence::Risky;
                item.rawScore = rawScore;
                results.push_back(item);
            }
        }
        valNameLen = 512;
        valDataLen = sizeof(valData);
        index++;
    }
    RegCloseKey(hKey);
}

void Uninstaller::ScanFirewallRules(std::vector<LeftoverItem>& results, const std::wstring& keyword) {
    std::wstring kwLower = keyword;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);

    const wchar_t* fwPath = L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";

    ScanFirewallHive(HKEY_LOCAL_MACHINE, fwPath, kwLower, L"HKLM", results);
    ScanFirewallHive(HKEY_CURRENT_USER, fwPath, kwLower, L"HKCU", results);
}

void Uninstaller::ScanInstallerCaches(std::vector<LeftoverItem>& results, const std::wstring& keyword) {
    const wchar_t* cachePaths[] = {
        L"C:\\Windows\\Installer\\$PatchCache$",
        L"C:\\Windows\\Installer\\$MspCache",
        NULL
    };

    for (int i = 0; cachePaths[i] != NULL; i++) {
        std::wstring path = cachePaths[i];
        if (!std::filesystem::exists(path)) continue;
        ScanDirectory(path, keyword, results, ScanDepth::Safe);
    }

    wchar_t programData[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programData))) {
        std::wstring installerDir = std::wstring(programData) + L"\\Package Cache";
        if (std::filesystem::exists(installerDir)) {
            ScanDirectory(installerDir, keyword, results, ScanDepth::Safe);
        }
    }
}

void Uninstaller::ScanPrefetch(std::vector<LeftoverItem>& results, const UninstallEntry& entry) {
    wchar_t winDir[MAX_PATH];
    if (!GetWindowsDirectoryW(winDir, MAX_PATH)) return;
    std::wstring prefetchDir = std::wstring(winDir) + L"\\Prefetch";
    if (!std::filesystem::exists(prefetchDir)) return;

    std::error_code ec;
    for (auto& f : std::filesystem::directory_iterator(prefetchDir, ec)) {
        if (ec) break;
        if (f.is_directory()) continue;
        std::wstring ext = f.path().extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
        if (ext != L".pf") continue;

        std::wstring pfName = f.path().filename().wstring();
        std::wstring pfLower = pfName;
        std::transform(pfLower.begin(), pfLower.end(), pfLower.begin(), ::towlower);

        for (auto& exe : entry.sortedExecutables) {
            std::wstring exeBase = exe;
            size_t dotPos = exeBase.find_last_of(L'.');
            if (dotPos != std::wstring::npos) exeBase = exeBase.substr(0, dotPos);

            if (pfLower.find(exeBase) != std::wstring::npos) {
                LeftoverItem item;
                item.path = f.path().wstring();
                item.displayName = pfName;
                item.type = LeftoverItem::File;
                item.checked = true;
                item.confidence = LeftoverConfidence::Safe;
                item.rawScore = 10;
                results.push_back(item);
                break;
            }
        }
    }
}

void Uninstaller::ScanWERReports(std::vector<LeftoverItem>& results, const UninstallEntry& entry) {
    wchar_t programData[MAX_PATH];
    if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programData))) return;

    const wchar_t* werPaths[] = {
        L"\\Microsoft\\Windows\\WER\\ReportArchive",
        L"\\Microsoft\\Windows\\WER\\ReportQueue",
        NULL
    };

    for (int p = 0; werPaths[p] != NULL; p++) {
        std::wstring werDir = std::wstring(programData) + werPaths[p];
        if (!std::filesystem::exists(werDir)) continue;

        std::error_code ec;
        for (auto& f : std::filesystem::directory_iterator(werDir, ec)) {
            if (ec) break;
            if (!f.is_directory()) continue;
            std::wstring dirName = f.path().filename().wstring();
            std::wstring dirLower = dirName;
            std::transform(dirLower.begin(), dirLower.end(), dirLower.begin(), ::towlower);

            for (auto& exe : entry.sortedExecutables) {
                std::wstring exeBase = exe;
                size_t dotPos = exeBase.find_last_of(L'.');
                if (dotPos != std::wstring::npos) exeBase = exeBase.substr(0, dotPos);

                if (dirLower.find(exeBase) != std::wstring::npos) {
                    LeftoverItem item;
                    item.path = f.path().wstring();
                    item.displayName = dirName;
                    item.type = LeftoverItem::Directory;
                    item.checked = true;
                    item.confidence = LeftoverConfidence::Safe;
                    item.rawScore = 8;
                    results.push_back(item);
                    break;
                }
            }
        }
    }
}

static std::wstring CompressGUID(const std::wstring& guid) {
    std::wstring result;
    result.reserve(32);
    for (wchar_t c : guid) {
        if (c == L'-' || c == L'{' || c == L'}') continue;
        result += (wchar_t)towlower(c);
    }
    return result;
}

void Uninstaller::ScanMSIUpgradeCodes(std::vector<LeftoverItem>& results, const UninstallEntry& entry) {
    if (!entry.isMsiInstaller) return;

    std::wstring registryKey = entry.registryKey;
    size_t lastSlash = registryKey.find_last_of(L'\\');
    if (lastSlash == std::wstring::npos) return;
    std::wstring productCode = registryKey.substr(lastSlash + 1);
    std::wstring compressedPC = CompressGUID(productCode);

    const wchar_t* upgradeCodesPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UpgradeCodes";
    const wchar_t* productsPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\Products";

    HKEY hUpgradeCodes;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, upgradeCodesPath, 0, KEY_READ, &hUpgradeCodes) != ERROR_SUCCESS)
        return;

    HKEY hProducts;
    bool productsOpen = RegOpenKeyExW(HKEY_LOCAL_MACHINE, productsPath, 0, KEY_READ, &hProducts) == ERROR_SUCCESS;

    DWORD ucIndex = 0;
    wchar_t upgradeCodeGuid[256];
    DWORD ucGuidLen = 256;

    while (RegEnumKeyExW(hUpgradeCodes, ucIndex, upgradeCodeGuid, &ucGuidLen,
                          NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        HKEY hUpgradeCode;
        std::wstring ucPath = std::wstring(upgradeCodesPath) + L"\\" + std::wstring(upgradeCodeGuid);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ucPath.c_str(), 0, KEY_READ, &hUpgradeCode) == ERROR_SUCCESS) {
            struct ValInfo { std::wstring name; std::wstring data; };
            std::vector<ValInfo> allVals;

            DWORD valIndex = 0;
            wchar_t valName[256];
            DWORD valNameLen = 256;
            BYTE valData[512];
            DWORD valDataLen = sizeof(valData);
            DWORD valType = 0;

            while (RegEnumValueW(hUpgradeCode, valIndex, valName, &valNameLen, NULL,
                                  &valType, valData, &valDataLen) == ERROR_SUCCESS) {
                if (valType == REG_SZ || valType == REG_MULTI_SZ) {
                    std::wstring dataStr((wchar_t*)valData, valDataLen / sizeof(wchar_t));
                    allVals.push_back({ std::wstring(valName), dataStr });
                }
                valNameLen = 256;
                valDataLen = sizeof(valData);
                valIndex++;
            }
            RegCloseKey(hUpgradeCode);

            bool foundOurProduct = false;
            for (auto& v : allVals) {
                std::wstring vCompressed = CompressGUID(v.data);
                if (vCompressed == compressedPC) {
                    foundOurProduct = true;
                    break;
                }
            }

            if (foundOurProduct && productsOpen) {
                for (auto& v : allVals) {
                    std::wstring vCompressed = CompressGUID(v.data);
                    if (vCompressed == compressedPC) continue;

                    HKEY hProduct;
                    if (RegOpenKeyExW(hProducts, v.data.c_str(), 0, KEY_READ, &hProduct) == ERROR_SUCCESS) {
                        wchar_t productName[512];
                        DWORD productNameLen = sizeof(productName);
                        if (RegQueryValueExW(hProduct, L"ProductName", NULL, NULL,
                                              (LPBYTE)productName, &productNameLen) == ERROR_SUCCESS) {
                            LeftoverItem item;
                            item.path = L"HKLM\\" + std::wstring(productsPath) + L"\\" + v.data;
                            item.displayName = std::wstring(productName, productNameLen / sizeof(wchar_t));
                            item.displayName += L" (MSI related)";
                            item.type = LeftoverItem::RegistryKey;
                            item.checked = false;
                            item.confidence = LeftoverConfidence::Moderate;
                            item.rawScore = 6;
                            results.push_back(item);
                        }
                        RegCloseKey(hProduct);
                    }
                }
            }
        }
        ucGuidLen = 256;
        ucIndex++;
    }
    if (productsOpen) RegCloseKey(hProducts);
    RegCloseKey(hUpgradeCodes);
}

std::wstring ROT13(const std::wstring& input) {
    std::wstring result = input;
    for (wchar_t& c : result) {
        if (c >= L'a' && c <= L'z') {
            c = L'a' + ((c - L'a' + 13) % 26);
        } else if (c >= L'A' && c <= L'Z') {
            c = L'A' + ((c - L'A' + 13) % 26);
        }
    }
    return result;
}

void Uninstaller::ScanUserAssist(std::vector<LeftoverItem>& results, const UninstallEntry& entry) {
    const wchar_t* uaRoot = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
    HKEY hRoot;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, uaRoot, 0, KEY_READ, &hRoot) != ERROR_SUCCESS) return;

    std::wstring kwLower = entry.displayName;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring pubLower = entry.publisher;
    std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);

    std::wstring exeList;
    for (auto& exe : entry.sortedExecutables)
        exeList += exe + L" ";
    std::wstring exeLower = exeList;
    std::transform(exeLower.begin(), exeLower.end(), exeLower.begin(), ::towlower);

    DWORD guidIndex = 0;
    wchar_t guidName[256];
    DWORD guidNameLen = 256;

    while (RegEnumKeyExW(hRoot, guidIndex, guidName, &guidNameLen,
                          NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        HKEY hGuid;
        std::wstring guidPath = std::wstring(uaRoot) + L"\\" + std::wstring(guidName);
        if (RegOpenKeyExW(HKEY_CURRENT_USER, guidPath.c_str(), 0, KEY_READ, &hGuid) == ERROR_SUCCESS) {
            HKEY hCount;
            if (RegOpenKeyExW(hGuid, L"Count", 0, KEY_READ, &hCount) == ERROR_SUCCESS) {
                DWORD valIndex = 0;
                wchar_t valName[1024];
                DWORD valNameLen = sizeof(valName) / sizeof(wchar_t);
                BYTE valData[4096];
                DWORD valDataLen = sizeof(valData);
                DWORD valType = 0;

                while (RegEnumValueW(hCount, valIndex, valName, &valNameLen, NULL,
                                      &valType, valData, &valDataLen) == ERROR_SUCCESS) {
                    if (valType == REG_BINARY && valDataLen > 12) {
                        std::wstring decoded = ROT13(std::wstring(valName));
                        std::wstring decLower = decoded;
                        std::transform(decLower.begin(), decLower.end(), decLower.begin(), ::towlower);

                        bool match = false;
                        int rawScore = 0;

                        for (auto& exe : entry.sortedExecutables) {
                            if (decLower.find(exe) != std::wstring::npos) {
                                match = true;
                                rawScore = 14;
                                break;
                            }
                        }

                        if (!match && !kwLower.empty() &&
                            (decLower.find(kwLower) != std::wstring::npos ||
                             kwLower.find(decLower) != std::wstring::npos)) {
                            match = true;
                            rawScore = 10;
                        }

                        if (!match && !pubLower.empty() &&
                            decLower.find(pubLower) != std::wstring::npos) {
                            match = true;
                            rawScore = 8;
                        }

                        if (!match && !exeLower.empty()) {
                            size_t pos = decLower.find(L"\\");
                            while (pos != std::wstring::npos) {
                                std::wstring seg = decLower.substr(pos + 1);
                                size_t nextPos = seg.find(L"\\");
                                if (nextPos != std::wstring::npos) seg = seg.substr(0, nextPos);
                                if (exeLower.find(seg) != std::wstring::npos && seg.length() > 3) {
                                    match = true;
                                    rawScore = 7;
                                    break;
                                }
                                pos = decLower.find(L"\\", pos + 1);
                            }
                        }

                        if (match) {
                            DWORD runCount = *(DWORD*)(valData + 4);
                            FILETIME* ft = (FILETIME*)(valData + 8);

                            LeftoverItem item;
                            item.path = L"HKCU\\" + guidPath + L"\\Count\\" + std::wstring(valName);
                            item.displayName = decoded;
                            item.displayName += L" (UA runs:" + std::to_wstring(runCount) + L")";
                            item.type = LeftoverItem::RegistryKey;
                            item.checked = false;
                            int rs = rawScore;
                            if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
                            else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
                            else item.confidence = LeftoverConfidence::Risky;
                            item.rawScore = rawScore;
                            results.push_back(item);
                        }
                    }
                    valNameLen = sizeof(valName) / sizeof(wchar_t);
                    valDataLen = sizeof(valData);
                    valIndex++;
                }
                RegCloseKey(hCount);
            }
            RegCloseKey(hGuid);
        }
        guidNameLen = 256;
        guidIndex++;
    }
    RegCloseKey(hRoot);
}

void Uninstaller::ScanEventLog(std::vector<LeftoverItem>& results, const UninstallEntry& entry) {
    std::wstring kwLower = entry.displayName;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring pubLower = entry.publisher;
    std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);

    const wchar_t* logPath = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application";
    HKEY hLogRoot;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, logPath, 0, KEY_READ, &hLogRoot) != ERROR_SUCCESS) return;

    DWORD srcIndex = 0;
    wchar_t srcName[256];
    DWORD srcNameLen = 256;

    while (RegEnumKeyExW(hLogRoot, srcIndex, srcName, &srcNameLen,
                          NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        std::wstring srcLower = srcName;
        std::transform(srcLower.begin(), srcLower.end(), srcLower.begin(), ::towlower);

        bool match = false;
        int rawScore = 0;

        if (!kwLower.empty() &&
            (srcLower.find(kwLower) != std::wstring::npos ||
             kwLower.find(srcLower) != std::wstring::npos)) {
            match = true;
            rawScore = 8;
        }

        if (!match && !pubLower.empty() &&
            srcLower.find(pubLower) != std::wstring::npos) {
            match = true;
            rawScore = 6;
        }

        if (!match) {
            for (auto& exe : entry.sortedExecutables) {
                if (srcLower.find(exe) != std::wstring::npos) {
                    match = true;
                    rawScore = 10;
                    break;
                }
            }
        }

        if (match) {
            HKEY hSrc;
            std::wstring srcPath = std::wstring(logPath) + L"\\" + std::wstring(srcName);
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, srcPath.c_str(), 0, KEY_READ, &hSrc) == ERROR_SUCCESS) {
                DWORD categoryCount = 0;
                DWORD eventCount = 0;
                DWORD typesSupported = 0;
                DWORD dataSize = sizeof(DWORD);

                RegQueryValueExW(hSrc, L"CategoryCount", NULL, NULL,
                                  (LPBYTE)&categoryCount, &dataSize);
                RegQueryValueExW(hSrc, L"EventMessageFile", NULL, NULL, NULL, NULL);
                RegQueryValueExW(hSrc, L"TypesSupported", NULL, NULL,
                                  (LPBYTE)&typesSupported, &dataSize);

                LeftoverItem item;
                item.path = L"HKLM\\" + srcPath;
                item.displayName = std::wstring(srcName);
                item.displayName += L" (evtsrc)";
                item.type = LeftoverItem::RegistryKey;
                item.checked = false;
                int rs = rawScore;
                if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
                else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
                else item.confidence = LeftoverConfidence::Risky;
                item.rawScore = rawScore;
                results.push_back(item);
                RegCloseKey(hSrc);
            }
        }
        srcNameLen = 256;
        srcIndex++;
    }
    RegCloseKey(hLogRoot);
}

void Uninstaller::ScanAppCompatFlags(std::vector<LeftoverItem>& results, const UninstallEntry& entry) {
    std::wstring kwLower = entry.displayName;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring pubLower = entry.publisher;
    std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);

    const wchar_t* compatPaths[] = {
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Databases",
    };

    for (auto* compatPath : compatPaths) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, compatPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;

        DWORD index = 0;
        wchar_t valName[2048];
        DWORD valNameLen = sizeof(valName) / sizeof(wchar_t);
        BYTE valData[4096];
        DWORD valDataLen = sizeof(valData);
        DWORD valType = 0;

        while (RegEnumValueW(hKey, index, valName, &valNameLen, NULL,
                              &valType, valData, &valDataLen) == ERROR_SUCCESS) {
            std::wstring searchTarget;
            if (valType == REG_SZ || valType == REG_EXPAND_SZ) {
                searchTarget = std::wstring((wchar_t*)valData, valDataLen / sizeof(wchar_t));
            }

            std::wstring nameLower = valName;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
            std::wstring dataLower = searchTarget;
            std::transform(dataLower.begin(), dataLower.end(), dataLower.begin(), ::towlower);

            bool match = false;
            int rawScore = 0;

            for (auto& exe : entry.sortedExecutables) {
                if (nameLower.find(exe) != std::wstring::npos ||
                    dataLower.find(exe) != std::wstring::npos) {
                    match = true;
                    rawScore = 12;
                    break;
                }
            }

            if (!match && !kwLower.empty()) {
                if (nameLower.find(kwLower) != std::wstring::npos ||
                    dataLower.find(kwLower) != std::wstring::npos) {
                    match = true;
                    rawScore = 8;
                }
            }

            if (!match && !pubLower.empty() &&
                (nameLower.find(pubLower) != std::wstring::npos ||
                 dataLower.find(pubLower) != std::wstring::npos)) {
                match = true;
                rawScore = 6;
            }

            if (match) {
                LeftoverItem item;
                item.path = L"HKLM\\" + std::wstring(compatPath) + L"\\" + std::wstring(valName);
                item.displayName = std::wstring(valName);
                if (!searchTarget.empty()) {
                    item.displayName += L" → " + searchTarget;
                }
                item.displayName += L" (compat)";
                item.type = LeftoverItem::RegistryKey;
                item.checked = false;
                int rs = rawScore;
                if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
                else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
                else item.confidence = LeftoverConfidence::Risky;
                item.rawScore = rawScore;
                results.push_back(item);
            }
            valNameLen = sizeof(valName) / sizeof(wchar_t);
            valDataLen = sizeof(valData);
            index++;
        }
        RegCloseKey(hKey);
    }

    HKEY hCUCompat;
    const wchar_t* cuCompatPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers";
    if (RegOpenKeyExW(HKEY_CURRENT_USER, cuCompatPath, 0, KEY_READ, &hCUCompat) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t valName[2048];
        DWORD valNameLen = sizeof(valName) / sizeof(wchar_t);
        BYTE valData[4096];
        DWORD valDataLen = sizeof(valData);
        DWORD valType = 0;

        while (RegEnumValueW(hCUCompat, index, valName, &valNameLen, NULL,
                              &valType, valData, &valDataLen) == ERROR_SUCCESS) {
            std::wstring searchTarget;
            if (valType == REG_SZ || valType == REG_EXPAND_SZ) {
                searchTarget = std::wstring((wchar_t*)valData, valDataLen / sizeof(wchar_t));
            }

            std::wstring nameLower = valName;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
            std::wstring dataLower = searchTarget;
            std::transform(dataLower.begin(), dataLower.end(), dataLower.begin(), ::towlower);

            bool match = false;
            int rawScore = 0;

            for (auto& exe : entry.sortedExecutables) {
                if (nameLower.find(exe) != std::wstring::npos ||
                    dataLower.find(exe) != std::wstring::npos) {
                    match = true;
                    rawScore = 12;
                    break;
                }
            }

            if (!match && !kwLower.empty()) {
                if (nameLower.find(kwLower) != std::wstring::npos ||
                    dataLower.find(kwLower) != std::wstring::npos) {
                    match = true;
                    rawScore = 8;
                }
            }

            if (!match && !pubLower.empty() &&
                (nameLower.find(pubLower) != std::wstring::npos ||
                 dataLower.find(pubLower) != std::wstring::npos)) {
                match = true;
                rawScore = 6;
            }

            if (match) {
                LeftoverItem item;
                item.path = L"HKCU\\" + std::wstring(cuCompatPath) + L"\\" + std::wstring(valName);
                item.displayName = std::wstring(valName);
                if (!searchTarget.empty()) {
                    item.displayName += L" → " + searchTarget;
                }
                item.displayName += L" (compat)";
                item.type = LeftoverItem::RegistryKey;
                item.checked = false;
                int rs = rawScore;
                if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
                else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
                else item.confidence = LeftoverConfidence::Risky;
                item.rawScore = rawScore;
                results.push_back(item);
            }
            valNameLen = sizeof(valName) / sizeof(wchar_t);
            valDataLen = sizeof(valData);
            index++;
        }
        RegCloseKey(hCUCompat);
    }
}

void Uninstaller::ScanCOMDeep(std::vector<LeftoverItem>& results, const std::wstring& keyword) {
    std::wstring kwLower = keyword;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);

    HKEY hCLSID;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hCLSID) != ERROR_SUCCESS) return;

    DWORD clsidIndex = 0;
    wchar_t clsidName[256];
    DWORD clsidNameLen = 256;

    while (RegEnumKeyExW(hCLSID, clsidIndex, clsidName, &clsidNameLen,
                          NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        std::wstring clsidPath = std::wstring(L"CLSID\\") + std::wstring(clsidName);
        HKEY hClsid;
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, clsidPath.c_str(), 0, KEY_READ, &hClsid) == ERROR_SUCCESS) {
            std::wstring desc = ReadRegString(hClsid, L"");
            HKEY hInproc = NULL;
            std::wstring inproc32;
            if (RegOpenKeyExW(hClsid, L"InprocServer32", 0, KEY_READ, &hInproc) == ERROR_SUCCESS) {
                inproc32 = ReadRegString(hInproc, L"");
                RegCloseKey(hInproc);
            }

            HKEY hLocalSrv = NULL;
            std::wstring localSrv32;
            if (RegOpenKeyExW(hClsid, L"LocalServer32", 0, KEY_READ, &hLocalSrv) == ERROR_SUCCESS) {
                localSrv32 = ReadRegString(hLocalSrv, L"");
                RegCloseKey(hLocalSrv);
            }

            std::wstring searchLower = desc + L" " + inproc32 + L" " + localSrv32;
            std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), ::towlower);

            if (searchLower.find(kwLower) != std::wstring::npos) {
                int rawScore = 10;
                LeftoverItem item;
                item.path = L"HKCR\\" + clsidPath;
                item.displayName = desc.empty() ? clsidName : desc;
                item.displayName += L" (COM)";
                item.type = LeftoverItem::RegistryKey;
                item.checked = false;
                int rs = rawScore;
                if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
                else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
                else item.confidence = LeftoverConfidence::Risky;
                item.rawScore = rawScore;
                results.push_back(item);

                std::wstring progID = ReadRegString(hClsid, L"ProgID");
                if (!progID.empty()) {
                    std::wstring progLower = progID;
                    std::transform(progLower.begin(), progLower.end(), progLower.begin(), ::towlower);
                    if (progLower.find(kwLower) != std::wstring::npos ||
                        kwLower.find(progLower) != std::wstring::npos) {
                        LeftoverItem pidItem;
                        pidItem.path = L"HKCR\\" + progID;
                        pidItem.displayName = progID + L" (ProgID)";
                        pidItem.type = LeftoverItem::RegistryKey;
                        pidItem.checked = false;
                        pidItem.confidence = LeftoverConfidence::Safe;
                        pidItem.rawScore = 10;
                        results.push_back(pidItem);

                        HKEY hProgVer;
                        std::wstring progVerPath = progID + L"\\CurVer";
                        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, progVerPath.c_str(), 0, KEY_READ, &hProgVer) == ERROR_SUCCESS) {
                            std::wstring curVer = ReadRegString(hProgVer, L"");
                            if (!curVer.empty()) {
                                LeftoverItem cvItem;
                                cvItem.path = L"HKCR\\" + progVerPath;
                                cvItem.displayName = curVer + L" (CurVer)";
                                cvItem.type = LeftoverItem::RegistryKey;
                                cvItem.checked = false;
                                cvItem.confidence = LeftoverConfidence::Safe;
                                cvItem.rawScore = 9;
                                results.push_back(cvItem);
                            }
                            RegCloseKey(hProgVer);
                        }
                    }
                }

                std::wstring VersionIndep = ReadRegString(hClsid, L"VersionIndependentProgID");
                if (!VersionIndep.empty()) {
                    std::wstring vipLower = VersionIndep;
                    std::transform(vipLower.begin(), vipLower.end(), vipLower.begin(), ::towlower);
                    if (vipLower.find(kwLower) != std::wstring::npos ||
                        kwLower.find(vipLower) != std::wstring::npos) {
                        LeftoverItem vipItem;
                        vipItem.path = L"HKCR\\" + VersionIndep;
                        vipItem.displayName = VersionIndep + L" (VersionIndepProgID)";
                        vipItem.type = LeftoverItem::RegistryKey;
                        vipItem.checked = false;
                        vipItem.confidence = LeftoverConfidence::Safe;
                        vipItem.rawScore = 10;
                        results.push_back(vipItem);
                    }
                }

                HKEY hTypeLib;
                if (RegOpenKeyExW(hClsid, L"TypeLib", 0, KEY_READ, &hTypeLib) == ERROR_SUCCESS) {
                    DWORD tlIndex = 0;
                    wchar_t tlName[256];
                    DWORD tlNameLen = 256;
                    while (RegEnumKeyExW(hTypeLib, tlIndex, tlName, &tlNameLen,
                                          NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                        std::wstring tlPath = std::wstring(L"TypeLib\\") + std::wstring(tlName);
                        HKEY hTL;
                        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, tlPath.c_str(), 0, KEY_READ, &hTL) == ERROR_SUCCESS) {
                            HKEY hVer;
                            DWORD verIdx = 0;
                            wchar_t verName[256];
                            DWORD verNameLen = 256;
                            while (RegEnumKeyExW(hTL, verIdx, verName, &verNameLen,
                                                  NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                                HKEY hVer;
                                std::wstring verPath = tlPath + L"\\" + std::wstring(verName);
                                if (RegOpenKeyExW(HKEY_CLASSES_ROOT, verPath.c_str(), 0, KEY_READ, &hVer) == ERROR_SUCCESS) {
                                    std::wstring tlDesc = ReadRegString(hVer, L"");
                                    std::wstring tlFlags = ReadRegString(hVer, L"Flags");
                                    std::wstring verSearch = tlDesc + L" " + std::wstring(verName);
                                    std::wstring verSearchLower = verSearch;
                                    std::transform(verSearchLower.begin(), verSearchLower.end(),
                                                    verSearchLower.begin(), ::towlower);

                                    if (verSearchLower.find(kwLower) != std::wstring::npos) {
                                        LeftoverItem tlItem;
                                        tlItem.path = L"HKCR\\" + verPath;
                                        tlItem.displayName = tlDesc.empty() ? (std::wstring(tlName) + L"\\" + std::wstring(verName)) : tlDesc;
                                        tlItem.displayName += L" (TypeLib)";
                                        tlItem.type = LeftoverItem::RegistryKey;
                                        tlItem.checked = false;
                                        tlItem.confidence = LeftoverConfidence::Moderate;
                                        tlItem.rawScore = 7;
                                        results.push_back(tlItem);
                                    }
                                    RegCloseKey(hVer);
                                }
                                verNameLen = 256;
                                verIdx++;
                            }
                            RegCloseKey(hTL);
                        }
                        tlNameLen = 256;
                        tlIndex++;
                    }
                    RegCloseKey(hTypeLib);
                }

                HKEY hInterfaces;
                if (RegOpenKeyExW(hClsid, L"Implemented Categories", 0, KEY_READ, &hInterfaces) == ERROR_SUCCESS) {
                    RegCloseKey(hInterfaces);
                }
            }
            RegCloseKey(hClsid);
        }
        clsidNameLen = 256;
        clsidIndex++;
    }
    RegCloseKey(hCLSID);

    HKEY hTypeLibRoot;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"TypeLib", 0, KEY_READ, &hTypeLibRoot) == ERROR_SUCCESS) {
        DWORD tlIndex = 0;
        wchar_t tlName[256];
        DWORD tlNameLen = 256;
        while (RegEnumKeyExW(hTypeLibRoot, tlIndex, tlName, &tlNameLen,
                              NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            std::wstring tlPath = std::wstring(L"TypeLib\\") + std::wstring(tlName);
            HKEY hTL;
            if (RegOpenKeyExW(HKEY_CLASSES_ROOT, tlPath.c_str(), 0, KEY_READ, &hTL) == ERROR_SUCCESS) {
                HKEY hVer;
                DWORD verIdx = 0;
                wchar_t verName[256];
                DWORD verNameLen = 256;
                while (RegEnumKeyExW(hTL, verIdx, verName, &verNameLen,
                                      NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    std::wstring verPath = tlPath + L"\\" + std::wstring(verName);
                    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, verPath.c_str(), 0, KEY_READ, &hVer) == ERROR_SUCCESS) {
                        std::wstring tlDesc = ReadRegString(hVer, L"");
                        std::wstring helpDir = ReadRegString(hVer, L"HelpDir");

                        std::wstring tlSearch = tlDesc + L" " + helpDir;
                        std::wstring tlSearchLower = tlSearch;
                        std::transform(tlSearchLower.begin(), tlSearchLower.end(),
                                        tlSearchLower.begin(), ::towlower);

                        if (tlSearchLower.find(kwLower) != std::wstring::npos) {
                            LeftoverItem tlItem;
                            tlItem.path = L"HKCR\\" + verPath;
                            tlItem.displayName = tlDesc.empty() ? (std::wstring(tlName) + L"\\" + std::wstring(verName)) : tlDesc;
                            tlItem.displayName += L" (TypeLib)";
                            tlItem.type = LeftoverItem::RegistryKey;
                            tlItem.checked = false;
                            tlItem.confidence = LeftoverConfidence::Moderate;
                            tlItem.rawScore = 7;
                            results.push_back(tlItem);
                        }
                        RegCloseKey(hVer);
                    }
                    verNameLen = 256;
                    verIdx++;
                }
                RegCloseKey(hTL);
            }
            tlNameLen = 256;
            tlIndex++;
        }
        RegCloseKey(hTypeLibRoot);
    }
}

void Uninstaller::ScanProgramFilesOrphans(std::vector<LeftoverItem>& results, const UninstallEntry& entry) {
    std::wstring kwLower = entry.displayName;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring pubLower = entry.publisher;
    std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);

    wchar_t pfBuf[MAX_PATH], pf86Buf[MAX_PATH];
    std::wstring programFiles, programFilesX86;

    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, 0, pfBuf)))
        programFiles = pfBuf;
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, pf86Buf)))
        programFilesX86 = pf86Buf;

    auto scanPFDir = [&](const std::wstring& pfDir) {
        if (pfDir.empty() || !std::filesystem::exists(pfDir)) return;

        std::error_code ec;
        for (auto& dirEntry : std::filesystem::directory_iterator(pfDir, ec)) {
            if (ec) break;
            if (!dirEntry.is_directory()) continue;

            std::wstring dirName = dirEntry.path().filename().wstring();
            std::wstring dirLower = dirName;
            std::transform(dirLower.begin(), dirLower.end(), dirLower.begin(), ::towlower);

            bool nameMatch = false;
            bool pubMatch = false;
            bool execMatch = false;
            int rawScore = 0;

            if (!kwLower.empty() &&
                (dirLower.find(kwLower) != std::wstring::npos ||
                 kwLower.find(dirLower) != std::wstring::npos)) {
                nameMatch = true;
                rawScore = 8;
            }

            if (!nameMatch && !pubLower.empty() &&
                (dirLower.find(pubLower) != std::wstring::npos ||
                 pubLower.find(dirLower) != std::wstring::npos)) {
                pubMatch = true;
                rawScore = 6;
            }

            if (!nameMatch && !pubMatch) {
                for (auto& exe : entry.sortedExecutables) {
                    std::wstring exeBase = exe;
                    size_t dotPos = exeBase.rfind(L'.');
                    if (dotPos != std::wstring::npos) exeBase = exeBase.substr(0, dotPos);
                    if (dirLower.find(exeBase) != std::wstring::npos ||
                        exeBase.find(dirLower) != std::wstring::npos) {
                        execMatch = true;
                        rawScore = 10;
                        break;
                    }
                }
            }

            if (nameMatch || pubMatch || execMatch) {
                LeftoverItem item;
                item.path = dirEntry.path().wstring();
                item.displayName = dirName;

                DWORD fileCount = 0;
                uint64_t totalSize = 0;
                std::error_code sizeEc;
                for (auto& f : std::filesystem::recursive_directory_iterator(dirEntry.path(), sizeEc)) {
                    if (sizeEc) break;
                    fileCount++;
                    totalSize += f.file_size(sizeEc);
                }

                item.displayName += L" (" + std::to_wstring(fileCount) + L" files, " +
                                     std::to_wstring(totalSize / 1024) + L" KB)";
                item.type = LeftoverItem::Directory;
                item.checked = false;

                bool exeFoundInDir = false;
                std::error_code exEc;
                for (auto& f : std::filesystem::recursive_directory_iterator(dirEntry.path(), exEc)) {
                    if (exEc) break;
                    std::wstring fExt = f.path().extension().wstring();
                    std::transform(fExt.begin(), fExt.end(), fExt.begin(), ::towlower);
                    if (fExt == L".exe" || fExt == L".dll") {
                        std::wstring fBase = f.path().filename().wstring();
                        std::transform(fBase.begin(), fBase.end(), fBase.begin(), ::towlower);
                        for (auto& exe : entry.sortedExecutables) {
                            if (fBase == exe) {
                                exeFoundInDir = true;
                                break;
                            }
                        }
                        if (exeFoundInDir) break;
                    }
                }

                if (exeFoundInDir) {
                    rawScore += 6;
                }

                bool dirUsedByOthers = false;
                if (m_cachedApps.empty()) m_cachedApps = ScanInstalled();
                for (auto& other : m_cachedApps) {
                    if (other.displayName == entry.displayName) continue;
                    if (!other.installPath.empty()) {
                        std::wstring otherLower = other.installPath;
                        std::transform(otherLower.begin(), otherLower.end(), otherLower.begin(), ::towlower);
                        std::wstring itemLower = item.path;
                        std::transform(itemLower.begin(), itemLower.end(), itemLower.begin(), ::towlower);
                        if (otherLower.find(itemLower) != std::wstring::npos ||
                            itemLower.find(otherLower) != std::wstring::npos) {
                            dirUsedByOthers = true;
                            break;
                        }
                    }
                }

                if (dirUsedByOthers) {
                    rawScore -= 8;
                }

                int rs = rawScore;
                if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
                else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
                else item.confidence = LeftoverConfidence::Risky;
                item.rawScore = rawScore;
                results.push_back(item);
            }
        }
    };

    scanPFDir(programFiles);
    scanPFDir(programFilesX86);

    wchar_t appDataLocal[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataLocal))) {
        std::wstring localApps = std::wstring(appDataLocal) + L"\\Programs";
        scanPFDir(localApps);
    }
}

void Uninstaller::ScanAudioPolicyConfig(std::vector<LeftoverItem>& results, const UninstallEntry& entry) {
    std::wstring kwLower = entry.displayName;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring pubLower = entry.publisher;
    std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);

    const wchar_t* apcPath = L"SOFTWARE\\Microsoft\\Internet Explorer\\LowRegistry\\Audio\\PolicyConfig\\PropertyStore";
    HKEY hRoot;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, apcPath, 0, KEY_READ, &hRoot) != ERROR_SUCCESS) return;

    DWORD idx = 0;
    wchar_t keyName[256];
    DWORD keyNameLen = 256;

    while (RegEnumKeyExW(hRoot, idx, keyName, &keyNameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        std::wstring subPath = std::wstring(apcPath) + L"\\" + std::wstring(keyName);
        HKEY hSub;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath.c_str(), 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            DWORD valIdx = 0;
            wchar_t valName[512];
            DWORD valNameLen = sizeof(valName) / sizeof(wchar_t);
            BYTE valData[4096];
            DWORD valDataLen = sizeof(valData);
            DWORD valType = 0;

            while (RegEnumValueW(hSub, valIdx, valName, &valNameLen, NULL,
                                  &valType, valData, &valDataLen) == ERROR_SUCCESS) {
                if (valType == REG_BINARY || valType == REG_SZ) {
                    std::wstring dataStr;
                    if (valType == REG_SZ) {
                        dataStr = std::wstring((wchar_t*)valData, valDataLen / sizeof(wchar_t));
                    } else {
                        dataStr = std::wstring((wchar_t*)valData, valDataLen / sizeof(wchar_t));
                    }

                    std::wstring dataLower = dataStr;
                    std::transform(dataLower.begin(), dataLower.end(), dataLower.begin(), ::towlower);

                    bool match = false;
                    int rawScore = 0;

                    for (auto& exe : entry.sortedExecutables) {
                        if (dataLower.find(exe) != std::wstring::npos) {
                            match = true;
                            rawScore = 10;
                            break;
                        }
                    }

                    if (!match && !kwLower.empty()) {
                        if (dataLower.find(kwLower) != std::wstring::npos ||
                            kwLower.find(dataLower) != std::wstring::npos) {
                            match = true;
                            rawScore = 8;
                        }
                    }

                    if (!match && !pubLower.empty() &&
                        dataLower.find(pubLower) != std::wstring::npos) {
                        match = true;
                        rawScore = 6;
                    }

                    if (match) {
                        LeftoverItem item;
                        item.path = L"HKLM\\" + subPath + L"\\" + std::wstring(valName);
                        item.displayName = std::wstring(valName);
                        item.displayName += L" (audiopolicy)";
                        item.type = LeftoverItem::RegistryKey;
                        item.checked = false;
                        int rs = rawScore;
                        if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
                        else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
                        else item.confidence = LeftoverConfidence::Risky;
                        item.rawScore = rawScore;
                        results.push_back(item);
                    }
                }
                valNameLen = sizeof(valName) / sizeof(wchar_t);
                valDataLen = sizeof(valData);
                valIdx++;
            }
            RegCloseKey(hSub);
        }
        keyNameLen = 256;
        idx++;
    }
    RegCloseKey(hRoot);
}

void Uninstaller::ScanHeapLeakDetection(std::vector<LeftoverItem>& results, const UninstallEntry& entry) {
    std::wstring kwLower = entry.displayName;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring pubLower = entry.publisher;
    std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);

    const wchar_t* radPath = L"SOFTWARE\\Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications";
    HKEY hRoot;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, radPath, 0, KEY_READ, &hRoot) != ERROR_SUCCESS) return;

    DWORD idx = 0;
    wchar_t keyName[256];
    DWORD keyNameLen = 256;

    while (RegEnumKeyExW(hRoot, idx, keyName, &keyNameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        std::wstring appKey(keyName);
        std::wstring appLower = appKey;
        std::transform(appLower.begin(), appLower.end(), appLower.begin(), ::towlower);

        bool match = false;
        int rawScore = 0;

        for (auto& exe : entry.sortedExecutables) {
            if (appLower.find(exe) != std::wstring::npos) {
                match = true;
                rawScore = 12;
                break;
            }
        }

        if (!match && !kwLower.empty()) {
            if (appLower.find(kwLower) != std::wstring::npos ||
                kwLower.find(appLower) != std::wstring::npos) {
                match = true;
                rawScore = 8;
            }
        }

        if (!match && !pubLower.empty() &&
            appLower.find(pubLower) != std::wstring::npos) {
            match = true;
            rawScore = 6;
        }

        if (match) {
            std::wstring fullPath = std::wstring(radPath) + L"\\" + appKey;
            HKEY hApp;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_READ, &hApp) == ERROR_SUCCESS) {
                DWORD lastRunTime = ReadRegDword(hApp, L"LastRunTime");
                RegCloseKey(hApp);

                LeftoverItem item;
                item.path = L"HKLM\\" + fullPath;
                item.displayName = appKey;
                item.displayName += L" (heapleak)";
                item.type = LeftoverItem::RegistryKey;
                item.checked = false;
                int rs = rawScore;
                if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
                else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
                else item.confidence = LeftoverConfidence::Risky;
                item.rawScore = rawScore;
                results.push_back(item);
            }
        }
        keyNameLen = 256;
        idx++;
    }
    RegCloseKey(hRoot);
}

void Uninstaller::ScanInstallerFolders(std::vector<LeftoverItem>& results, const UninstallEntry& entry) {
    std::wstring kwLower = entry.displayName;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring pubLower = entry.publisher;
    std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);

    const wchar_t* ifPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\Folders";
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ifPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

    DWORD idx = 0;
    wchar_t valName[1024];
    DWORD valNameLen = sizeof(valName) / sizeof(wchar_t);
    wchar_t valData[4096];
    DWORD valDataLen = sizeof(valData);
    DWORD valType = 0;

    while (RegEnumValueW(hKey, idx, valName, &valNameLen, NULL,
                          &valType, (LPBYTE)valData, &valDataLen) == ERROR_SUCCESS) {
        if (valType == REG_SZ || valType == REG_EXPAND_SZ) {
            std::wstring folderPath(valData, valDataLen / sizeof(wchar_t));
            std::wstring folderLower = folderPath;
            std::transform(folderLower.begin(), folderLower.end(), folderLower.begin(), ::towlower);

            std::wstring nameLower = valName;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);

            bool match = false;
            int rawScore = 0;

            if (!entry.installPath.empty()) {
                std::wstring instLower = entry.installPath;
                std::transform(instLower.begin(), instLower.end(), instLower.begin(), ::towlower);
                if (!instLower.empty() && folderLower.find(instLower) != std::wstring::npos) {
                    match = true;
                    rawScore = 10;
                }
            }

            if (!match && !kwLower.empty()) {
                if (folderLower.find(kwLower) != std::wstring::npos ||
                    kwLower.find(folderLower) != std::wstring::npos ||
                    nameLower.find(kwLower) != std::wstring::npos) {
                    match = true;
                    rawScore = 8;
                }
            }

            if (!match && !pubLower.empty()) {
                if (folderLower.find(pubLower) != std::wstring::npos ||
                    nameLower.find(pubLower) != std::wstring::npos) {
                    match = true;
                    rawScore = 6;
                }
            }

            if (match) {
                LeftoverItem item;
                item.path = L"HKLM\\" + std::wstring(ifPath) + L"\\" + std::wstring(valName);
                item.displayName = std::wstring(valName);
                item.displayName += L" → " + folderPath;
                item.displayName += L" (installfolder)";
                item.type = LeftoverItem::RegistryKey;
                item.checked = false;
                int rs = rawScore;
                if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
                else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
                else item.confidence = LeftoverConfidence::Risky;
                item.rawScore = rawScore;
                results.push_back(item);
            }
        }
        valNameLen = sizeof(valName) / sizeof(wchar_t);
        valDataLen = sizeof(valData);
        idx++;
    }
    RegCloseKey(hKey);
}

void Uninstaller::ScanDebugTracing(std::vector<LeftoverItem>& results, const UninstallEntry& entry) {
    std::wstring kwLower = entry.displayName;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring pubLower = entry.publisher;
    std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);

    const wchar_t* traceRoot = L"SOFTWARE\\Microsoft\\Tracing";
    HKEY hRoot;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, traceRoot, 0, KEY_READ, &hRoot) != ERROR_SUCCESS) return;

    DWORD idx = 0;
    wchar_t keyName[256];
    DWORD keyNameLen = 256;

    while (RegEnumKeyExW(hRoot, idx, keyName, &keyNameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        std::wstring traceKey(keyName);
        std::wstring traceLower = traceKey;
        std::transform(traceLower.begin(), traceLower.end(), traceLower.begin(), ::towlower);

        bool match = false;
        int rawScore = 0;

        for (auto& exe : entry.sortedExecutables) {
            std::wstring exeBase = exe;
            size_t dotPos = exeBase.find_last_of(L'.');
            if (dotPos != std::wstring::npos) exeBase = exeBase.substr(0, dotPos);
            if (traceLower.find(exeBase) != std::wstring::npos) {
                match = true;
                rawScore = 12;
                break;
            }
        }

        if (!match && !kwLower.empty()) {
            if (traceLower.find(kwLower) != std::wstring::npos ||
                kwLower.find(traceLower) != std::wstring::npos) {
                match = true;
                rawScore = 8;
            }
        }

        if (!match && !pubLower.empty() &&
            traceLower.find(pubLower) != std::wstring::npos) {
            match = true;
            rawScore = 6;
        }

        if (match) {
            std::wstring fullPath = std::wstring(traceRoot) + L"\\" + traceKey;
            LeftoverItem item;
            item.path = L"HKLM\\" + fullPath;
            item.displayName = traceKey;
            item.displayName += L" (tracing)";
            item.type = LeftoverItem::RegistryKey;
            item.checked = false;
            int rs = rawScore;
            if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
            else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
            else item.confidence = LeftoverConfidence::Risky;
            item.rawScore = rawScore;
            results.push_back(item);
        }
        keyNameLen = 256;
        idx++;
    }
    RegCloseKey(hRoot);
}

void Uninstaller::ScanRegisteredApplications(std::vector<LeftoverItem>& results, const UninstallEntry& entry) {
    std::wstring kwLower = entry.displayName;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring pubLower = entry.publisher;
    std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);

    const wchar_t* raPath = L"SOFTWARE\\RegisteredApplications";

    for (HKEY root : { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER }) {
        HKEY hKey;
        if (RegOpenKeyExW(root, raPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;

        DWORD idx = 0;
        wchar_t valName[512];
        DWORD valNameLen = sizeof(valName) / sizeof(wchar_t);
        BYTE valData[4096];
        DWORD valDataLen = sizeof(valData);
        DWORD valType = 0;

        while (RegEnumValueW(hKey, idx, valName, &valNameLen, NULL,
                              &valType, valData, &valDataLen) == ERROR_SUCCESS) {
            if (valType == REG_SZ) {
                std::wstring regPath((wchar_t*)valData, valDataLen / sizeof(wchar_t));
                std::wstring nameLower = valName;
                std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);

                bool match = false;
                int rawScore = 0;

                if (!kwLower.empty() &&
                    nameLower.find(kwLower) != std::wstring::npos) {
                    match = true;
                    rawScore = 8;
                }

                if (!match && !pubLower.empty() &&
                    nameLower.find(pubLower) != std::wstring::npos) {
                    match = true;
                    rawScore = 6;
                }

                if (!match) {
                    std::wstring regLower = regPath;
                    std::transform(regLower.begin(), regLower.end(), regLower.begin(), ::towlower);
                    if (!kwLower.empty() && regLower.find(kwLower) != std::wstring::npos) {
                        match = true;
                        rawScore = 8;
                    }
                }

                if (match) {
                    std::wstring hivePrefix = (root == HKEY_CURRENT_USER) ? L"HKCU" : L"HKLM";
                    LeftoverItem item;
                    item.path = hivePrefix + L"\\" + std::wstring(raPath) + L"\\" + std::wstring(valName);
                    item.displayName = std::wstring(valName);
                    item.displayName += L" → " + regPath;
                    item.displayName += L" (regapp)";
                    item.type = LeftoverItem::RegistryKey;
                    item.checked = false;
                    int rs = rawScore;
                    if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
                    else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
                    else item.confidence = LeftoverConfidence::Risky;
                    item.rawScore = rawScore;
                    results.push_back(item);
                }
            }
            valNameLen = sizeof(valName) / sizeof(wchar_t);
            valDataLen = sizeof(valData);
            idx++;
        }
        RegCloseKey(hKey);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Scheduled Tasks Scanner — finds leftover task triggers
// ═══════════════════════════════════════════════════════════════════════
void Uninstaller::ScanScheduledTasks(std::vector<LeftoverItem>& results, const std::wstring& keyword,
                                     const std::wstring& publisher, const std::wstring& installPath) {
    BH_TIMER_START(t0);
    int enumerated = 0, matches = 0;

    const wchar_t* taskCachePath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks";
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, taskCachePath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        OutputDebugStringA("ScanScheduledTasks: cannot open TaskCache\\Tasks\n");
        BH_TIMER_END_MS(t0, "ScanScheduledTasks");
        return;
    }
    BH_REG_OPEN(hKey, HKEY_LOCAL_MACHINE, taskCachePath);

    std::wstring kwLower = keyword;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring pubLower = publisher;
    std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);
    std::wstring instLower = installPath;
    std::transform(instLower.begin(), instLower.end(), instLower.begin(), ::towlower);

    DWORD index = 0;
    wchar_t subKeyName[512];
    DWORD subKeyLen = 512;

    while (RegEnumKeyExW(hKey, index, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        enumerated++;
        std::wstring taskPath = std::wstring(taskCachePath) + L"\\" + std::wstring(subKeyName);
        HKEY hTask;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, taskPath.c_str(), 0, KEY_READ, &hTask) == ERROR_SUCCESS) {
            std::wstring taskName = ReadRegString(hTask, L"Path");
            std::wstring taskURI = ReadRegString(hTask, L"URI");

            // Read Actions binary blob — contains executable paths
            DWORD actionsSize = 0;
            DWORD actionsType = 0;
            RegQueryValueExW(hTask, L"Actions", NULL, &actionsType, NULL, &actionsSize);

            bool matched = false;
            std::wstring matchedDetail;

            // Check task name / URI against keyword
            std::wstring taskNameLower = taskName;
            std::transform(taskNameLower.begin(), taskNameLower.end(), taskNameLower.begin(), ::towlower);
            std::wstring taskURILower = taskURI;
            std::transform(taskURILower.begin(), taskURILower.end(), taskURILower.begin(), ::towlower);

            if (!kwLower.empty()) {
                if (taskNameLower.find(kwLower) != std::wstring::npos) {
                    matched = true;
                    matchedDetail = L"Task name contains keyword: " + taskName;
                } else if (taskURILower.find(kwLower) != std::wstring::npos) {
                    matched = true;
                    matchedDetail = L"Task URI contains keyword: " + taskURI;
                }
            }

            // Parse Actions blob for executable paths
            if (!matched && actionsSize > 0 && (actionsType == REG_BINARY)) {
                std::vector<BYTE> actionsData(actionsSize);
                DWORD actualSize = actionsSize;
                if (RegQueryValueExW(hTask, L"Actions", NULL, NULL, actionsData.data(), &actualSize) == ERROR_SUCCESS) {
                    // Actions blob contains embedded wide strings (executable paths)
                    // Scan for any path-like strings that contain the keyword or install path
                    const wchar_t* wData = (const wchar_t*)actionsData.data();
                    DWORD wCount = actualSize / sizeof(wchar_t);
                    std::wstring extracted;
                    for (DWORD i = 0; i < wCount; i++) {
                        wchar_t c = wData[i];
                        if (c >= 32) {
                            extracted += c;
                        } else {
                            if (!extracted.empty()) {
                                std::wstring exLower = extracted;
                                std::transform(exLower.begin(), exLower.end(), exLower.begin(), ::towlower);

                                if (!kwLower.empty() && exLower.find(kwLower) != std::wstring::npos) {
                                    matched = true;
                                    matchedDetail = L"Actions executable matches keyword: " + extracted;
                                    break;
                                }
                                if (!instLower.empty() && exLower.find(instLower) != std::wstring::npos) {
                                    matched = true;
                                    matchedDetail = L"Actions executable matches install path: " + extracted;
                                    break;
                                }
                                extracted.clear();
                            }
                        }
                    }
                }
            }

            if (matched) {
                const wchar_t* rootName = L"HKLM";
                std::wstring fullPath = L"HKLM\\" + taskPath;

                int rawScore = 0;
                LeftoverConfidence conf = ScoreConfidence(
                    taskName.empty() ? std::wstring(subKeyName) : taskName,
                    keyword, publisher, installPath, true, 0, rawScore);

                LeftoverItem item;
                item.path = fullPath;
                item.displayName = taskName.empty() ? std::wstring(subKeyName) : taskName;
                if (!matchedDetail.empty()) {
                    item.displayName += L" (" + matchedDetail + L")";
                }
                item.type = LeftoverItem::RegistryKey;
                item.checked = (conf != LeftoverConfidence::Risky);
                item.confidence = conf;
                item.rawScore = rawScore;
                results.push_back(item);
                matches++;

                {
                    char _b[512];
                    snprintf(_b, sizeof(_b), "ScanScheduledTasks: MATCH task=%ls detail=[%ls] score=%d conf=%d\n",
                             taskName.c_str(), matchedDetail.c_str(), rawScore, (int)conf);
                    OutputDebugStringA(_b);
                }
            }

            RegCloseKey(hTask);
        }
        subKeyLen = 512;
        index++;
    }
    BH_REG_CLOSE(hKey);
    RegCloseKey(hKey);

    {
        char _buf[256];
        snprintf(_buf, sizeof(_buf), "ScanScheduledTasks: enumerated=%d matches=%d results=%d\n",
                 enumerated, matches, (int)results.size());
        OutputDebugStringA(_buf);
    }
    BH_TIMER_END_MS(t0, "ScanScheduledTasks");
}

// ═══════════════════════════════════════════════════════════════════════
//  Orphaned Installer Files Scanner — orphaned .msi/.msp in C:\Windows\Installer
// ═══════════════════════════════════════════════════════════════════════
void Uninstaller::ScanOrphanedInstallerFiles(std::vector<LeftoverItem>& results, const std::wstring& keyword,
                                              const std::wstring& publisher) {
    BH_TIMER_START(t0);
    int scanned = 0, matches = 0;

    wchar_t winDir[MAX_PATH];
    if (!GetWindowsDirectoryW(winDir, MAX_PATH)) {
        BH_TIMER_END_MS(t0, "ScanOrphanedInstallerFiles");
        return;
    }
    std::wstring installerDir = std::wstring(winDir) + L"\\Installer";
    if (!std::filesystem::exists(installerDir) || !std::filesystem::is_directory(installerDir)) {
        BH_TIMER_END_MS(t0, "ScanOrphanedInstallerFiles");
        return;
    }

    std::wstring kwLower = keyword;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);
    std::wstring pubLower = publisher;
    std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);

    // Build set of active product codes from registry
    std::unordered_map<std::wstring, bool> activeProducts;
    const wchar_t* uninstallPaths[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        NULL
    };
    for (int pi = 0; uninstallPaths[pi]; pi++) {
        HKEY hUninst;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, uninstallPaths[pi], 0, KEY_READ, &hUninst) == ERROR_SUCCESS) {
            DWORD idx = 0;
            wchar_t keyName[256];
            DWORD keyNameLen = 256;
            while (RegEnumKeyExW(hUninst, idx, keyName, &keyNameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                std::wstring codeLower = keyName;
                std::transform(codeLower.begin(), codeLower.end(), codeLower.begin(), ::towlower);
                activeProducts[codeLower] = true;
                keyNameLen = 256;
                idx++;
            }
            RegCloseKey(hUninst);
        }
    }

    // Scan C:\Windows\Installer for .msi and .msp files
    std::error_code ec;
    std::filesystem::directory_iterator it(installerDir, ec);
    if (ec) {
        BH_TIMER_END_MS(t0, "ScanOrphanedInstallerFiles");
        return;
    }
    std::filesystem::directory_iterator end;
    for (; it != end; it.increment(ec)) {
        if (ec) break;
        const auto& entry = *it;
        if (entry.is_directory()) continue;

        std::wstring ext = entry.path().extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
        if (ext != L".msi" && ext != L".msp") continue;

        scanned++;
        std::wstring fileName = entry.path().stem().wstring();
        std::wstring fileNameLower = fileName;
        std::transform(fileNameLower.begin(), fileNameLower.end(), fileNameLower.begin(), ::towlower);

        // Check if the filename (which is a product code GUID) is in active products
        bool isActive = activeProducts.count(fileNameLower) > 0;
        if (isActive) continue;

        // Check if filename or display name matches keyword
        bool match = false;
        int rawScore = 0;

        if (!kwLower.empty() && (fileNameLower.find(kwLower) != std::wstring::npos ||
                                  kwLower.find(fileNameLower) != std::wstring::npos)) {
            match = true;
            rawScore = 8;
        }

        // For GUID-named files, try to read the MSI Summary Information to get the product name
        if (!match && fileName.size() > 10 && fileName[0] == L'{') {
            // This is likely a GUID — try to extract product info from MSI
            // MSI files with GUID names are stored by Windows Installer
            // Check file size as a heuristic — orphaned files tend to be standalone
            auto fSize = entry.file_size();
            if (fSize > 100000) {
                // Large MSI file, likely a full installer — flag as potential orphan
                rawScore = 3;
                LeftoverItem item;
                item.path = entry.path().wstring();
                item.displayName = fileName + L" (" + ext.substr(1) + L", " +
                                   std::to_wstring(fSize / 1024) + L" KB)";
                item.type = LeftoverItem::File;
                item.checked = false;
                item.confidence = LeftoverConfidence::Risky;
                item.rawScore = rawScore;
                results.push_back(item);
                matches++;
                continue;
            }
        }

        if (match) {
            LeftoverItem item;
            item.path = entry.path().wstring();
            item.displayName = fileName + L" (" + ext.substr(1) + L")";
            item.type = LeftoverItem::File;
            item.checked = false;
            int rs = rawScore;
            if (rs >= 8) item.confidence = LeftoverConfidence::Safe;
            else if (rs >= 4) item.confidence = LeftoverConfidence::Moderate;
            else item.confidence = LeftoverConfidence::Risky;
            item.rawScore = rawScore;
            results.push_back(item);
            matches++;
        }
    }

    {
        char _buf[256];
        snprintf(_buf, sizeof(_buf), "ScanOrphanedInstallerFiles: scanned=%d matches=%d activeProducts=%d results=%d\n",
                 scanned, matches, (int)activeProducts.size(), (int)results.size());
        OutputDebugStringA(_buf);
    }
    BH_TIMER_END_MS(t0, "ScanOrphanedInstallerFiles");
}

void Uninstaller::MergeCrossHiveEntries(std::vector<LeftoverItem>& items) {
    auto stripHive = [](const std::wstring& path) -> std::wstring {
        const wchar_t* prefixes[] = {
            L"HKCU\\", L"HKLM\\", L"HKCR\\", L"HKU\\",
            L"HKEY_CURRENT_USER\\", L"HKEY_LOCAL_MACHINE\\",
            L"HKEY_CLASSES_ROOT\\", L"HKEY_USERS\\"
        };
        for (auto* p : prefixes) {
            size_t len = wcslen(p);
            if (path.compare(0, len, p) == 0)
                return path.substr(len);
        }
        return path;
    };

    auto getHive = [](const std::wstring& path) -> std::wstring {
        if (path.compare(0, 5, L"HKCU\\") == 0 || path.compare(0, 18, L"HKEY_CURRENT_USER\\") == 0)
            return L"HKCU";
        if (path.compare(0, 5, L"HKLM\\") == 0 || path.compare(0, 20, L"HKEY_LOCAL_MACHINE\\") == 0)
            return L"HKLM";
        if (path.compare(0, 5, L"HKCR\\") == 0 || path.compare(0, 18, L"HKEY_CLASSES_ROOT\\") == 0)
            return L"HKCR";
        return L"";
    };

    std::unordered_map<std::wstring, size_t> normToIdx;
    std::vector<size_t> toErase;

    for (size_t i = 0; i < items.size(); i++) {
        if (items[i].type != LeftoverItem::RegistryKey) continue;
        std::wstring norm = stripHive(items[i].path);

        auto it = normToIdx.find(norm);
        if (it != normToIdx.end()) {
            size_t canonical = it->second;
            std::wstring hiveA = getHive(items[canonical].path);
            std::wstring hiveB = getHive(items[i].path);
            bool crossHive = (!hiveA.empty() && !hiveB.empty() && hiveA != hiveB);

            items[canonical].rawScore += items[i].rawScore + 2;
            int rs = items[canonical].rawScore;

            if (crossHive) {
                if (rs >= 8) items[canonical].confidence = LeftoverConfidence::Moderate;
                else if (rs >= 4) items[canonical].confidence = LeftoverConfidence::Moderate;
                else items[canonical].confidence = LeftoverConfidence::Risky;
            } else {
                if (rs >= 8) items[canonical].confidence = LeftoverConfidence::Safe;
                else if (rs >= 4) items[canonical].confidence = LeftoverConfidence::Moderate;
                else items[canonical].confidence = LeftoverConfidence::Risky;
            }
            if (items[i].checked && !items[canonical].checked)
                items[canonical].checked = true;
            toErase.push_back(i);
        } else {
            normToIdx[norm] = i;
        }
    }

    for (auto it = toErase.rbegin(); it != toErase.rend(); ++it)
        items.erase(items.begin() + *it);
}

void Uninstaller::RemoveDuplicates(std::vector<LeftoverItem>& items) {
    std::unordered_map<std::wstring, size_t> pathToIdx;
    std::vector<size_t> toErase;

    for (size_t i = 0; i < items.size(); i++) {
        auto it = pathToIdx.find(items[i].path);
        if (it != pathToIdx.end()) {
            size_t canonical = it->second;
            items[canonical].rawScore += items[i].rawScore;
            int rs = items[canonical].rawScore;
            if (rs >= 8) items[canonical].confidence = LeftoverConfidence::Safe;
            else if (rs >= 4) items[canonical].confidence = LeftoverConfidence::Moderate;
            else items[canonical].confidence = LeftoverConfidence::Risky;
            if (items[i].checked && !items[canonical].checked)
                items[canonical].checked = true;
            toErase.push_back(i);
        } else {
            pathToIdx[items[i].path] = i;
        }
    }

    for (auto it = toErase.rbegin(); it != toErase.rend(); ++it)
        items.erase(items.begin() + *it);
}

void Uninstaller::FilterByConfidence(std::vector<LeftoverItem>& items, ScanDepth depth) {
    std::vector<LeftoverItem> filtered;
    for (auto& item : items) {
        if (depth == ScanDepth::Safe && item.confidence == LeftoverConfidence::Risky)
            continue;
        if (depth == ScanDepth::Moderate && item.confidence == LeftoverConfidence::Risky)
            continue;
        filtered.push_back(item);
    }
    items = filtered;
}

std::vector<LeftoverItem> Uninstaller::ScanLeftovers(const UninstallEntry& entry,
                                                      ScanDepth depth,
                                                      bool basicOnly) {
    std::vector<LeftoverItem> results;

    std::wstring keyword = entry.displayName;
    if (keyword.empty()) keyword = entry.publisher;
    if (keyword.empty()) return results;

    BH_TIMER_START(tTotal);
    {
        char _hdr[512];
        snprintf(_hdr, sizeof(_hdr),
                 "ScanLeftovers: BEGIN kw=[%ls] pub=[%ls] inst=[%ls] depth=%d basicOnly=%d\n",
                 keyword.c_str(), entry.publisher.c_str(), entry.installPath.c_str(),
                 (int)depth, basicOnly ? 1 : 0);
        OutputDebugStringA(_hdr);
    }
    OutputDebugStringA("ScanLeftovers: start\n");

    try {

    BH_TIMER_START(tPhase);
    OutputDebugStringA("ScanLeftovers: scanning APPDATA\n");
    std::wstring envBuf;
    envBuf.resize(MAX_PATH);

    try {
    DWORD len = GetEnvironmentVariableW(L"APPDATA", &envBuf[0], MAX_PATH);
    if (len > 0) { envBuf.resize(len); ScanDirectory(envBuf, keyword, results, depth); }
    } catch (...) { OutputDebugStringA("ScanLeftovers: APPDATA crashed\n"); }
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: APPDATA");

    BH_TIMER_RESTART(tPhase);
    OutputDebugStringA("ScanLeftovers: scanning LOCALAPPDATA\n");
    try {
    DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", &envBuf[0], MAX_PATH);
    if (len > 0) { envBuf.resize(len); ScanDirectory(envBuf, keyword, results, depth); }
    } catch (...) { OutputDebugStringA("ScanLeftovers: LOCALAPPDATA crashed\n"); }
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: LOCALAPPDATA");

    BH_TIMER_RESTART(tPhase);
    OutputDebugStringA("ScanLeftovers: scanning PROGRAMDATA\n");
    try {
    DWORD len = GetEnvironmentVariableW(L"PROGRAMDATA", &envBuf[0], MAX_PATH);
    if (len > 0) { envBuf.resize(len); ScanDirectory(envBuf, keyword, results, depth); }
    } catch (...) { OutputDebugStringA("ScanLeftovers: PROGRAMDATA crashed\n"); }
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: PROGRAMDATA");

    BH_TIMER_RESTART(tPhase);
    OutputDebugStringA("ScanLeftovers: scanning UserProfile\n");
    try {
    wchar_t userProfile[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile))) {
        ScanDirectory(userProfile, keyword, results, depth);
        std::wstring docs = std::wstring(userProfile) + L"\\Documents";
        ScanDirectory(docs, keyword, results, depth);
        std::wstring downloads = std::wstring(userProfile) + L"\\Downloads";
        ScanDirectory(downloads, keyword, results, depth);
    }
    } catch (...) { OutputDebugStringA("ScanLeftovers: UserProfile crashed\n"); }
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: UserProfile");

    BH_TIMER_RESTART(tPhase);
    OutputDebugStringA("ScanLeftovers: scanning InstallPath\n");
    try {
    if (!entry.installPath.empty()) {
        std::wstring installDir = std::filesystem::path(entry.installPath).wstring();
        ScanInstallDirContents(installDir, keyword, entry.publisher, results, depth);
        std::wstring parentPath = std::filesystem::path(entry.installPath).parent_path().wstring();
        if (!parentPath.empty()) ScanDirectory(parentPath, keyword, results, depth);
    }
    } catch (...) { OutputDebugStringA("ScanLeftovers: InstallPath crashed\n"); }
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: InstallPath");

    BH_TIMER_RESTART(tPhase);
    OutputDebugStringA("ScanLeftovers: scanning TempDir\n");
    try {
    std::wstring tempDir;
    tempDir.resize(MAX_PATH);
    DWORD len = GetTempPathW(MAX_PATH, &tempDir[0]);
    if (len > 0) { tempDir.resize(len); ScanDirectory(tempDir, keyword, results, depth); }
    } catch (...) { OutputDebugStringA("ScanLeftovers: TempDir crashed\n"); }
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: TempDir");

    BH_TIMER_RESTART(tPhase);
    OutputDebugStringA("ScanLeftovers: scanning InstallerCache\n");
    try {
    wchar_t winDir[MAX_PATH];
    if (GetWindowsDirectoryW(winDir, MAX_PATH) > 0) {
        std::wstring installerCache = std::wstring(winDir) + L"\\Installer";
        ScanDirectory(installerCache, keyword, results, depth);
    }
    } catch (...) { OutputDebugStringA("ScanLeftovers: InstallerCache crashed\n"); }
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: InstallerCache");

    BH_TIMER_RESTART(tPhase);
    OutputDebugStringA("ScanLeftovers: scanning registry\n");
    try {
    ScanRegistryForLeftovers(HKEY_CURRENT_USER, L"SOFTWARE", keyword, entry.publisher, entry.installPath, results, depth);
    } catch (...) { OutputDebugStringA("ScanLeftovers: HKCU crashed\n"); }

    try {
    ScanRegistryForLeftovers(HKEY_LOCAL_MACHINE, L"SOFTWARE", keyword, entry.publisher, entry.installPath, results, depth);
    } catch (...) { OutputDebugStringA("ScanLeftovers: HKLM crashed\n"); }

    try {
    ScanRegistryForLeftovers(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node", keyword, entry.publisher, entry.installPath, results, depth);
    } catch (...) { OutputDebugStringA("ScanLeftovers: WOW6432Node crashed\n"); }
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: Registry");

    {
        char _buf[256];
        snprintf(_buf, sizeof(_buf), "ScanLeftovers: basic scan done — %d results so far\n", (int)results.size());
        OutputDebugStringA(_buf);
    }
    OutputDebugStringA("ScanLeftovers: basic scan done\n");

    if (!basicOnly) {

    BH_TIMER_RESTART(tPhase);
    if (depth != ScanDepth::Safe) {
        ScanStartMenu(results, keyword);
        ScanDesktop(results, keyword);
        ScanAppPaths(results, keyword);
        ScanRunKeys(results, keyword);
        ScanServices(results, keyword, entry.publisher, entry.installPath);
        ScanCOM(results, keyword, entry.publisher, entry.installPath);
        ScanFirewallRules(results, keyword);

        wchar_t pfBuf[MAX_PATH], pf86Buf[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, 0, pfBuf)))
            ScanDirectory(pfBuf, keyword, results, depth);
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, pf86Buf)))
            ScanDirectory(pf86Buf, keyword, results, depth);
    }
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: Extended (non-Safe)");

    BH_TIMER_RESTART(tPhase);
    if (depth == ScanDepth::Advanced) {
        ScanCOMDeep(results, keyword);
        ScanInstallerCaches(results, keyword);
        ScanEventLog(results, entry);
        ScanAppCompatFlags(results, entry);
        ScanProgramFilesOrphans(results, entry);
        ScanAudioPolicyConfig(results, entry);
        ScanHeapLeakDetection(results, entry);
        ScanInstallerFolders(results, entry);
        ScanDebugTracing(results, entry);
        ScanRegisteredApplications(results, entry);
        ScanScheduledTasks(results, keyword, entry.publisher, entry.installPath);
        ScanOrphanedInstallerFiles(results, keyword, entry.publisher);
    }
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: Advanced");

    BH_TIMER_RESTART(tPhase);
    OutputDebugStringA("ScanLeftovers: ScanPrefetch\n");
    try {
    ScanPrefetch(results, entry);
    } catch (...) { OutputDebugStringA("ScanLeftovers: ScanPrefetch crashed\n"); }
    OutputDebugStringA("ScanLeftovers: ScanWERReports\n");
    try {
    ScanWERReports(results, entry);
    } catch (...) { OutputDebugStringA("ScanLeftovers: ScanWERReports crashed\n"); }
    OutputDebugStringA("ScanLeftovers: ScanMSIUpgradeCodes\n");
    try {
    ScanMSIUpgradeCodes(results, entry);
    } catch (...) { OutputDebugStringA("ScanLeftovers: ScanMSIUpgradeCodes crashed\n"); }
    OutputDebugStringA("ScanLeftovers: ScanUserAssist\n");
    try {
    ScanUserAssist(results, entry);
    } catch (...) { OutputDebugStringA("ScanLeftovers: ScanUserAssist crashed\n"); }
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: Prefetch/WER/MSI/UserAssist");

    BH_TIMER_RESTART(tPhase);
    OutputDebugStringA("ScanLeftovers: publisher scan\n");
    try {
    if (!entry.publisher.empty() && entry.publisher != keyword) {
        DWORD len2 = GetEnvironmentVariableW(L"APPDATA", &envBuf[0], MAX_PATH);
        if (len2 > 0) { envBuf.resize(len2); ScanDirectory(envBuf, entry.publisher, results, depth); }
        ScanRegistryForLeftovers(HKEY_CURRENT_USER, L"SOFTWARE", entry.publisher, entry.publisher, entry.installPath, results, depth);
        ScanRegistryForLeftovers(HKEY_LOCAL_MACHINE, L"SOFTWARE", entry.publisher, entry.publisher, entry.installPath, results, depth);
    }
    } catch (...) { OutputDebugStringA("ScanLeftovers: publisher scan crashed\n"); }
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: Publisher scan");

    BH_TIMER_RESTART(tPhase);
    OutputDebugStringA("ScanLeftovers: post-processing\n");

    try {
    if (m_cachedApps.empty()) m_cachedApps = ScanInstalled();
    } catch (...) { OutputDebugStringA("ScanLeftovers: ScanInstalled crashed\n"); }

    std::wstring kwLower = keyword;
    std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), ::towlower);

    results.erase(std::remove_if(results.begin(), results.end(),
        [&](const LeftoverItem& item) {
            if (IsProtectedPath(item.path)) return true;
            if (item.type == LeftoverItem::RegistryKey && IsProtectedRegistryKey(item.path))
                return true;
            if (IsUsedByOtherApp(item.path, m_cachedApps, entry.displayName))
                return true;
            if (item.type == LeftoverItem::Directory && !kwLower.empty()) {
                std::wstring dirLower = item.path;
                std::transform(dirLower.begin(), dirLower.end(), dirLower.begin(), ::towlower);
                std::wstring nameLower = item.displayName;
                std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
                std::wstring pubLower = entry.publisher;
                std::transform(pubLower.begin(), pubLower.end(), pubLower.begin(), ::towlower);
                bool nameMatch = (!kwLower.empty() && (nameLower.find(kwLower) != std::wstring::npos || kwLower.find(nameLower) != std::wstring::npos));
                bool pubMatch = (!pubLower.empty() && (nameLower.find(pubLower) != std::wstring::npos || pubLower.find(nameLower) != std::wstring::npos));
                if (!nameMatch && !pubMatch) return true;
            }
            return false;
        }), results.end());

    MergeCrossHiveEntries(results);
    RemoveDuplicates(results);

    // Consolidate: if many files are under the same parent directory, replace with one directory entry
    if (results.size() > 10) {
        std::unordered_map<std::wstring, int> dirFileCount;
        for (auto& item : results) {
            if (item.type == LeftoverItem::File) {
                std::wstring parent = item.path;
                size_t lastSlash = parent.find_last_of(L'\\');
                if (lastSlash != std::wstring::npos) {
                    parent = parent.substr(0, lastSlash);
                    std::transform(parent.begin(), parent.end(), parent.begin(), ::towlower);
                    dirFileCount[parent]++;
                }
            }
        }
        for (auto& [dir, count] : dirFileCount) {
            if (count > 5) {
                std::wstring dirLower = dir;
                std::transform(dirLower.begin(), dirLower.end(), dirLower.begin(), ::towlower);
                // Remove individual files under this directory
                results.erase(std::remove_if(results.begin(), results.end(),
                    [&](const LeftoverItem& item) {
                        if (item.type != LeftoverItem::File) return false;
                        std::wstring p = item.path;
                        size_t ls = p.find_last_of(L'\\');
                        if (ls == std::wstring::npos) return false;
                        p = p.substr(0, ls);
                        std::transform(p.begin(), p.end(), p.begin(), ::towlower);
                        return p == dirLower;
                    }), results.end());
                // Add single directory entry
                LeftoverItem dirItem;
                dirItem.path = dir;
                std::wstring dirName = dir;
                size_t ls = dirName.find_last_of(L'\\');
                if (ls != std::wstring::npos) dirName = dirName.substr(ls + 1);
                dirItem.displayName = dirName + L" (" + std::to_wstring(count) + L" files)";
                dirItem.type = LeftoverItem::Directory;
                dirItem.checked = true;
                dirItem.confidence = LeftoverConfidence::Safe;
                dirItem.rawScore = 10;
                results.push_back(dirItem);
            }
        }
    }

    FilterByConfidence(results, depth);
    BH_TIMER_END_MS(tPhase, "ScanLeftovers: Post-processing");

    } // if (!basicOnly)

    } catch (...) {
        OutputDebugStringA("ScanLeftovers: outer exception caught\n");
    }
    {
        int safe = 0, maybe = 0, risky = 0;
        for (auto& r : results) {
            if (r.confidence == LeftoverConfidence::Safe) safe++;
            else if (r.confidence == LeftoverConfidence::Moderate) maybe++;
            else risky++;
        }
        char _buf[512];
        snprintf(_buf, sizeof(_buf),
                 "ScanLeftovers: DONE kw=[%ls] total=%d (Safe=%d Maybe=%d Risky=%d) regOpen=%d regClose=%d leaked=%d\n",
                 keyword.c_str(), (int)results.size(), safe, maybe, risky,
                 g_regOpenCount.load(), g_regCloseCount.load(),
                 g_regOpenCount.load() - g_regCloseCount.load());
        OutputDebugStringA(_buf);
    }
    BH_TIMER_END_MS(tTotal, "ScanLeftovers: TOTAL");
    return results;
}

bool Uninstaller::PurgeLeftovers(const std::vector<LeftoverItem>& items, bool createRestorePoint) {
    Deletor deletor;
    BlackHole::PrivilegeManager priv;
    priv.EnableAllPrivileges();
    bool allOk = true;

    // Launch restore point on background thread so UI doesn't freeze
    HANDLE hRestoreThread = NULL;
    if (createRestorePoint) {
        OutputDebugStringA("PurgeLeftovers: launching restore point thread\n");
        struct RestoreThreadData { std::wstring name; };
        auto* rtd = new RestoreThreadData{ L"BlackHole Cleanup" };
        hRestoreThread = (HANDLE)_beginthreadex(NULL, 2 * 1024 * 1024,
            [](void* param) -> unsigned {
                auto* d = static_cast<RestoreThreadData*>(param);
                OutputDebugStringA("RestoreThread: start\n");
                // We need an Uninstaller instance for CreateSystemRestorePoint
                Uninstaller u;
                u.CreateSystemRestorePoint(d->name);
                OutputDebugStringA("RestoreThread: done\n");
                delete d;
                return 0;
            }, rtd, 0, NULL);
    }

    std::vector<LeftoverItem> sorted = items;
    std::stable_sort(sorted.begin(), sorted.end(), [](const LeftoverItem& a, const LeftoverItem& b) {
        if (a.type == LeftoverItem::Directory && b.type != LeftoverItem::Directory) return false;
        if (a.type != LeftoverItem::Directory && b.type == LeftoverItem::Directory) return true;
        return false;
    });

    for (auto& item : sorted) {
        if (!item.checked) continue;

        OutputDebugStringA("PurgeLeftovers: processing item\n");

        if (IsProtectedPath(item.path)) {
            OutputDebugStringA("PurgeLeftovers: skipping (protected)\n");
            continue;
        }
        if (item.type == LeftoverItem::RegistryKey && IsProtectedRegistryKey(item.path)) {
            OutputDebugStringA("PurgeLeftovers: skipping (protected registry)\n");
            continue;
        }

        if (item.type == LeftoverItem::RegistryKey) {
            HKEY rootKey = HKEY_LOCAL_MACHINE;
            std::wstring regPath = item.path;
            size_t firstSlash = regPath.find(L'\\');
            bool isHKLM = true;
            if (firstSlash != std::wstring::npos) {
                std::wstring root = regPath.substr(0, firstSlash);
                regPath = regPath.substr(firstSlash + 1);
                if (root == L"HKEY_CURRENT_USER" || root == L"HKCU") {
                    rootKey = HKEY_CURRENT_USER;
                    isHKLM = false;
                }
            } else {
                regPath = item.path;
            }

            bool deleted = false;
            if (isHKLM && rootKey == HKEY_LOCAL_MACHINE) {
                HKEY hKey = NULL;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0,
                                   KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                    deleted = (RegDeleteTreeW(hKey, NULL) == ERROR_SUCCESS);
                    RegCloseKey(hKey);
                }
                if (!deleted) {
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0,
                                       KEY_READ | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS) {
                        deleted = (RegDeleteTreeW(hKey, NULL) == ERROR_SUCCESS);
                        RegCloseKey(hKey);
                    }
                }
            } else {
                HKEY hKey = NULL;
                if (RegOpenKeyExW(rootKey, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    deleted = (RegDeleteTreeW(hKey, NULL) == ERROR_SUCCESS);
                    RegCloseKey(hKey);
                }
            }
            if (!deleted) allOk = false;
        } else if (item.type == LeftoverItem::Directory) {
            DWORD attrs = GetFileAttributesW(item.path.c_str());
            if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                auto result = deletor.DeleteFileSafely(item.path);
                if (result.result != DeletionResult::Success &&
                    result.result != DeletionResult::Scheduled_Reboot)
                    allOk = false;
            } else {
                auto result = deletor.DeleteDirectoryRecursive(item.path);
                if (result.result != DeletionResult::Success &&
                    result.result != DeletionResult::Scheduled_Reboot)
                    allOk = false;
            }
        } else {
            auto result = deletor.DeleteFileSafely(item.path);
            if (result.result != DeletionResult::Success &&
                result.result != DeletionResult::Scheduled_Reboot)
                allOk = false;
        }
    }

    // Wait for restore point thread to finish
    if (hRestoreThread) {
        OutputDebugStringA("PurgeLeftovers: waiting for restore point thread\n");
        WaitForSingleObject(hRestoreThread, 30000);
        CloseHandle(hRestoreThread);
        OutputDebugStringA("PurgeLeftovers: restore point thread finished\n");
    }

    return allOk;
}

std::wstring Uninstaller::ResolveInstallPath(const UninstallEntry& entry) {
    if (!entry.installPath.empty()) {
        DWORD attr = GetFileAttributesW(entry.installPath.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES) return entry.installPath;
    }

    if (!entry.uninstallString.empty()) {
        std::wstring cmd = entry.uninstallString;
        size_t lastSlash = cmd.find_last_of(L'\\');
        if (lastSlash != std::wstring::npos) {
            std::wstring dir = cmd.substr(0, lastSlash);
            size_t lastSlash2 = dir.find_last_of(L'\\');
            if (lastSlash2 != std::wstring::npos && lastSlash2 > 2)
                dir = dir.substr(0, lastSlash2);
            size_t spacePos = dir.find(L' ');
            if (spacePos != std::wstring::npos) {
                std::wstring candidate = dir.substr(0, spacePos);
                DWORD attr = GetFileAttributesW(candidate.c_str());
                if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
                    return candidate;
            }
            DWORD attr = GetFileAttributesW(dir.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
                return dir;
        }
    }

    wchar_t pfBuf[MAX_PATH], pf86Buf[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, 0, pfBuf);
    SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, pf86Buf);

    std::wstring nameLower = entry.displayName;
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);

    std::wstring bases[2] = { std::wstring(pfBuf), std::wstring(pf86Buf) };
    for (int bi = 0; bi < 2; bi++) {
        std::error_code ec;
        for (auto& d : std::filesystem::directory_iterator(bases[bi], ec)) {
            if (ec) break;
            if (!d.is_directory()) continue;

            DWORD dAttr = GetFileAttributesW(d.path().c_str());
            if (dAttr != INVALID_FILE_ATTRIBUTES && (dAttr & FILE_ATTRIBUTE_REPARSE_POINT))
                continue;

            std::wstring dirLower = d.path().filename().wstring();
            std::transform(dirLower.begin(), dirLower.end(), dirLower.begin(), ::towlower);
            if (dirLower.find(nameLower) != std::wstring::npos ||
                nameLower.find(dirLower) != std::wstring::npos)
                return d.path().wstring();
        }
    }
    return L"";
}

std::wstring Uninstaller::GetBackupDir() const {
    wchar_t appData[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData))) {
        std::wstring dir = std::wstring(appData) + L"\\BlackHole\\RegistryBackups";
        std::filesystem::create_directories(dir);
        return dir;
    }
    return L"";
}

bool Uninstaller::BackupRegistryKey(const std::wstring& appName, const std::wstring& regPath) {
    std::wstring backupDir = GetBackupDir();
    if (backupDir.empty()) return false;

    std::wstring safeName = appName;
    std::replace(safeName.begin(), safeName.end(), L'\\', L'_');
    std::replace(safeName.begin(), safeName.end(), L'/', L'_');
    std::replace(safeName.begin(), safeName.end(), L':', L'_');

    wchar_t timestamp[64];
    SYSTEMTIME st;
    GetLocalTime(&st);
    swprintf_s(timestamp, L"%04d%02d%02d_%02d%02d%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::wstring backupFile = backupDir + L"\\" + safeName + L"_" + timestamp + L".reg";

    std::wstring cmd = L"reg export \"" + regPath + L"\" \"" + backupFile + L"\" /y";

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(0);

    if (CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return exitCode == 0;
    }
    return false;
}

static std::wstring PowerShellEscapeString(const std::wstring& input) {
    std::wstring result;
    result.reserve(input.size() + 16);
    for (wchar_t c : input) {
        switch (c) {
            case L'\'': result += L"''"; break;
            case L'`': result += L"``"; break;
            case L'"': result += L"`\""; break;
            case L'$': result += L"`$"; break;
            case L'\\': result += L"`\\"; break;
            default: result += c; break;
        }
    }
    return result;
}

bool Uninstaller::CreateRestorePoint(const std::wstring& appName) {
    std::wstring desc = L"BlackHole - Before removing: " + appName;

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD enable = 1;
        RegSetValueExW(hKey, L"RPSessionInterval", 0, REG_DWORD,
                       (BYTE*)&enable, sizeof(enable));
        RegCloseKey(hKey);
    }

    std::wstring safeDesc = PowerShellEscapeString(desc);
    std::wstring cmd = L"powershell.exe -NoProfile -Command \""
        L"Checkpoint-Computer -Description '" + safeDesc +
        L"' -RestorePointType 'APPLICATION_UNINSTALL'\"";

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(0);

    bool success = false;
    if (CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        success = (exitCode == 0);
    }

    if (!success) {
        std::wstring wmiCmd = L"powershell.exe -NoProfile -Command \""
            L"$sr = Get-CimClass -Namespace root\\default -ClassName SystemRestore; "
            L"if ($sr) { "
            L"  Invoke-CimMethod -ClassName SystemRestore -MethodName CreateRestorePoint "
            L"  -Arguments @{Description='" + safeDesc +
            L"'; RestorePointType=12; EventDescription='Application Uninstall'} "
            L"  | Select-Object -ExpandProperty ReturnValue } else { 1 }\"";

        std::vector<wchar_t> wmiBuf(wmiCmd.begin(), wmiCmd.end());
        wmiBuf.push_back(0);

        STARTUPINFOW wsi = { sizeof(wsi) };
        PROCESS_INFORMATION wpi = {};
        if (CreateProcessW(NULL, wmiBuf.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW,
                            NULL, NULL, &wsi, &wpi)) {
            WaitForSingleObject(wpi.hProcess, 30000);
            DWORD wmiExit = 0;
            GetExitCodeProcess(wpi.hProcess, &wmiExit);
            CloseHandle(wpi.hProcess);
            CloseHandle(wpi.hThread);
            success = (wmiExit == 0);
        }
    }
    return success;
}

// ═══════════════════════════════════════════════════════════════════════
//  System Restore Point via SRSetRestorePointW (fast, direct API)
// ═══════════════════════════════════════════════════════════════════════

#ifndef RESTOREPOINTINFOW
typedef struct _RESTOREPOINTINFOW {
    DWORD dwEventType;
    DWORD dwRestorePtType;
    LONGLONG llSequenceNumber;
    WCHAR szDescription[MAX_PATH];
} RESTOREPOINTINFOW, *PRESTOREPOINTINFOW;
#endif

#ifndef STATEMGRSTATUS
typedef struct _BH_STATEMGRSTATUS {
    ULONG nStatus;
    LONGLONG llSequenceNumber;
} BH_STATEMGRSTATUS, *PBH_STATEMGRSTATUS;
#endif

#ifndef BEGIN_SYSTEM_CHANGE
#define BEGIN_SYSTEM_CHANGE 100
#endif

#ifndef APPLICATION_UNINSTALL
#define APPLICATION_UNINSTALL 12
#endif

typedef BOOL (WINAPI *PFN_SRSetRestorePointW)(PRESTOREPOINTINFOW pRestorePtSpec, PBH_STATEMGRSTATUS pSMgrStatus);

bool Uninstaller::CreateSystemRestorePoint(const std::wstring& appName) {
    OutputDebugStringA("CreateSystemRestorePoint: starting\n");

    HINSTANCE hSR = LoadLibraryW(L"srclient.dll");
    if (!hSR) {
        OutputDebugStringA("CreateSystemRestorePoint: srclient.dll not found\n");
        return false;
    }

    auto pSRSetRestorePointW = (PFN_SRSetRestorePointW)GetProcAddress(hSR, "SRSetRestorePointW");
    if (!pSRSetRestorePointW) {
        OutputDebugStringA("CreateSystemRestorePoint: SRSetRestorePointW not found\n");
        FreeLibrary(hSR);
        return false;
    }

    std::wstring desc = L"BlackHole - Before removing: " + appName;

    RESTOREPOINTINFOW rpInfo = { 0 };
    rpInfo.dwEventType = BEGIN_SYSTEM_CHANGE;
    rpInfo.dwRestorePtType = APPLICATION_UNINSTALL;
    rpInfo.llSequenceNumber = 0;  // auto-assign
    wcsncpy_s(rpInfo.szDescription, MAX_PATH, desc.c_str(), _TRUNCATE);

    BH_STATEMGRSTATUS smStatus = { 0 };
    BOOL ok = pSRSetRestorePointW(&rpInfo, &smStatus);

    FreeLibrary(hSR);

    if (ok) {
        char _buf[256];
        snprintf(_buf, sizeof(_buf), "CreateSystemRestorePoint: SUCCESS seq=%lld status=%lu\n",
                 smStatus.llSequenceNumber, smStatus.nStatus);
        OutputDebugStringA(_buf);
    } else {
        char _buf[128];
        snprintf(_buf, sizeof(_buf), "CreateSystemRestorePoint: FAILED status=%lu\n",
                 smStatus.nStatus);
        OutputDebugStringA(_buf);
    }

    return ok == TRUE;
}

ForceRemovalResult Uninstaller::ForceRemovalPipeline(const UninstallEntry& entry,
                                                       ScanDepth depth,
                                                       bool createRestorePoint) {
    ForceRemovalResult result;
    Deletor deletor;

    if (createRestorePoint) {
        OutputDebugStringA("ForceRemovalPipeline: creating system restore point\n");
        CreateSystemRestorePoint(entry.displayName);
    }

    std::wstring resolvedPath = ResolveInstallPath(entry);

    if (!resolvedPath.empty() && std::filesystem::exists(resolvedPath)) {
        auto procs = deletor.GetProcessesLockingFile(resolvedPath);
        for (auto& proc : procs) {
            deletor.TerminateProcessIfSafe(proc.pid);
        }

        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (LookupPrivilegeValueW(NULL, SE_TAKE_OWNERSHIP_NAME, &tp.Privileges[0].Luid))
                AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
            if (LookupPrivilegeValueW(NULL, SE_RESTORE_NAME, &tp.Privileges[0].Luid))
                AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
            CloseHandle(hToken);
        }

        deletor.DeleteFileSafely(resolvedPath);
    }

    if (!entry.registryKey.empty()) {
        HKEY rootKey = HKEY_LOCAL_MACHINE;
        std::wstring regPath = entry.registryKey;
        if (regPath.find(L"HKCU\\") == 0 || regPath.find(L"HKEY_CURRENT_USER\\") == 0) {
            rootKey = HKEY_CURRENT_USER;
            if (regPath.find(L"HKCU\\") == 0) regPath = regPath.substr(5);
            else regPath = regPath.substr(18);
        } else {
            size_t firstSlash = regPath.find(L'\\');
            if (firstSlash != std::wstring::npos) {
                std::wstring root = regPath.substr(0, firstSlash);
                regPath = regPath.substr(firstSlash + 1);
                if (root == L"HKLM" || root == L"HKEY_LOCAL_MACHINE") rootKey = HKEY_LOCAL_MACHINE;
                else if (root == L"HKCU" || root == L"HKEY_CURRENT_USER") rootKey = HKEY_CURRENT_USER;
            }
        }
        RegDeleteTreeW(rootKey, regPath.c_str());
    }

    result.leftovers = ScanLeftovers(entry, depth);
    result.success = true;
    return result;
}

HICON ExtractProgramIcon(const std::wstring& displayIcon) {
    if (displayIcon.empty()) return NULL;

    std::wstring iconPath = displayIcon;
    int iconIndex = 0;

    size_t commaPos = iconPath.find_last_of(L',');
    if (commaPos != std::wstring::npos) {
        std::wstring idxStr = iconPath.substr(commaPos + 1);
        while (!idxStr.empty() && idxStr[0] == L' ')
            idxStr.erase(idxStr.begin());
        iconPath = iconPath.substr(0, commaPos);
        while (!iconPath.empty() && iconPath.back() == L' ')
            iconPath.pop_back();
        iconIndex = _wtoi(idxStr.c_str());
    }

    while (!iconPath.empty() && iconPath[0] == L'"')
        iconPath.erase(iconPath.begin());
    while (!iconPath.empty() && iconPath.back() == L'"')
        iconPath.pop_back();

    if (iconPath.empty()) return NULL;

    std::wstring ext = iconPath;
    size_t dotPos = ext.find_last_of(L'.');
    if (dotPos != std::wstring::npos) {
        ext = ext.substr(dotPos);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    }

    if (ext == L".png" || ext == L".jpg" || ext == L".jpeg" || ext == L".bmp") {
        HICON hIcon = ExtractIconFromPNG(iconPath);
        if (hIcon) return hIcon;
    }

    HICON hIcon = NULL;
    UINT extracted = ExtractIconExW(iconPath.c_str(), iconIndex, NULL, NULL, 1);
    if (extracted > 0 && extracted != (UINT)-1) {
        ExtractIconExW(iconPath.c_str(), iconIndex, &hIcon, NULL, 1);
    }
    return hIcon;
}

HICON ExtractIconFromPNG(const std::wstring& pngPath) {
    if (pngPath.empty()) return NULL;

    HANDLE hFile = CreateFileW(pngPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return NULL;
    }

    std::vector<BYTE> fileData(fileSize);
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, fileData.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    if (!ok || bytesRead != fileSize) return NULL;

    IStream* stream = NULL;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, fileSize);
    if (!hMem) return NULL;

    void* pMem = GlobalLock(hMem);
    memcpy(pMem, fileData.data(), fileSize);
    GlobalUnlock(hMem);

    if (CreateStreamOnHGlobal(hMem, TRUE, &stream) != S_OK) {
        GlobalFree(hMem);
        return NULL;
    }

    static std::once_flag gdiplusInitFlag;
    static ULONG_PTR gdiplusToken = 0;
    std::call_once(gdiplusInitFlag, []() {
        Gdiplus::GdiplusStartupInput input;
        Gdiplus::GdiplusStartup(&gdiplusToken, &input, NULL);
    });

    Gdiplus::Bitmap* bitmap = Gdiplus::Bitmap::FromStream(stream);
    stream->Release();

    if (!bitmap || bitmap->GetLastStatus() != Gdiplus::Ok) {
        delete bitmap;
        return NULL;
    }

    HICON hIcon = NULL;
    bitmap->GetHICON(&hIcon);
    delete bitmap;

    return hIcon;
}

std::wstring ResolveAppIconPath(const UninstallEntry& entry) {
    static const wchar_t* knownIconNames[] = {
        L"app.ico", L"icon.ico", L"logo.ico", L"appicon.ico",
        L"application.ico", L"DisplayIcon.ico", NULL
    };

    if (!entry.displayIcon.empty()) {
        std::wstring iconPath = entry.displayIcon;
        size_t commaPos = iconPath.find_last_of(L',');
        if (commaPos != std::wstring::npos)
            iconPath = iconPath.substr(0, commaPos);
        while (!iconPath.empty() && iconPath[0] == L'"')
            iconPath.erase(iconPath.begin());
        while (!iconPath.empty() && iconPath.back() == L'"')
            iconPath.pop_back();
        while (!iconPath.empty() && iconPath.back() == L' ')
            iconPath.pop_back();
        std::wstring lowerPath = iconPath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
        bool isMsiExec = (lowerPath.find(L"msiexec") != std::wstring::npos);
        if (!isMsiExec && GetFileAttributesW(iconPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return iconPath;
        }
    }

    if (!entry.uninstallString.empty()) {
        bool isMsiExec = false;
        std::wstring lower = entry.uninstallString;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        if (lower.find(L"msiexec") != std::wstring::npos)
            isMsiExec = true;

        if (isMsiExec) {
            size_t guidStart = entry.uninstallString.find(L'{');
            size_t guidEnd = entry.uninstallString.find(L'}', guidStart);
            if (guidStart != std::wstring::npos && guidEnd != std::wstring::npos) {
                std::wstring guid = entry.uninstallString.substr(guidStart, guidEnd - guidStart + 1);
                wchar_t iconBuf[MAX_PATH] = {};
                DWORD bufSize = MAX_PATH;
                UINT result = MsiGetProductInfoW(guid.c_str(),
                    L"ProductIcon", iconBuf, &bufSize);
                if (result == ERROR_SUCCESS && iconBuf[0] != L'\0') {
                    std::wstring msiIcon(iconBuf);
                    size_t comma = msiIcon.find_last_of(L',');
                    if (comma != std::wstring::npos)
                        msiIcon = msiIcon.substr(0, comma);
                    while (!msiIcon.empty() && msiIcon[0] == L'"')
                        msiIcon.erase(msiIcon.begin());
                    while (!msiIcon.empty() && msiIcon.back() == L'"')
                        msiIcon.pop_back();
                    if (GetFileAttributesW(msiIcon.c_str()) != INVALID_FILE_ATTRIBUTES) {
                        return msiIcon;
                    }
                }

                wchar_t pkgBuf[MAX_PATH] = {};
                DWORD pkgSize = MAX_PATH;
                result = MsiGetProductInfoW(guid.c_str(),
                    L"LocalPackage", pkgBuf, &pkgSize);
                if (result == ERROR_SUCCESS && pkgBuf[0] != L'\0') {
                    std::wstring msiPath(pkgBuf);
                    if (GetFileAttributesW(msiPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                        return msiPath;
                    }
                }
            }
        }
    }

    if (!entry.installPath.empty() && GetFileAttributesW(entry.installPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        for (const wchar_t** name = knownIconNames; *name; ++name) {
            std::wstring candidate = entry.installPath;
            if (candidate.back() != L'\\') candidate += L'\\';
            candidate += *name;
            if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
                return candidate;
        }
    }

    if (!entry.sortedExecutables.empty()) {
        for (size_t i = 0; i < entry.sortedExecutables.size() && i < 2; ++i) {
            std::wstring exePath = entry.sortedExecutables[i];
            if (exePath.find(L'\\') == std::wstring::npos && !entry.installPath.empty()) {
                exePath = entry.installPath;
                if (exePath.back() != L'\\') exePath += L'\\';
                exePath += entry.sortedExecutables[i];
            }
            if (GetFileAttributesW(exePath.c_str()) != INVALID_FILE_ATTRIBUTES)
                return exePath;
        }
    }

    if (!entry.installPath.empty() && GetFileAttributesW(entry.installPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        std::wstring search = entry.installPath;
        if (search.back() != L'\\') search += L'\\';
        search += L"*.exe";

        WIN32_FIND_DATAW fdata;
        HANDLE hFind = FindFirstFileW(search.c_str(), &fdata);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                std::wstring candidate = entry.installPath;
                if (candidate.back() != L'\\') candidate += L'\\';
                candidate += fdata.cFileName;
                FindClose(hFind);
                return candidate;
            } while (FindNextFileW(hFind, &fdata));
            FindClose(hFind);
        }
    }

    if (!entry.uninstallString.empty()) {
        std::wstring cmd = entry.uninstallString;
        size_t q1 = cmd.find(L'\"');
        if (q1 != std::wstring::npos) {
            size_t q2 = cmd.find(L'\"', q1 + 1);
            cmd = (q2 != std::wstring::npos) ? cmd.substr(q1 + 1, q2 - q1 - 1) : cmd.substr(q1 + 1);
        } else {
            size_t space = cmd.find(L' ');
            if (space != std::wstring::npos) cmd = cmd.substr(0, space);
        }
        if (GetFileAttributesW(cmd.c_str()) != INVALID_FILE_ATTRIBUTES)
            return cmd;
    }

    return L"imageres.dll,15";
}

HICON ExtractAppIcon(const UninstallEntry& entry) {
    std::wstring iconPath = ResolveAppIconPath(entry);

    if (iconPath == L"imageres.dll,15") {
        return NULL;
    }

    {
        DWORD attr = GetFileAttributesW(iconPath.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES) {
            wchar_t pathCopy[MAX_PATH];
            wcsncpy_s(pathCopy, iconPath.c_str(), MAX_PATH - 1);
            WORD iconIdx = 0;
            HICON hShellIcon = ExtractAssociatedIconW(NULL, pathCopy, &iconIdx);
            if (hShellIcon) return hShellIcon;
        }
    }

    if (!entry.sortedExecutables.empty()) {
        for (size_t i = 0; i < entry.sortedExecutables.size() && i < 2; ++i) {
            std::wstring exePath = entry.sortedExecutables[i];
            if (exePath.find(L'\\') == std::wstring::npos && !entry.installPath.empty()) {
                exePath = entry.installPath;
                if (exePath.back() != L'\\') exePath += L'\\';
                exePath += entry.sortedExecutables[i];
            }
            DWORD attr = GetFileAttributesW(exePath.c_str());
            if (attr == INVALID_FILE_ATTRIBUTES) continue;

            wchar_t pathCopy[MAX_PATH];
            wcsncpy_s(pathCopy, exePath.c_str(), MAX_PATH - 1);
            WORD iconIdx = 0;
            HICON hShellIcon = ExtractAssociatedIconW(NULL, pathCopy, &iconIdx);
            if (hShellIcon) return hShellIcon;
        }
    }

    if (!entry.installPath.empty() && GetFileAttributesW(entry.installPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        std::wstring search = entry.installPath;
        if (search.back() != L'\\') search += L'\\';
        search += L"*.exe";

        WIN32_FIND_DATAW fdata;
        HANDLE hFind = FindFirstFileW(search.c_str(), &fdata);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                std::wstring candidate = entry.installPath;
                if (candidate.back() != L'\\') candidate += L'\\';
                candidate += fdata.cFileName;
                wchar_t pathCopy[MAX_PATH];
                wcsncpy_s(pathCopy, candidate.c_str(), MAX_PATH - 1);
                WORD iconIdx = 0;
                HICON hShellIcon = ExtractAssociatedIconW(NULL, pathCopy, &iconIdx);
                if (hShellIcon) {
                    FindClose(hFind);
                    return hShellIcon;
                }
            } while (FindNextFileW(hFind, &fdata));
            FindClose(hFind);
        }
    }

    if (!entry.uninstallString.empty()) {
        std::wstring cmd = entry.uninstallString;
        size_t q1 = cmd.find(L'\"');
        if (q1 != std::wstring::npos) {
            size_t q2 = cmd.find(L'\"', q1 + 1);
            cmd = (q2 != std::wstring::npos) ? cmd.substr(q1 + 1, q2 - q1 - 1) : cmd.substr(q1 + 1);
        } else {
            size_t space = cmd.find(L' ');
            if (space != std::wstring::npos) cmd = cmd.substr(0, space);
        }
        std::wstring lower = cmd;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        if (lower.find(L"msiexec") == std::wstring::npos &&
            GetFileAttributesW(cmd.c_str()) != INVALID_FILE_ATTRIBUTES) {
            wchar_t pathCopy[MAX_PATH];
            wcsncpy_s(pathCopy, cmd.c_str(), MAX_PATH - 1);
            WORD iconIdx = 0;
            HICON hShellIcon = ExtractAssociatedIconW(NULL, pathCopy, &iconIdx);
            if (hShellIcon) return hShellIcon;
        }
    }

    HICON hIcon = ExtractProgramIcon(iconPath);
    if (hIcon) return hIcon;

    return NULL;
}

bool ExtractPEMetadata(const std::wstring& exePath, PEMetadata& outData) {
    if (exePath.empty()) return false;

    DWORD dummy;
    DWORD size = GetFileVersionInfoSizeW(exePath.c_str(), &dummy);
    if (size == 0) return false;

    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(exePath.c_str(), dummy, size, data.data()))
        return false;

    struct LangAndCodepage {
        WORD language;
        WORD codePage;
    };

    LangAndCodepage* lpTranslate = NULL;
    UINT cbTranslate = 0;
    if (!VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation",
                        (LPVOID*)&lpTranslate, &cbTranslate))
        return false;

    if (cbTranslate < sizeof(LangAndCodepage)) return false;

    wchar_t subBlock[256];
    LPVOID value = NULL;
    UINT valueLen = 0;

    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\CompanyName",
               lpTranslate[0].language, lpTranslate[0].codePage);
    if (VerQueryValueW(data.data(), subBlock, &value, &valueLen) && valueLen > 0) {
        outData.companyName = std::wstring((wchar_t*)value, valueLen - 1);
    }

    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\FileDescription",
               lpTranslate[0].language, lpTranslate[0].codePage);
    if (VerQueryValueW(data.data(), subBlock, &value, &valueLen) && valueLen > 0) {
        outData.fileDescription = std::wstring((wchar_t*)value, valueLen - 1);
    }

    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\ProductName",
               lpTranslate[0].language, lpTranslate[0].codePage);
    if (VerQueryValueW(data.data(), subBlock, &value, &valueLen) && valueLen > 0) {
        outData.productName = std::wstring((wchar_t*)value, valueLen - 1);
    }

    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\FileVersion",
               lpTranslate[0].language, lpTranslate[0].codePage);
    if (VerQueryValueW(data.data(), subBlock, &value, &valueLen) && valueLen > 0) {
        outData.fileVersion = std::wstring((wchar_t*)value, valueLen - 1);
    }

    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\ProductVersion",
               lpTranslate[0].language, lpTranslate[0].codePage);
    if (VerQueryValueW(data.data(), subBlock, &value, &valueLen) && valueLen > 0) {
        outData.productVersion = std::wstring((wchar_t*)value, valueLen - 1);
    }

    return true;
}

void EnrichEntryFromPE(UninstallEntry& entry) {
    std::wstring mainExe;

    if (!entry.sortedExecutables.empty() && !entry.installPath.empty()) {
        mainExe = entry.installPath + L"\\" + entry.sortedExecutables[0];
    }

    if (mainExe.empty() && !entry.displayIcon.empty()) {
        mainExe = entry.displayIcon;
        size_t commaPos = mainExe.find_last_of(L',');
        if (commaPos != std::wstring::npos)
            mainExe = mainExe.substr(0, commaPos);
        while (!mainExe.empty() && mainExe[0] == L'"')
            mainExe.erase(mainExe.begin());
        while (!mainExe.empty() && (mainExe.back() == L'"' || mainExe.back() == L' '))
            mainExe.pop_back();
    }

    if (mainExe.empty()) return;

    DWORD attr = GetFileAttributesW(mainExe.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return;

    PEMetadata meta;
    if (!ExtractPEMetadata(mainExe, meta)) return;

    if (entry.publisher.empty() && !meta.companyName.empty())
        entry.publisher = meta.companyName;

    if (entry.displayName.empty()) {
        if (!meta.fileDescription.empty())
            entry.displayName = meta.fileDescription;
        else if (!meta.productName.empty())
            entry.displayName = meta.productName;
    }

    if (entry.displayVersion.empty()) {
        if (!meta.productVersion.empty())
            entry.displayVersion = meta.productVersion;
        else if (!meta.fileVersion.empty())
            entry.displayVersion = meta.fileVersion;
    }

    entry.displayNameLower = entry.displayName;
    std::transform(entry.displayNameLower.begin(), entry.displayNameLower.end(),
                    entry.displayNameLower.begin(), ::towlower);
    entry.publisherLower = entry.publisher;
    std::transform(entry.publisherLower.begin(), entry.publisherLower.end(),
                    entry.publisherLower.begin(), ::towlower);
}

static std::wstring RunPowerShellCommand(const std::wstring& command) {
    std::wstring escaped = PowerShellEscapeString(command);
    std::wstring psCmd = L"powershell.exe -NoProfile -NonInteractive -Command \"" + escaped + L"\"";

    HANDLE hRead = NULL, hWrite = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa) };
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return L"";

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> cmdBuf(psCmd.begin(), psCmd.end());
    cmdBuf.push_back(0);

    std::wstring output;
    if (CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(hWrite);
        hWrite = NULL;

        char buf[4096];
        DWORD bytesRead = 0;
        while (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buf[bytesRead] = 0;
            int wideLen = MultiByteToWideChar(CP_UTF8, 0, buf, bytesRead, NULL, 0);
            if (wideLen > 0) {
                std::wstring wide(wideLen, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, buf, bytesRead, &wide[0], wideLen);
                output += wide;
            }
        }
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    if (hRead) CloseHandle(hRead);
    if (hWrite) CloseHandle(hWrite);
    return output;
}

static std::wstring TrimWhitespace(const std::wstring& s) {
    size_t start = s.find_first_not_of(L" \t\r\n");
    if (start == std::wstring::npos) return L"";
    size_t end = s.find_last_not_of(L" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::vector<UninstallEntry> Uninstaller::ScanStoreApps() {
    std::vector<UninstallEntry> results;

    std::wstring psOutput = RunPowerShellCommand(
        L"Get-AppxPackage | ForEach-Object { "
        L"$n=$_.Name; $d=$_.DisplayName; $p=$_.PublisherDisplayName; "
        L"$f=$_.PackageFamilyName; $i=$_.InstallLocation; "
        L"$v=$_.Version; Write-Output \"$n|$d|$p|$f|$i|$v\" }");

    if (psOutput.empty()) return results;

    std::wistringstream stream(psOutput);
    std::wstring line;

    while (std::getline(stream, line)) {
        line = TrimWhitespace(line);
        if (line.empty()) continue;

        std::vector<std::wstring> parts;
        std::wistringstream lineStream(line);
        std::wstring part;
        while (std::getline(lineStream, part, L'|')) {
            parts.push_back(TrimWhitespace(part));
        }
        if (parts.size() < 6) continue;

        UninstallEntry entry;
        entry.displayName = parts[1].empty() ? parts[0] : parts[1];
        entry.publisher = parts[2];
        entry.installPath = parts[4];
        entry.displayVersion = parts[5];
        entry.registryKey = L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + parts[3];

        std::wstring pkgFamily = parts[3];
        std::wstring safeName = PowerShellEscapeString(parts[0]);
        entry.uninstallString = L"powershell.exe -NoProfile -Command \"Remove-AppxPackage -Package '" +
                                safeName + L"' -Confirm:$false\"";

        entry.installerType = InstallerType::StoreApp;
        entry.isSystemComponent = false;

        if (!entry.installPath.empty() && std::filesystem::exists(entry.installPath)) {
            std::error_code ec;
            for (auto& f : std::filesystem::directory_iterator(entry.installPath, ec)) {
                if (ec) break;
                if (!f.is_directory()) {
                    std::wstring ext = f.path().extension().wstring();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
                    if (ext == L".exe" || ext == L".dll") {
                        std::wstring fn = f.path().filename().wstring();
                        std::transform(fn.begin(), fn.end(), fn.begin(), ::towlower);
                        entry.sortedExecutables.push_back(fn);
                    }
                }
            }
            std::sort(entry.sortedExecutables.begin(), entry.sortedExecutables.end());

            DWORD fileCount = 0;
            uint64_t totalSize = 0;
            for (auto& f : std::filesystem::recursive_directory_iterator(entry.installPath, ec)) {
                if (ec) break;
                fileCount++;
                totalSize += f.file_size(ec);
            }
            entry.estimatedSize = (DWORD)(totalSize / 1024);
        }

        entry.displayNameLower = entry.displayName;
        std::transform(entry.displayNameLower.begin(), entry.displayNameLower.end(),
                        entry.displayNameLower.begin(), ::towlower);
        entry.publisherLower = entry.publisher;
        std::transform(entry.publisherLower.begin(), entry.publisherLower.end(),
                        entry.publisherLower.begin(), ::towlower);
        entry.registryKeyLower = entry.registryKey;
        std::transform(entry.registryKeyLower.begin(), entry.registryKeyLower.end(),
                        entry.registryKeyLower.begin(), ::towlower);

        results.push_back(entry);
    }

    return results;
}

std::vector<UninstallEntry> Uninstaller::ScanDirectoryOrphans() {
    std::vector<UninstallEntry> results;

    std::vector<std::wstring> programFiles = {
        L"C:\\Program Files",
        L"C:\\Program Files (x86)"
    };

    for (const auto& pf : programFiles) {
        if (!std::filesystem::exists(pf)) continue;

        std::error_code ec;
        for (auto& dir : std::filesystem::directory_iterator(pf, ec)) {
            if (ec) break;
            if (!dir.is_directory()) continue;

            std::wstring dirName = dir.path().filename().wstring();
            std::wstring dirNameLower = dirName;
            std::transform(dirNameLower.begin(), dirNameLower.end(), dirNameLower.begin(), ::towlower);

            bool isRegistered = false;
            for (const auto& app : m_cachedApps) {
                std::wstring appPathLower = app.installPath;
                std::transform(appPathLower.begin(), appPathLower.end(), appPathLower.begin(), ::towlower);
                if (appPathLower.find(dirNameLower) != std::wstring::npos) {
                    isRegistered = true;
                    break;
                }
            }
            if (isRegistered) continue;

            UninstallEntry entry;
            entry.displayName = dirName;
            entry.installPath = dir.path().wstring();
            entry.isOrphaned = true;

            std::vector<std::wstring> exes;
            for (auto& f : std::filesystem::directory_iterator(dir.path(), ec)) {
                if (ec) break;
                if (!f.is_directory()) {
                    std::wstring ext = f.path().extension().wstring();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
                    if (ext == L".exe") {
                        std::wstring fn = f.path().filename().wstring();
                        std::transform(fn.begin(), fn.end(), fn.begin(), ::towlower);
                        exes.push_back(fn);
                    }
                }
            }
            std::sort(exes.begin(), exes.end());
            entry.sortedExecutables = exes;

            if (!exes.empty()) {
                entry.uninstallString = L"cmd.exe /c rmdir /s /q \"" + dir.path().wstring() + L"\"";
            }

            uint64_t totalSize = 0;
            for (auto& f : std::filesystem::recursive_directory_iterator(dir.path(), ec)) {
                if (ec) break;
                totalSize += f.file_size(ec);
            }
            entry.estimatedSize = (DWORD)(totalSize / 1024);

            auto ftt = dir.last_write_time(ec);
            if (!ec) {
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    ftt - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
                auto ticks = sctp.time_since_epoch().count();
                FILETIME ft;
                ft.dwLowDateTime = (DWORD)(ticks & 0xFFFFFFFF);
                ft.dwHighDateTime = (DWORD)((unsigned long long)ticks >> 32);
                SYSTEMTIME st;
                FileTimeToSystemTime(&ft, &st);
                wchar_t dateBuf[9];
                swprintf_s(dateBuf, L"%04d%02d%02d", st.wYear, st.wMonth, st.wDay);
                int oyr = st.wYear, omo = st.wMonth, ody = st.wDay;
                if (oyr >= 1990 && oyr <= 2099 && omo >= 1 && omo <= 12 && ody >= 1 && ody <= 31)
                    entry.installDate = dateBuf;
            }

            entry.displayNameLower = entry.displayName;
            std::transform(entry.displayNameLower.begin(), entry.displayNameLower.end(),
                            entry.displayNameLower.begin(), ::towlower);
            entry.publisherLower = entry.publisher;
            std::transform(entry.publisherLower.begin(), entry.publisherLower.end(),
                            entry.publisherLower.begin(), ::towlower);
            entry.registryKeyLower = entry.registryKey;
            std::transform(entry.registryKeyLower.begin(), entry.registryKeyLower.end(),
                            entry.registryKeyLower.begin(), ::towlower);

            if (entry.bitness == Bitness::Unknown) {
                std::wstring dirPath = dir.path().wstring();
                std::wstring dirPathLower = dirPath;
                std::transform(dirPathLower.begin(), dirPathLower.end(), dirPathLower.begin(), ::towlower);
                if (dirPathLower.find(L"c:\\program files (x86)") == 0)
                    entry.bitness = Bitness::X86;
                else if (dirPathLower.find(L"c:\\program files") == 0)
                    entry.bitness = Bitness::X64;
            }

            if (entry.publisher.empty()) {
                std::wstring parentName = dir.path().parent_path().filename().wstring();
                if (!parentName.empty() && parentName != L"Program Files" && parentName != L"Program Files (x86)") {
                    entry.publisher = parentName;
                    entry.publisherLower = parentName;
                    std::transform(entry.publisherLower.begin(), entry.publisherLower.end(),
                                    entry.publisherLower.begin(), ::towlower);
                }
            }

            if (entry.bitness == Bitness::Unknown && !entry.sortedExecutables.empty() && !entry.installPath.empty()) {
                std::wstring firstExe = entry.installPath + L"\\" + entry.sortedExecutables[0];
                Bitness detected = DetectBitness(firstExe);
                if (detected != Bitness::Unknown)
                    entry.bitness = detected;
            }

            results.push_back(entry);
        }
    }

    return results;
}

bool Uninstaller::UninstallStoreApp(const UninstallEntry& entry) {
    if (entry.uninstallString.empty()) {
        m_lastError = L"No uninstall string for store app";
        return false;
    }

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    std::wstring safeName = PowerShellEscapeString(entry.displayName);
    std::wstring cmd = L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \""
                       L"Get-AppxPackage -AllUsers | Where-Object {$_.Name -like '*" +
                       safeName +
                       L"*'} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue\"";

    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(0);

    if (CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 60000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return exitCode == 0;
    }

    m_lastError = L"Failed to launch PowerShell for store app removal";
    return false;
}

void Uninstaller::SortUninstallQueue(std::vector<UninstallEntry>& queue) {
    struct SortKey {
        int typeOrder;
        bool isSilent;
        bool isUpdate;
        bool isSystemComponent;
        DWORD estimatedSize;
        bool isMsi;
    };

    auto getKey = [](const UninstallEntry& e) -> SortKey {
        SortKey k{};
        switch (e.installerType) {
            case InstallerType::Nsis:      k.typeOrder = 0; break;
            case InstallerType::InnoSetup: k.typeOrder = 1; break;
            case InstallerType::Msi:       k.typeOrder = 2; break;
            case InstallerType::StoreApp:  k.typeOrder = 3; break;
            case InstallerType::InstallShield: k.typeOrder = 4; break;
            default:                       k.typeOrder = 5; break;
        }
        k.isSilent = (e.uninstallString.find(L"/S") != std::wstring::npos ||
                      e.uninstallString.find(L"/silent") != std::wstring::npos ||
                      e.uninstallString.find(L"/VERYSILENT") != std::wstring::npos ||
                      e.installerType == InstallerType::StoreApp);
        k.isUpdate = false;
        if (!e.displayName.empty()) {
            std::wstring dnLower = e.displayName;
            std::transform(dnLower.begin(), dnLower.end(), dnLower.begin(), ::towlower);
            k.isUpdate = (dnLower.find(L" update") != std::wstring::npos ||
                          dnLower.find(L"update for") != std::wstring::npos);
        }
        k.isSystemComponent = e.isSystemComponent;
        k.estimatedSize = e.estimatedSize;
        k.isMsi = e.isMsiInstaller;
        return k;
    };

    std::stable_sort(queue.begin(), queue.end(),
        [&getKey](const UninstallEntry& a, const UninstallEntry& b) {
            SortKey ka = getKey(a);
            SortKey kb = getKey(b);

            if (ka.isSystemComponent != kb.isSystemComponent)
                return !ka.isSystemComponent;

            if (ka.isUpdate != kb.isUpdate)
                return !ka.isUpdate;

            if (ka.typeOrder != kb.typeOrder)
                return ka.typeOrder < kb.typeOrder;

            if (ka.isMsi != kb.isMsi)
                return !ka.isMsi;

            if (ka.isSilent != kb.isSilent)
                return ka.isSilent;

            return ka.estimatedSize > kb.estimatedSize;
        });

    size_t msiStart = 0;
    while (msiStart < queue.size() && !queue[msiStart].isMsiInstaller)
        msiStart++;

    if (msiStart < queue.size()) {
        size_t msiEnd = msiStart;
        while (msiEnd < queue.size() && queue[msiEnd].isMsiInstaller)
            msiEnd++;

        std::stable_sort(queue.begin() + msiStart, queue.begin() + msiEnd,
            [](const UninstallEntry& a, const UninstallEntry& b) {
                return a.estimatedSize > b.estimatedSize;
            });
    }
}

CertStatus VerifyCertificate(const std::wstring& filePath) {
    if (filePath.empty()) return CertStatus::NotFound;

    std::wstring ext = filePath;
    size_t dotPos = ext.find_last_of(L'.');
    if (dotPos != std::wstring::npos) {
        ext = ext.substr(dotPos);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    }
    if (ext != L".exe" && ext != L".dll" && ext != L".sys" && ext != L".msi")
        return CertStatus::NotFound;

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return CertStatus::NotFound;

    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    BOOL ok = CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(),
                               CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                               CERT_QUERY_FORMAT_FLAG_BINARY,
                               0, NULL, NULL, NULL, &hStore, &hMsg, NULL);
    if (!ok || !hMsg) {
        CloseHandle(hFile);
        return CertStatus::NotFound;
    }

    DWORD signerInfoSize = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize);
    if (signerInfoSize == 0) {
        CryptMsgClose(hMsg);
        if (hStore) CertCloseStore(hStore, 0);
        CloseHandle(hFile);
        return CertStatus::NotFound;
    }

    std::vector<BYTE> signerInfoData(signerInfoSize);
    PCMSG_SIGNER_INFO pSignerInfo = (PCMSG_SIGNER_INFO)signerInfoData.data();
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &signerInfoSize)) {
        CryptMsgClose(hMsg);
        if (hStore) CertCloseStore(hStore, 0);
        CloseHandle(hFile);
        return CertStatus::NotFound;
    }

    CERT_INFO certInfo = {};
    certInfo.Issuer = pSignerInfo->Issuer;
    certInfo.SerialNumber = pSignerInfo->SerialNumber;

    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(
        hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_SUBJECT_CERT, &certInfo, NULL);

    if (!pCertContext) {
        CryptMsgClose(hMsg);
        if (hStore) CertCloseStore(hStore, 0);
        CloseHandle(hFile);
        return CertStatus::NotFound;
    }

    CertStatus result = CertStatus::Unverified;

    CryptMsgClose(hMsg);
    CertFreeCertificateContext(pCertContext);
    if (hStore) CertCloseStore(hStore, 0);
    CloseHandle(hFile);
    return result;
}

Bitness DetectBitness(const std::wstring& exePath) {
    if (exePath.empty()) return Bitness::Unknown;

    HANDLE hFile = CreateFileW(exePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return Bitness::Unknown;

    BYTE dosHeader[1024];
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, dosHeader, sizeof(dosHeader), &bytesRead, NULL) || bytesRead < 64) {
        CloseHandle(hFile);
        return Bitness::Unknown;
    }

    if (dosHeader[0] != 'M' || dosHeader[1] != 'Z') {
        CloseHandle(hFile);
        return Bitness::Unknown;
    }

    DWORD peOffset = *(DWORD*)(dosHeader + 60);
    if (peOffset + 4 + sizeof(IMAGE_FILE_HEADER) > bytesRead) {
        CloseHandle(hFile);
        return Bitness::Unknown;
    }

    SetFilePointer(hFile, peOffset, NULL, FILE_BEGIN);
    BYTE peSig[4];
    if (!ReadFile(hFile, peSig, 4, &bytesRead, NULL) || bytesRead != 4) {
        CloseHandle(hFile);
        return Bitness::Unknown;
    }
    if (peSig[0] != 'P' || peSig[1] != 'E' || peSig[2] != 0 || peSig[3] != 0) {
        CloseHandle(hFile);
        return Bitness::Unknown;
    }

    IMAGE_FILE_HEADER fileHeader;
    if (!ReadFile(hFile, &fileHeader, sizeof(fileHeader), &bytesRead, NULL) ||
        bytesRead != sizeof(fileHeader)) {
        CloseHandle(hFile);
        return Bitness::Unknown;
    }

    CloseHandle(hFile);

    switch (fileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386:  return Bitness::X86;
        case IMAGE_FILE_MACHINE_AMD64: return Bitness::X64;
        case IMAGE_FILE_MACHINE_ARM64: return Bitness::ARM64;
        default: return Bitness::Unknown;
    }
}

bool IsMicrosoftApp(const UninstallEntry& entry) {
    return entry.publisherLower.find(L"microsoft") != std::wstring::npos ||
           entry.displayNameLower.find(L"microsoft") != std::wstring::npos;
}

bool IsStoreApp(const UninstallEntry& entry) {
    return entry.registryKeyLower.find(L"microsoft\\windows\\currentversion\\uninstall\\microsoft.windows") != std::wstring::npos ||
           entry.registryKeyLower.find(L"microsoft\\windows\\currentversion\\uninstall\\microsoft.windowsstore") != std::wstring::npos ||
           entry.installerType == InstallerType::StoreApp;
}

void Uninstaller::GenerateQuietSwitches(UninstallEntry& entry) {
    if (!entry.quietUninstallString.empty()) return;
    if (entry.uninstallString.empty()) return;

    std::wstring cmd = entry.uninstallString;
    std::wstring cmdLower = cmd;
    std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::towlower);

    switch (entry.installerType) {
        case InstallerType::Nsis:
            if (cmdLower.find(L"/s") == std::wstring::npos)
                entry.quietUninstallString = cmd + L" /S";
            else
                entry.quietUninstallString = cmd;
            break;

        case InstallerType::InnoSetup:
            if (cmdLower.find(L"/verysilent") == std::wstring::npos) {
                entry.quietUninstallString = cmd + L" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART";
            } else {
                entry.quietUninstallString = cmd;
            }
            break;

        case InstallerType::Msi: {
            size_t guidStart = cmd.find(L'{');
            if (guidStart != std::wstring::npos) {
                size_t guidEnd = cmd.find(L'}', guidStart);
                if (guidEnd != std::wstring::npos) {
                    std::wstring guid = cmd.substr(guidStart, guidEnd - guidStart + 1);
                    entry.quietUninstallString =
                        L"msiexec.exe /x " + guid + L" /qn /norestart";
                }
            }
            if (entry.quietUninstallString.empty()) {
                size_t slashX = cmd.find(L"/x ");
                if (slashX == std::wstring::npos) slashX = cmd.find(L"/X ");
                if (slashX != std::wstring::npos) {
                    entry.quietUninstallString = cmd + L" /qn /norestart";
                } else {
                    entry.quietUninstallString = cmd + L" /qn /norestart";
                }
            }
            break;
        }

        case InstallerType::InstallShield:
            if (cmdLower.find(L"/s") == std::wstring::npos &&
                cmdLower.find(L"/silent") == std::wstring::npos)
                entry.quietUninstallString = cmd + L" /s /v\"/qn\"";
            else
                entry.quietUninstallString = cmd;
            break;

        case InstallerType::PowerShell:
            if (cmdLower.find(L"-noninteractive") == std::wstring::npos)
                entry.quietUninstallString = cmd + L" -NonInteractive -Force";
            else
                entry.quietUninstallString = cmd;
            break;

        case InstallerType::Chocolatey:
            entry.quietUninstallString = L"choco uninstall \"" + entry.displayName + L"\" -y --no-progress";
            break;

        case InstallerType::Scoop:
            entry.quietUninstallString = L"scoop uninstall \"" + entry.displayName + L"\"";
            break;

        case InstallerType::WindowsFeature:
            entry.quietUninstallString = cmd;
            break;

        case InstallerType::StoreApp:
            entry.quietUninstallString = cmd;
            break;

        case InstallerType::SdbInst:
            entry.quietUninstallString = cmd;
            break;

        default: {
            entry.quietUninstallString = cmd;
            break;
        }
    }
}

void Uninstaller::RunInfoAdders(std::vector<UninstallEntry>& entries) {
    for (auto& entry : entries) {
        GenerateQuietSwitches(entry);

        if (entry.bitness == Bitness::Unknown &&
            entry.registryKey.find(L"WOW6432Node") != std::wstring::npos)
            entry.bitness = Bitness::X86;

        if (entry.bitness == Bitness::Unknown && !entry.displayNameLower.empty()) {
            if (entry.displayNameLower.find(L"(x64)") != std::wstring::npos ||
                entry.displayNameLower.find(L" 64-bit") != std::wstring::npos ||
                entry.displayNameLower.find(L" (amd64)") != std::wstring::npos)
                entry.bitness = Bitness::X64;
            else if (entry.displayNameLower.find(L"(x86)") != std::wstring::npos ||
                     entry.displayNameLower.find(L" 32-bit") != std::wstring::npos)
                entry.bitness = Bitness::X86;
            else if (entry.displayNameLower.find(L"(arm64)") != std::wstring::npos)
                entry.bitness = Bitness::ARM64;
        }

        if (entry.estimatedSize == 0 && !entry.installPath.empty() &&
            std::filesystem::exists(entry.installPath)) {
            std::error_code ec;
            uint64_t totalBytes = 0;
            int fileCount = 0;
            for (auto& f : std::filesystem::recursive_directory_iterator(entry.installPath, ec)) {
                if (ec) break;
                if (!f.is_directory()) {
                    totalBytes += f.file_size(ec);
                    if (ec) break;
                    fileCount++;
                }
                if (fileCount > 50000 || totalBytes > (uint64_t)4ULL * 1024 * 1024 * 1024) break;
            }
            if (totalBytes > 0)
                entry.estimatedSize = (DWORD)(totalBytes / 1024);
        }

        if (entry.installDate.empty() && !entry.installPath.empty() &&
            std::filesystem::exists(entry.installPath)) {
            std::error_code ec;
            auto lwt = std::filesystem::last_write_time(entry.installPath, ec);
            if (!ec) {
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    lwt - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
                auto ticks = sctp.time_since_epoch().count();
                FILETIME ft;
                ft.dwLowDateTime = (DWORD)(ticks & 0xFFFFFFFF);
                ft.dwHighDateTime = (DWORD)((unsigned long long)ticks >> 32);
                SYSTEMTIME st;
                if (FileTimeToSystemTime(&ft, &st)) {
                    int yr = st.wYear, mo = st.wMonth, dy = st.wDay;
                    if (yr >= 1990 && yr <= 2099 && mo >= 1 && mo <= 12 && dy >= 1 && dy <= 31) {
                        wchar_t dbuf[9];
                        swprintf_s(dbuf, L"%04d%02d%02d", yr, mo, dy);
                        entry.installDate = dbuf;
                    }
                }
            }
        }

        std::wstring exePath;
        if (!entry.sortedExecutables.empty() && !entry.installPath.empty()) {
            exePath = entry.installPath + L"\\" + entry.sortedExecutables[0];
            if (GetFileAttributesW(exePath.c_str()) == INVALID_FILE_ATTRIBUTES)
                exePath.clear();
        }
        if (exePath.empty() && !entry.displayIcon.empty()) {
            std::wstring iconPath = entry.displayIcon;
            size_t commaPos = iconPath.find_last_of(L',');
            if (commaPos != std::wstring::npos)
                iconPath = iconPath.substr(0, commaPos);
            while (!iconPath.empty() && iconPath[0] == L'"')
                iconPath.erase(iconPath.begin());
            while (!iconPath.empty() && (iconPath.back() == L'"' || iconPath.back() == L' '))
                iconPath.pop_back();
            if (!iconPath.empty() && GetFileAttributesW(iconPath.c_str()) != INVALID_FILE_ATTRIBUTES)
                exePath = iconPath;
        }

        if (!exePath.empty()) {
            if (entry.certStatus == CertStatus::Unknown)
                entry.certStatus = VerifyCertificate(exePath);
            if (entry.bitness == Bitness::Unknown)
                entry.bitness = DetectBitness(exePath);
            EnrichEntryFromPE(entry);
        }

        if (entry.publisher.empty() && !entry.installPath.empty()) {
            std::wstring parentDir = entry.installPath;
            size_t lastSlash = parentDir.find_last_of(L'\\');
            if (lastSlash != std::wstring::npos) {
                entry.publisher = parentDir.substr(lastSlash + 1);
                entry.publisherLower = entry.publisher;
                std::transform(entry.publisherLower.begin(), entry.publisherLower.end(),
                                entry.publisherLower.begin(), ::towlower);
            }
        }

        if (entry.displayNameLower.empty()) {
            entry.displayNameLower = entry.displayName;
            std::transform(entry.displayNameLower.begin(), entry.displayNameLower.end(),
                            entry.displayNameLower.begin(), ::towlower);
        }
        if (entry.registryKeyLower.empty()) {
            entry.registryKeyLower = entry.registryKey;
            std::transform(entry.registryKeyLower.begin(), entry.registryKeyLower.end(),
                            entry.registryKeyLower.begin(), ::towlower);
        }
    }
}

void Uninstaller::DeduplicateEntries(std::vector<UninstallEntry>& entries) {
    if (entries.size() < 2) return;

    std::vector<bool> removed(entries.size(), false);

    for (size_t i = 0; i < entries.size(); i++) {
        if (removed[i]) continue;
        for (size_t j = i + 1; j < entries.size(); j++) {
            if (removed[j]) continue;

            const auto& a = entries[i];
            const auto& b = entries[j];

            if (!a.installPath.empty() && !b.installPath.empty() &&
                _wcsicmp(a.installPath.c_str(), b.installPath.c_str()) == 0) {
                if (!a.uninstallString.empty() && b.uninstallString.empty()) {
                    removed[j] = true;
                } else if (!b.uninstallString.empty() && a.uninstallString.empty()) {
                    removed[i] = true;
                    break;
                }
                continue;
            }

            if (a.displayNameLower == b.displayNameLower) {
                if (!a.publisherLower.empty() && !b.publisherLower.empty() &&
                    a.publisherLower == b.publisherLower) {
                    if (a.isSystemComponent != b.isSystemComponent) {
                        if (a.isSystemComponent) removed[i] = true;
                        else removed[j] = true;
                    } else if (a.estimatedSize > b.estimatedSize) {
                        removed[j] = true;
                    } else if (b.estimatedSize > a.estimatedSize) {
                        removed[i] = true;
                        break;
                    }
                }
            }

            if (!a.registryKeyLower.empty() && !b.registryKeyLower.empty()) {
                int dist = Sift4Distance(a.registryKeyLower, b.registryKeyLower);
                int maxLen = (int)max(a.registryKeyLower.size(), b.registryKeyLower.size());
                if (maxLen > 0 && dist < maxLen / 6) {
                    if (a.uninstallString.empty() && !b.uninstallString.empty()) {
                        removed[i] = true;
                        break;
                    } else if (b.uninstallString.empty() && !a.uninstallString.empty()) {
                        removed[j] = true;
                    }
                }
            }
        }
    }

    std::vector<UninstallEntry> result;
    result.reserve(entries.size());
    for (size_t i = 0; i < entries.size(); i++) {
        if (!removed[i])
            result.push_back(std::move(entries[i]));
    }
    entries = std::move(result);
}

static std::wstring EscapeJsonString(const std::wstring& s) {
    std::wstring result;
    result.reserve(s.size() + 10);
    for (wchar_t c : s) {
        switch (c) {
            case L'"':  result += L"\\\""; break;
            case L'\\': result += L"\\\\"; break;
            case L'\n': result += L"\\n"; break;
            case L'\r': result += L"\\r"; break;
            case L'\t': result += L"\\t"; break;
            default:
                if (c < 0x20) {
                    wchar_t buf[8];
                    swprintf_s(buf, L"\\u%04x", (unsigned int)c);
                    result += buf;
                } else {
                    result += c;
                }
        }
    }
    return result;
}

static std::wstring EscapeXmlString(const std::wstring& s) {
    std::wstring result;
    result.reserve(s.size() + 10);
    for (wchar_t c : s) {
        switch (c) {
            case L'&':  result += L"&amp;"; break;
            case L'<':  result += L"&lt;"; break;
            case L'>':  result += L"&gt;"; break;
            case L'"':  result += L"&quot;"; break;
            case L'\'': result += L"&apos;"; break;
            default:    result += c;
        }
    }
    return result;
}

bool Uninstaller::ExportToJSON(const std::vector<UninstallEntry>& entries, const std::wstring& filePath) {
    std::wofstream out(filePath, std::ios::binary);
    if (!out.is_open()) {
        m_lastError = L"Cannot open file for writing: " + filePath;
        return false;
    }

    out << L"{\n  \"applications\": [\n";

    for (size_t i = 0; i < entries.size(); i++) {
        const auto& e = entries[i];
        out << L"    {\n";
        out << L"      \"displayName\": \"" << EscapeJsonString(e.displayName) << L"\",\n";
        out << L"      \"displayVersion\": \"" << EscapeJsonString(e.displayVersion) << L"\",\n";
        out << L"      \"publisher\": \"" << EscapeJsonString(e.publisher) << L"\",\n";
        out << L"      \"installPath\": \"" << EscapeJsonString(e.installPath) << L"\",\n";
        out << L"      \"uninstallString\": \"" << EscapeJsonString(e.uninstallString) << L"\",\n";
        out << L"      \"quietUninstallString\": \"" << EscapeJsonString(e.quietUninstallString) << L"\",\n";
        out << L"      \"registryKey\": \"" << EscapeJsonString(e.registryKey) << L"\",\n";

        const wchar_t* typeStr = L"Unknown";
        switch (e.installerType) {
            case InstallerType::Msi:            typeStr = L"Msi"; break;
            case InstallerType::InnoSetup:      typeStr = L"InnoSetup"; break;
            case InstallerType::Nsis:           typeStr = L"Nsis"; break;
            case InstallerType::InstallShield:  typeStr = L"InstallShield"; break;
            case InstallerType::PowerShell:     typeStr = L"PowerShell"; break;
            case InstallerType::StoreApp:       typeStr = L"StoreApp"; break;
            case InstallerType::Chocolatey:     typeStr = L"Chocolatey"; break;
            case InstallerType::Scoop:          typeStr = L"Scoop"; break;
            case InstallerType::WindowsFeature: typeStr = L"WindowsFeature"; break;
            case InstallerType::SdbInst:        typeStr = L"SdbInst"; break;
            default: break;
        }
        out << L"      \"installerType\": \"" << typeStr << L"\",\n";

        const wchar_t* bitStr = L"Unknown";
        switch (e.bitness) {
            case Bitness::X86:   bitStr = L"x86"; break;
            case Bitness::X64:   bitStr = L"x64"; break;
            case Bitness::ARM64: bitStr = L"ARM64"; break;
            default: break;
        }
        out << L"      \"bitness\": \"" << bitStr << L"\",\n";

        const wchar_t* certStr = L"Unknown";
        switch (e.certStatus) {
            case CertStatus::NotFound:  certStr = L"NotFound"; break;
            case CertStatus::Verified:  certStr = L"Verified"; break;
            case CertStatus::Unverified: certStr = L"Unverified"; break;
            default: break;
        }
        out << L"      \"certStatus\": \"" << certStr << L"\",\n";

        out << L"      \"estimatedSizeKB\": " << e.estimatedSize << L",\n";
        out << L"      \"installDate\": \"" << EscapeJsonString(e.installDate) << L"\",\n";
        out << L"      \"isSystemComponent\": " << (e.isSystemComponent ? L"true" : L"false") << L",\n";
        out << L"      \"isMsiInstaller\": " << (e.isMsiInstaller ? L"true" : L"false") << L",\n";
        out << L"      \"isOrphaned\": " << (e.isOrphaned ? L"true" : L"false") << L",\n";
        out << L"      \"isProtected\": " << (e.isProtected ? L"true" : L"false") << L",\n";
        out << L"      \"isUpdate\": " << (e.isUpdate ? L"true" : L"false") << L",\n";
        out << L"      \"aboutUrl\": \"" << EscapeJsonString(e.aboutUrl) << L"\",\n";
        out << L"      \"installSource\": \"" << EscapeJsonString(e.installSource) << L"\",\n";
        out << L"      \"modifyPath\": \"" << EscapeJsonString(e.modifyPath) << L"\"\n";

        out << L"    }";
        if (i + 1 < entries.size()) out << L",";
        out << L"\n";
    }

    out << L"  ],\n";
    out << L"  \"totalCount\": " << entries.size() << L"\n";
    out << L"}\n";
    out.close();
    return true;
}

bool Uninstaller::ExportToXML(const std::vector<UninstallEntry>& entries, const std::wstring& filePath) {
    std::wofstream out(filePath, std::ios::binary);
    if (!out.is_open()) {
        m_lastError = L"Cannot open file for writing: " + filePath;
        return false;
    }

    out << L"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out << L"<BlackHoleExport>\n";
    out << L"  <Applications count=\"" << entries.size() << L"\">\n";

    for (const auto& e : entries) {
        out << L"    <Application>\n";
        out << L"      <DisplayName>" << EscapeXmlString(e.displayName) << L"</DisplayName>\n";
        out << L"      <DisplayVersion>" << EscapeXmlString(e.displayVersion) << L"</DisplayVersion>\n";
        out << L"      <Publisher>" << EscapeXmlString(e.publisher) << L"</Publisher>\n";
        out << L"      <InstallPath>" << EscapeXmlString(e.installPath) << L"</InstallPath>\n";
        out << L"      <UninstallString>" << EscapeXmlString(e.uninstallString) << L"</UninstallString>\n";
        out << L"      <QuietUninstallString>" << EscapeXmlString(e.quietUninstallString) << L"</QuietUninstallString>\n";
        out << L"      <RegistryKey>" << EscapeXmlString(e.registryKey) << L"</RegistryKey>\n";

        const wchar_t* typeStr = L"Unknown";
        switch (e.installerType) {
            case InstallerType::Msi:            typeStr = L"Msi"; break;
            case InstallerType::InnoSetup:      typeStr = L"InnoSetup"; break;
            case InstallerType::Nsis:           typeStr = L"Nsis"; break;
            case InstallerType::InstallShield:  typeStr = L"InstallShield"; break;
            case InstallerType::PowerShell:     typeStr = L"PowerShell"; break;
            case InstallerType::StoreApp:       typeStr = L"StoreApp"; break;
            case InstallerType::Chocolatey:     typeStr = L"Chocolatey"; break;
            case InstallerType::Scoop:          typeStr = L"Scoop"; break;
            case InstallerType::WindowsFeature: typeStr = L"WindowsFeature"; break;
            case InstallerType::SdbInst:        typeStr = L"SdbInst"; break;
            default: break;
        }
        out << L"      <InstallerType>" << typeStr << L"</InstallerType>\n";

        const wchar_t* bitStr = L"Unknown";
        switch (e.bitness) {
            case Bitness::X86:   bitStr = L"x86"; break;
            case Bitness::X64:   bitStr = L"x64"; break;
            case Bitness::ARM64: bitStr = L"ARM64"; break;
            default: break;
        }
        out << L"      <Bitness>" << bitStr << L"</Bitness>\n";

        const wchar_t* certStr = L"Unknown";
        switch (e.certStatus) {
            case CertStatus::NotFound:  certStr = L"NotFound"; break;
            case CertStatus::Verified:  certStr = L"Verified"; break;
            case CertStatus::Unverified: certStr = L"Unverified"; break;
            default: break;
        }
        out << L"      <CertStatus>" << certStr << L"</CertStatus>\n";

        out << L"      <EstimatedSizeKB>" << e.estimatedSize << L"</EstimatedSizeKB>\n";
        out << L"      <InstallDate>" << EscapeXmlString(e.installDate) << L"</InstallDate>\n";
        out << L"      <IsSystemComponent>" << (e.isSystemComponent ? L"true" : L"false") << L"</IsSystemComponent>\n";
        out << L"      <IsMsiInstaller>" << (e.isMsiInstaller ? L"true" : L"false") << L"</IsMsiInstaller>\n";
        out << L"      <IsOrphaned>" << (e.isOrphaned ? L"true" : L"false") << L"</IsOrphaned>\n";
        out << L"      <IsProtected>" << (e.isProtected ? L"true" : L"false") << L"</IsProtected>\n";
        out << L"      <IsUpdate>" << (e.isUpdate ? L"true" : L"false") << L"</IsUpdate>\n";
        out << L"      <AboutUrl>" << EscapeXmlString(e.aboutUrl) << L"</AboutUrl>\n";
        out << L"      <InstallSource>" << EscapeXmlString(e.installSource) << L"</InstallSource>\n";
        out << L"      <ModifyPath>" << EscapeXmlString(e.modifyPath) << L"</ModifyPath>\n";
        out << L"    </Application>\n";
    }

    out << L"  </Applications>\n";
    out << L"</BlackHoleExport>\n";
    out.close();
    return true;
}

}
