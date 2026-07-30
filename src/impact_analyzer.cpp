#include "impact_analyzer.h"
#include "deletor.h"
#include <filesystem>
#include <algorithm>
#include <thread>
#include <Windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <psapi.h>
#include <winsvc.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")

namespace BlackHole {

static std::wstring GetFileExtension(const std::wstring& path) {
    auto pos = path.rfind(L'.');
    return (pos != std::wstring::npos) ? path.substr(pos) : L"";
}

static std::wstring GetFileName(const std::wstring& path) {
    auto pos = path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? path.substr(pos + 1) : path;
}

static std::wstring GetDirectoryName(const std::wstring& path) {
    auto pos = path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? path.substr(0, pos) : L"";
}

static std::wstring ToLower(const std::wstring& s) {
    std::wstring result = s;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}

static bool FileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES;
}

static ULONGLONG GetFileSize64(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) {
        ULARGE_INTEGER size;
        size.HighPart = fad.nFileSizeHigh;
        size.LowPart = fad.nFileSizeLow;
        return size.QuadPart;
    }
    return 0;
}

ImpactAnalysis ImpactAnalyzer::Analyze(const std::wstring& filePath) {
    ImpactAnalysis result;
    result.filePath = filePath;
    result.fileName = GetFileName(filePath);

    if (!FileExists(filePath)) {
        result.analyzed = false;
        return result;
    }

    GatherFileInfo(result);
    DetectLocks(result);
    ScanRegistryReferences(result);
    ScanServiceReferences(result);
    FindDependentApps(result);
    FindRelatedFiles(result);
    PredictLeftovers(result);
    CalculateRiskScore(result);
    result.analyzed = true;
    return result;
}

void ImpactAnalyzer::GatherFileInfo(ImpactAnalysis& result) {
    result.fileSize = GetFileSize64(result.filePath);
    result.fileType = GetFileExtension(result.filePath);

    // PE metadata
    DWORD dummy;
    DWORD verSize = GetFileVersionInfoSizeW(result.filePath.c_str(), &dummy);
    if (verSize > 0) {
        std::vector<BYTE> verData(verSize);
        if (GetFileVersionInfoW(result.filePath.c_str(), 0, verSize, verData.data())) {
            VS_FIXEDFILEINFO* ffi = nullptr;
            UINT len = 0;
            if (VerQueryValueW(verData.data(), L"\\", (void**)&ffi, &len) && ffi) {
                DWORD major = HIWORD(ffi->dwProductVersionMS);
                DWORD minor = LOWORD(ffi->dwProductVersionMS);
                DWORD build = HIWORD(ffi->dwProductVersionLS);
                DWORD revision = LOWORD(ffi->dwProductVersionLS);
                result.version = std::to_wstring(major) + L"." + std::to_wstring(minor) +
                    L"." + std::to_wstring(build) + L"." + std::to_wstring(revision);
            }

            struct Translate { WORD language; WORD codePage; };
            Translate* translate = nullptr;
            UINT transLen = 0;
            if (VerQueryValueW(verData.data(), L"\\VarFileInfo\\Translation", (void**)&translate, &transLen) && translate) {
                wchar_t prop[256];
                wchar_t block[256];
                swprintf_s(block, L"\\StringFileInfo\\%04x%04x\\CompanyName", translate[0].language, translate[0].codePage);
                if (VerQueryValueW(verData.data(), block, (void**)&prop, &len) && len > 0)
                    result.publisher = prop;
            }
        }
    }

    // Digital signature check
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = result.filePath.c_str();

    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.pPolicyCallbackData = nullptr;
    winTrustData.pSIPClientData = nullptr;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;
    winTrustData.hWVTStateData = nullptr;
    winTrustData.pwszURLReference = nullptr;
    winTrustData.dwUIContext = 0;

    LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &actionId, &winTrustData);
    result.isSigned = (status == ERROR_SUCCESS);

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &actionId, &winTrustData);

    result.isSystemFile = IsSystemCriticalPath(result.filePath);
}

void ImpactAnalyzer::DetectLocks(ImpactAnalysis& result) {
    Deletor deletor;
    auto locks = deletor.GetProcessesLockingFile(result.filePath);
    for (auto& lock : locks) {
        LockInfo info;
        info.pid = lock.pid;
        info.processName = lock.processName;
        info.isProtected = lock.isProtected;
        result.lockedBy.push_back(info);
    }
}

void ImpactAnalyzer::ScanRegistryReferences(ImpactAnalysis& result) {
    std::wstring fileName = ToLower(result.fileName);
    std::wstring dirName = ToLower(GetDirectoryName(result.filePath));

    struct RegScanInfo { HKEY root; const wchar_t* subKey; };
    RegScanInfo scans[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" },
        { HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    };

    for (auto& scan : scans) {
        HKEY hRoot;
        if (RegOpenKeyExW(scan.root, scan.subKey, 0, KEY_READ, &hRoot) != ERROR_SUCCESS) continue;

        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hRoot, nullptr, nullptr, nullptr, &subKeyCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD i = 0; i < subKeyCount && i < 500; i++) {
            wchar_t keyName[256];
            DWORD keyNameLen = 256;
            if (RegEnumKeyExW(hRoot, i, keyName, &keyNameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) continue;

            HKEY hSub;
            std::wstring fullPath = std::wstring(scan.subKey) + L"\\" + keyName;
            if (RegOpenKeyExW(scan.root, fullPath.c_str(), 0, KEY_READ, &hSub) != ERROR_SUCCESS) continue;

            DWORD valueType = 0;
            DWORD valueSize = 0;

            // Check common string values that might reference our file
            const wchar_t* valueNames[] = { L"InstallLocation", L"UninstallString", L"DisplayIcon", L"ExecutablePath", L"Image Path" };
            for (auto& vn : valueNames) {
                if (RegQueryValueExW(hSub, vn, nullptr, &valueType, nullptr, &valueSize) != ERROR_SUCCESS) continue;
                if (valueType != REG_SZ && valueType != REG_EXPAND_SZ) continue;
                if (valueSize == 0 || valueSize > 4096) continue;

                std::vector<wchar_t> buf(valueSize / sizeof(wchar_t) + 1, 0);
                if (RegQueryValueExW(hSub, vn, nullptr, nullptr, (LPBYTE)buf.data(), &valueSize) == ERROR_SUCCESS) {
                    std::wstring val = ToLower(std::wstring(buf.data()));
                    if (val.find(fileName) != std::wstring::npos || val.find(dirName) != std::wstring::npos) {
                        RegistryRef ref;
                        ref.keyPath = std::wstring(scan.root == HKEY_LOCAL_MACHINE ? L"HKLM\\" : L"HKCU\\") + fullPath;
                        ref.valueName = vn;
                        ref.valueData = buf.data();
                        result.registryRefs.push_back(ref);
                    }
                }
            }
            RegCloseKey(hSub);
        }
        RegCloseKey(hRoot);
    }
}

void ImpactAnalyzer::ScanServiceReferences(ImpactAnalysis& result) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

    if (bytesNeeded == 0) { CloseServiceHandle(scm); return; }

    std::vector<BYTE> buffer(bytesNeeded);
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr)) {
        CloseServiceHandle(scm);
        return;
    }

    ENUM_SERVICE_STATUS_PROCESSW* services = (ENUM_SERVICE_STATUS_PROCESSW*)buffer.data();
    std::wstring fileName = ToLower(result.fileName);
    std::wstring dirName = ToLower(GetDirectoryName(result.filePath));

    for (DWORD i = 0; i < servicesReturned; i++) {
        // Query the service's binary path
        SC_HANDLE svc = OpenServiceW(scm, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!svc) continue;

        DWORD configSize = 0;
        QueryServiceConfigW(svc, nullptr, 0, &configSize);
        if (configSize > 0) {
            std::vector<BYTE> configBuf(configSize);
            QUERY_SERVICE_CONFIGW* config = (QUERY_SERVICE_CONFIGW*)configBuf.data();
            if (QueryServiceConfigW(svc, config, configSize, &configSize)) {
                std::wstring binPath = ToLower(config->lpBinaryPathName);
                if (binPath.find(fileName) != std::wstring::npos || binPath.find(dirName) != std::wstring::npos) {
                    ServiceRef ref;
                    ref.serviceName = services[i].lpServiceName;
                    ref.displayName = services[i].lpDisplayName;
                    ref.startType = config->dwStartType;
                    ref.processId = services[i].ServiceStatusProcess.dwProcessId;
                    result.serviceRefs.push_back(ref);
                }
            }
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

void ImpactAnalyzer::FindDependentApps(ImpactAnalysis& result) {
    std::wstring dirName = GetDirectoryName(result.filePath);
    std::wstring dirNameLower = ToLower(dirName);

    struct RegScanInfo { HKEY root; const wchar_t* subKey; };
    RegScanInfo scans[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
    };

    for (auto& scan : scans) {
        HKEY hRoot;
        if (RegOpenKeyExW(scan.root, scan.subKey, 0, KEY_READ, &hRoot) != ERROR_SUCCESS) continue;

        DWORD subKeyCount = 0;
        RegQueryInfoKeyW(hRoot, nullptr, nullptr, nullptr, &subKeyCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD i = 0; i < subKeyCount && i < 500; i++) {
            wchar_t keyName[256];
            DWORD keyNameLen = 256;
            if (RegEnumKeyExW(hRoot, i, keyName, &keyNameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) continue;

            HKEY hSub;
            std::wstring fullPath = std::wstring(scan.subKey) + L"\\" + keyName;
            if (RegOpenKeyExW(scan.root, fullPath.c_str(), 0, KEY_READ, &hSub) != ERROR_SUCCESS) continue;

            // Read InstallLocation
            wchar_t installLoc[1024] = {};
            DWORD locSize = sizeof(installLoc);
            DWORD valueType = 0;
            if (RegQueryValueExW(hSub, L"InstallLocation", nullptr, &valueType, (LPBYTE)installLoc, &locSize) == ERROR_SUCCESS && locSize > 0) {
                std::wstring instLower = ToLower(installLoc);
                // Check if this app's install dir contains our file's directory
                if (!instLower.empty() && dirNameLower.find(instLower) != std::wstring::npos) {
                    wchar_t displayName[256] = {};
                    DWORD nameSize = sizeof(displayName);
                    if (RegQueryValueExW(hSub, L"DisplayName", nullptr, nullptr, (LPBYTE)displayName, &nameSize) == ERROR_SUCCESS) {
                        DependentApp app;
                        app.appName = displayName;
                        app.installPath = installLoc;
                        app.reason = L"File is within install directory";
                        result.dependentApps.push_back(app);
                    }
                }
                // Check if our file's directory contains the app's install dir
                else if (!instLower.empty() && instLower.find(dirNameLower) != std::wstring::npos) {
                    wchar_t displayName[256] = {};
                    DWORD nameSize = sizeof(displayName);
                    if (RegQueryValueExW(hSub, L"DisplayName", nullptr, nullptr, (LPBYTE)displayName, &nameSize) == ERROR_SUCCESS) {
                        DependentApp app;
                        app.appName = displayName;
                        app.installPath = installLoc;
                        app.reason = L"App installs within file's directory";
                        result.dependentApps.push_back(app);
                    }
                }
            }
            RegCloseKey(hSub);
        }
        RegCloseKey(hRoot);
    }
}

void ImpactAnalyzer::FindRelatedFiles(ImpactAnalysis& result) {
    std::wstring dir = GetDirectoryName(result.filePath);
    std::wstring baseName = ToLower(result.fileName);
    // Remove extension for matching
    auto dotPos = baseName.rfind(L'.');
    if (dotPos != std::wstring::npos) baseName = baseName.substr(0, dotPos);

    if (!FileExists(dir)) return;

    WIN32_FIND_DATAW findData;
    std::wstring searchPath = dir + L"\\*";
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        std::wstring name = findData.cFileName;
        if (name == L"." || name == L"..") continue;

        std::wstring fullPath = dir + L"\\" + name;
        bool isDir = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        // Match by name prefix or same extension
        std::wstring nameLower = ToLower(name);
        auto nameDot = nameLower.rfind(L'.');
        std::wstring nameBase = (nameDot != std::wstring::npos) ? nameLower.substr(0, nameDot) : nameLower;

        bool related = false;
        if (nameBase.find(baseName) != std::wstring::npos || baseName.find(nameBase) != std::wstring::npos)
            related = true;

        if (related && fullPath != result.filePath) {
            RelatedFile rf;
            rf.path = fullPath;
            rf.isDirectory = isDir;
            if (!isDir) {
                rf.fileSize = GetFileSize64(fullPath);
                result.totalRelatedSize += rf.fileSize;
            }
            result.relatedFiles.push_back(rf);
        }
    } while (FindNextFileW(hFind, &findData));
    FindClose(hFind);
}

void ImpactAnalyzer::PredictLeftovers(ImpactAnalysis& result) {
    // Add registry leftovers
    for (auto& ref : result.registryRefs) {
        LeftoverRef lr;
        lr.path = ref.keyPath + L" -> " + ref.valueName;
        lr.typeName = L"Registry";
        lr.description = ref.valueData;
        result.leftovers.push_back(lr);
    }

    // Add service leftovers
    for (auto& svc : result.serviceRefs) {
        LeftoverRef lr;
        lr.path = L"Service: " + svc.serviceName;
        lr.typeName = L"Service";
        lr.description = svc.displayName + L" (Start: " + std::to_wstring(svc.startType) + L")";
        result.leftovers.push_back(lr);
    }
}

void ImpactAnalyzer::CalculateRiskScore(ImpactAnalysis& result) {
    int score = 0;

    // File type risk
    std::wstring ext = ToLower(result.fileType);
    if (ext == L".dll" || ext == L".sys" || ext == L".drv") score += 25;
    else if (ext == L".exe") score += 15;
    else if (ext == L".ocx" || ext == L".ax") score += 20;

    // Lock risk
    if (!result.lockedBy.empty()) {
        score += 15;
        for (auto& lock : result.lockedBy) {
            if (lock.isProtected) score += 20;
        }
    }

    // Registry reference risk
    score += (int)result.registryRefs.size() * 5;
    if (score > 100) score = 100;

    // Service risk
    score += (int)result.serviceRefs.size() * 15;
    if (score > 100) score = 100;

    // Dependent app risk
    score += (int)result.dependentApps.size() * 10;
    if (score > 100) score = 100;

    // System file risk
    if (result.isSystemFile) score += 40;
    if (score > 100) score = 100;

    // Signed file reduces risk slightly
    if (result.isSigned) score -= 5;
    if (score < 0) score = 0;

    result.riskScore = score;

    if (score >= 80) result.riskLevel = RiskLevel::Critical;
    else if (score >= 60) result.riskLevel = RiskLevel::High;
    else if (score >= 40) result.riskLevel = RiskLevel::Medium;
    else if (score >= 20) result.riskLevel = RiskLevel::Low;
    else result.riskLevel = RiskLevel::Safe;

    // Generate recommendation
    if (result.riskLevel == RiskLevel::Critical) {
        result.recommendation = L"Dangerous: This file is critical to system stability or multiple apps. Use the Uninstaller tab for safe removal.";
    } else if (result.riskLevel == RiskLevel::High) {
        result.recommendation = L"Warning: Multiple dependencies found. Consider using the Uninstaller tab or reboot-based deletion.";
    } else if (result.riskLevel == RiskLevel::Medium) {
        result.recommendation = L"Caution: Some dependencies exist. Review the details below before proceeding.";
    } else if (result.riskLevel == RiskLevel::Low) {
        result.recommendation = L"Low risk: Minor dependencies found. Safe to delete with caution.";
    } else {
        result.recommendation = L"Safe: No significant dependencies detected. File can be deleted safely.";
    }
}

bool ImpactAnalyzer::IsSystemCriticalPath(const std::wstring& path) {
    std::wstring lower = ToLower(path);
    const wchar_t* criticalPaths[] = {
        L"c:\\windows\\system32",
        L"c:\\windows\\syswow64",
        L"c:\\windows\\winsxs",
        L"c:\\program files\\windows",
        L"c:\\program files\\microsoft",
        L"c:\\windows\\boot",
    };
    for (auto& cp : criticalPaths) {
        if (lower.find(cp) != std::wstring::npos) return true;
    }
    return false;
}

}
