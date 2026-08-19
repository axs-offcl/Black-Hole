#include "deletion_engine.h"
#include "uninstaller.h"
#include "privilege.h"
#include "deletor.h"
#include "blacklist.h"
#include "logger.h"
#include "app_util.h"
#include <ShlObj.h>
#include <ShObjIdl.h>
#include <filesystem>
#include <fstream>

#ifndef WM_DELETION_COMPLETE
#define WM_DELETION_COMPLETE (WM_USER + 2)
#endif

extern std::wstring g_selectedFile;
extern std::atomic<bool> g_overrideActive;
extern bool g_sendToRecycleBin;

void PushNotification(const std::wstring& title, const std::wstring& detail, bool isError);

static void AppendToAuditLog(const std::wstring& path, const std::wstring& label) {
    PWSTR ap = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &ap))) {
        std::wstring wlp(ap);
        CoTaskMemFree(ap);
        wlp += L"\\BlackHole\\audit.log";
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t ts[64];
        swprintf_s(ts, L"%04d-%02d-%02d %02d:%02d:%02d.%03d",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        std::wstring entry = std::wstring(ts) + L" | " + label + L" | " + path + L"\n";
        SetFileAttributesW(wlp.c_str(), FILE_ATTRIBUTE_NORMAL);
        std::ofstream logF(WideToUtf8(wlp), std::ios::app | std::ios::out);
        if (logF.is_open()) {
            logF << WideToUtf8(entry);
            logF.flush();
            logF.close();
        }
    }
}

void SelectFile(HWND hwnd) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    bool comInited = SUCCEEDED(hr);

    IFileOpenDialog* pDialog = nullptr;
    hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_ALL, IID_PPV_ARGS(&pDialog));
    if (SUCCEEDED(hr)) {
        DWORD options;
        pDialog->GetOptions(&options);
        pDialog->SetOptions(options | FOS_FORCEFILESYSTEM);
        pDialog->SetTitle(L"Select File to Analyze");

        IShellItem* pItem = nullptr;
        hr = pDialog->Show(hwnd);
        if (SUCCEEDED(hr)) {
            pDialog->GetResult(&pItem);
            if (pItem) {
                PWSTR pszPath = nullptr;
                pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszPath);
                if (pszPath) {
                    g_selectedFile = pszPath;
                    CoTaskMemFree(pszPath);
                }
                pItem->Release();
            }
        }
        pDialog->Release();
    }

    if (comInited) CoUninitialize();
}

void SelectFolder(HWND hwnd) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    bool comInited = SUCCEEDED(hr);

    IFileOpenDialog* pDialog = nullptr;
    hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_ALL, IID_PPV_ARGS(&pDialog));
    if (SUCCEEDED(hr)) {
        DWORD options;
        pDialog->GetOptions(&options);
        pDialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
        pDialog->SetTitle(L"Select Folder to Analyze");

        IShellItem* pItem = nullptr;
        hr = pDialog->Show(hwnd);
        if (SUCCEEDED(hr)) {
            pDialog->GetResult(&pItem);
            if (pItem) {
                PWSTR pszPath = nullptr;
                pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszPath);
                if (pszPath) {
                    g_selectedFile = pszPath;
                    CoTaskMemFree(pszPath);
                }
                pItem->Release();
            }
        }
        pDialog->Release();
    }

    if (comInited) CoUninitialize();
}

void PerformDeletion(const std::wstring& path, HWND hwnd) {
    BlackHole::BlacklistModule blacklist;
    if (blacklist.IsInBlacklist(path) && !g_overrideActive.load()) {
        PushNotification(L"BLOCKED", L"File is in the blacklist", true);
        BlackHole::GetLogger().LogDeletion(BlackHole::LogEventType::DeletionBlocked, path);
        SendMessage(hwnd, WM_DELETION_COMPLETE, 0, (LPARAM)new std::wstring(path));
        return;
    }

    if (g_sendToRecycleBin) {
        BlackHole::Deletor deletor;
        bool ok = deletor.MoveToRecycleBin(path);
        if (ok) {
            PushNotification(L"Moved to Recycle Bin", std::filesystem::path(path).filename().wstring(), false);
            AppendToAuditLog(path, L"Recycled");
        } else {
            PushNotification(L"RECYCLE FAILED", L"Could not send to Recycle Bin", true);
            BlackHole::GetLogger().LogDeletion(BlackHole::LogEventType::DeletionFailed, path, L"Move to Recycle Bin failed");
        }
        SendMessage(hwnd, WM_DELETION_COMPLETE, 0, (LPARAM)new std::wstring(path));
        return;
    }

    BlackHole::PrivilegeManager priv;
    priv.EnableAllPrivileges();
    BlackHole::Deletor deletor;
    auto result = deletor.DeleteFileSafely(path);
    bool success = (result.result == BlackHole::DeletionResult::Success);
    bool scheduled = (result.result == BlackHole::DeletionResult::Scheduled_Reboot);
    if (success || scheduled) {
        std::wstring title = success ? L"DELETE SUCCESS" : L"DELETE SCHEDULED";
        PushNotification(title, result.errorMessage, !scheduled);
    } else {
        PushNotification(L"DELETE FAILED", result.errorMessage, true);
    }
    BlackHole::LogEventType logType = success
        ? (result.result == BlackHole::DeletionResult::Success
            ? BlackHole::LogEventType::DeletionSuccess : BlackHole::LogEventType::DeletionScheduled)
        : BlackHole::LogEventType::DeletionFailed;
    BlackHole::GetLogger().LogDeletion(logType, path, result.errorMessage, result.errorCode);
    SendMessage(hwnd, WM_DELETION_COMPLETE, 0, (LPARAM)new std::wstring(path));
}

void PerformLeftoverClean(const std::vector<BlackHole::LeftoverRef>& items,
                          const std::vector<bool>& checked, HWND hwnd) {
    int cleaned = 0, failed = 0;

    for (int i = 0; i < (int)items.size(); i++) {
        if (i >= (int)checked.size() || !checked[i]) continue;
        const auto& item = items[i];

        if (item.typeName == L"Registry") {
            size_t arrowPos = item.path.find(L" -> ");
            if (arrowPos != std::wstring::npos) {
                std::wstring keyPart = item.path.substr(0, arrowPos);
                std::wstring valName = item.path.substr(arrowPos + 4);

                HKEY rootKey = HKEY_LOCAL_MACHINE;
                std::wstring subKey = keyPart;
                if (subKey.find(L"HKLM\\") == 0 || subKey.find(L"HKLM/") == 0) {
                    rootKey = HKEY_LOCAL_MACHINE;
                    subKey = keyPart.substr(5);
                } else if (subKey.find(L"HKCU\\") == 0 || subKey.find(L"HKCU/") == 0) {
                    rootKey = HKEY_CURRENT_USER;
                    subKey = keyPart.substr(5);
                } else if (subKey.find(L"HKCR\\") == 0 || subKey.find(L"HKCR/") == 0) {
                    rootKey = HKEY_CLASSES_ROOT;
                    subKey = keyPart.substr(5);
                }

                HKEY hKey;
                if (RegOpenKeyExW(rootKey, subKey.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                    if (RegDeleteValueW(hKey, valName.c_str()) == ERROR_SUCCESS)
                        cleaned++;
                    else
                        failed++;
                    RegCloseKey(hKey);
                } else {
                    failed++;
                }
            } else {
                failed++;
            }
        } else if (item.typeName == L"Service") {
            std::wstring svcName = item.path;
            size_t svcPos = svcName.find(L"Service: ");
            if (svcPos != std::wstring::npos)
                svcName = svcName.substr(svcPos + 9);

            SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
            if (scm) {
                SC_HANDLE svc = OpenServiceW(scm, svcName.c_str(), DELETE);
                if (svc) {
                    if (DeleteService(svc))
                        cleaned++;
                    else
                        failed++;
                    CloseServiceHandle(svc);
                } else {
                    failed++;
                }
                CloseServiceHandle(scm);
            } else {
                failed++;
            }
        } else {
            DWORD attrs = GetFileAttributesW(item.path.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES) {
                if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
                    if (RemoveDirectoryW(item.path.c_str()))
                        cleaned++;
                    else
                        failed++;
                } else {
                    if (DeleteFileW(item.path.c_str()))
                        cleaned++;
                    else
                        failed++;
                }
            } else {
                failed++;
            }
        }
    }

    std::wstring msg = std::to_wstring(cleaned) + L" cleaned";
    if (failed > 0) msg += L", " + std::to_wstring(failed) + L" failed";
    PushNotification(L"LEFTOVER CLEAN", msg, failed > 0);
}
