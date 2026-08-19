#include <Windows.h>
#include <Windowsx.h>
#include <dwmapi.h>
#include <d3d11.h>
#include <dxgi.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <queue>
#include <functional>
#include <cmath>
#include <ctime>
#include <sstream>
#include <filesystem>
#include <unordered_map>
#include <exception>

#include <shellapi.h>
#include <shlobj.h>
#include <fstream>
#include <winhttp.h>
#include <TlHelp32.h>
#include "crash_handler.h"
#include "deletion_engine.h"
#include "process_util.h"
#include "toggle_window.h"
#include "icon_manager.h"
#include "bg_workers.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "dbghelp.lib")

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include "imgui_internal.h"
#include "deletor.h"
#include "blacklist.h"
#include "privilege.h"
#include "logger.h"
#include "uninstaller.h"
#include "impact_analyzer.h"
#include "embedded_font.h"
#include "embedded_lucide.h"
#include "embedded_logo_png.h"
#include <GdiPlus.h>
#include "app_util.h"
#include "app_config.h"
#include "context_menu.h"
#include "scan_delete_popup.h"
#include "install_monitor.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static bool g_SwapChainOccluded = false;
static UINT g_ResizeWidth = 0, g_ResizeHeight = 0;

HWND g_hMainWindow = nullptr;
static WNDCLASSEXW g_wc = {};
static NOTIFYICONDATAW g_nid = {};

static std::atomic<bool> g_running{true};
std::atomic<bool> g_overrideActive{false};
static std::atomic<bool> g_installStatus{false};

static char g_overrideInput[256] = "";
static bool g_phraseFocused = false;
static bool g_phraseWrong = false;
static float g_phraseWrongTimer = 0.0f;
std::wstring g_selectedFile = L"";
static std::vector<std::wstring> g_batchFiles;
static BlackHole::ImpactAnalysis g_impactAnalysis;
static std::atomic<bool> g_analysisRunning{false};
static std::atomic<bool> g_showLockDetails{false};
static std::atomic<bool> g_showRegistryDetails{false};
static std::atomic<bool> g_showServiceDetails{false};
static std::atomic<bool> g_showDependentDetails{false};
static std::atomic<bool> g_showRelatedDetails{false};
static std::atomic<bool> g_showLeftoverDetails{false};
static std::vector<bool> g_leftoverChecked;
static std::atomic<bool> g_showLeftoverCleanConfirm{false};
static std::vector<bool> g_lockedByChecked;
static std::vector<bool> g_dependentAppsChecked;
static std::vector<bool> g_registryRefsChecked;
static std::vector<bool> g_serviceRefsChecked;
static std::vector<bool> g_relatedFilesChecked;

static ImFont* g_fontDefault = nullptr;
static ImFont* g_fontSidebar = nullptr;
static ImFont* g_fontPill = nullptr;
static ImFont* g_fontIcon = nullptr;

#define WM_TRAYICON (WM_USER + 1)
#define WM_DELETION_COMPLETE (WM_USER + 2)

struct NotificationPopup {
    std::wstring title;
    std::wstring detail;
    std::string titleUtf8;
    std::string detailUtf8;
    bool isError;
    float timer = 0.f;
    float alpha = 0.f;
    bool active = true;
};

static std::vector<NotificationPopup> g_notifications;
static std::mutex g_notifMutex;
static std::vector<std::wstring> g_logEntries;
static std::vector<std::string> g_logEntriesUtf8;
static std::mutex g_logMutex;
static int g_selectedTab = 0;
bool g_autoAnalyzeOnStart = false;
bool g_installMonitorEnabled = false;
static std::atomic<bool> g_showDeleteConfirm{false};
static std::atomic<bool> g_showBatchConfirm{false};
static float g_analysisAnimTime = 0.0f;
static const wchar_t* BH_VERSION = L"2.0";

static std::vector<BlackHole::UninstallEntry> g_uninstallEntries;
std::vector<BlackHole::LeftoverItem> g_leftoverItems;
static std::vector<BlackHole::LeftoverItem> g_leftoverSnapshot;
static std::string g_uninstallFilter;
static bool g_uninstallFilterFocused = false;
static bool g_filterShowMicrosoft = true;
static bool g_filterShowPortable = true;
static bool g_filterShowStore = true;
static bool g_filterShowSystem = true;
static bool g_filterShowUpdates = true;
static bool g_filterShowProtected = true;
static bool g_filterShowOrphans = true;
static bool g_filterShowChocolatey = true;
static bool g_filterShowScoop = true;
static bool g_filterShowTweaks = true;
static bool g_filterShowUnregistered = true;
static int g_colorFilter = -1;
std::atomic<bool> g_scanComplete{false};
std::atomic<bool> g_initialScanStarted{false};
std::mutex g_scanResultMutex;
std::vector<BlackHole::UninstallEntry> g_scanResultPending;
std::atomic<bool> g_scanPhase{0};
static const char* g_scanPhaseNames[] = {
    "Scanning registry...", "Scanning registry...", "Scanning registry...",
    "Scanning Chocolatey...", "Scanning Scoop...",
    "Scanning Windows Features...", "Finalizing..."
};
static std::atomic<bool> g_scanComplete2{false};
static std::atomic<bool> g_initialScanStarted2{false};
static std::atomic<bool> g_scanPhase2Started{false};
static std::atomic<bool> g_scanPhase2Complete{false};
static std::mutex g_extrasMutex;
static std::vector<BlackHole::UninstallEntry> g_extrasPending;
std::atomic<bool> g_showLeftoverPopup{false};
static char g_leftoverSearchFilter[128] = {};
static BlackHole::ScanDepth g_scanDepth = BlackHole::ScanDepth::Safe;
std::mutex g_forceRemovalMutex;
static bool g_pendingStandardUninstall = false;
static BlackHole::UninstallEntry g_standardUninstallEntry;
static int g_standardUninstallIdx = -1;
std::atomic<bool> g_standardUninstallRunning{false};
static HANDLE g_standardUninstallThreadHandle = NULL;
int g_popupEraseIdx = -1;
static int g_selectedUninstallIdx = -1;
static int g_ctxMenuIdx = -1;

static std::vector<ProcessInfo> g_lockedProcesses;
static std::atomic<bool> g_showProcessKillDialog{false};

std::atomic<bool> g_batchLeftoverScanning{false};
std::atomic<int> g_batchLeftoverProgress{0};
std::atomic<int> g_batchLeftoverTotal{0};
std::atomic<bool> g_batchLeftoverComplete{false};
std::vector<BlackHole::LeftoverItem> g_batchLeftoverItems;
std::mutex g_batchLeftoverMutex;
std::vector<std::wstring> g_batchLeftoverProgramNames;
std::vector<std::wstring> g_batchPurgeNames;
std::mutex g_processKillMutex;
std::vector<ProcessInfo> g_pendingLockedProcesses;
static int g_uninstallSortCol = 0;
static bool g_uninstallSortAsc = true;
bool g_sendToRecycleBin = false;
bool g_createRestorePoint = true;
static float g_settingsScrollY = 0.0f;

static std::atomic<bool> g_showPropertiesModal{false};
static int g_propertiesIdx = -1;
bool g_sidebarGlowEnabled = true;
bool g_lineGlowEnabled = true;
bool g_hideSidebar = false;
bool g_hideDock = false;

static bool g_colVisible[11] = { true, true, true, true, true, true, true, true, true, true, true };
static const char* g_colNames[] = { "Program Name", "Publisher", "Size", "Installed On", "Cert", "Arch", "Version", "Kind", "Location", "Protected", "Sys Component" };
static std::atomic<bool> g_showColumnChooser{false};
static std::atomic<bool> g_showFilterChooser{false};
static std::vector<bool> g_rowSelected;
static std::atomic<bool> g_showDeleteSelectedConfirm{false};

HWND g_hToggleWnd = NULL;
bool g_windowTransparent = false;
float g_windowAlpha = 0.85f;
bool g_applyTransparencyNextFrame = false;
bool g_resizableWindow = false;
static bool g_isMaximized = false;
static ImVec2 g_mainWinPos;
static ImVec2 g_mainWinSize;
static std::vector<int> g_filteredIndicesCache;
static bool g_filteredIndicesDirty = true;
static std::string g_lastFilterText;
float g_sidebarGlowColor[3] = { 128.0f / 255.0f, 0.0f / 255.0f, 230.0f / 255.0f };
float g_lineGlowColor[3] = { 128.0f / 255.0f, 0.0f / 255.0f, 230.0f / 255.0f };

std::unordered_map<std::wstring, ID3D11ShaderResourceView*> g_iconCache;
std::mutex g_iconMutex;
std::atomic<bool> g_iconThreadRunning{false};
std::atomic<int> g_iconThreadGeneration{0};
static ID3D11ShaderResourceView* g_defaultIconSRV = nullptr;
static ID3D11ShaderResourceView* g_sidebarLogoSRV = nullptr;
static const size_t MAX_ICON_CACHE_ENTRIES = 2000;

std::atomic<int> g_texCreated(0);
std::atomic<int> g_texReleased(0);

struct PendingIcon { std::wstring key; HICON hIcon; };
std::vector<PendingIcon> g_pendingIcons;
std::mutex g_pendingIconMutex;

struct PendingCachedIcon { std::wstring key; std::vector<BYTE> pixels; };
std::vector<PendingCachedIcon> g_pendingCachedIcons;
std::mutex g_pendingCachedIconMutex;

static bool gDragging = false;
static POINT gDragOffset = {};
bool g_darkMode = true;

static const float SIDEBAR_W = 80.0f;
static const float TITLE_BAR_H = 36.0f;
static const float DOCK_BTN_H = 36.0f;
static const float DOCK_BTN_GAP = 2.0f;
static const float DOCK_GAP = 4.0f;
static const float DOCK_PAD = 6.0f;

bool g_dockExpanded = false;
static const float PI = 3.14159265359f;

static ImVec4 CLR_MAIN_BG      = ImVec4(0.016f, 0.016f, 0.020f, 1.0f);

static ImVec4 CLR_ROW_VERIFIED   = ImVec4(0.05f, 0.15f, 0.05f, 1.0f);
static ImVec4 CLR_ROW_UNVERIFIED = ImVec4(0.15f, 0.10f, 0.05f, 1.0f);
static ImVec4 CLR_ROW_ORPHANED   = ImVec4(0.15f, 0.08f, 0.05f, 1.0f);
static ImVec4 CLR_ROW_STORE      = ImVec4(0.05f, 0.08f, 0.15f, 1.0f);
static ImVec4 CLR_ROW_INVALID    = ImVec4(0.08f, 0.08f, 0.08f, 1.0f);
static ImVec4 CLR_ROW_UPDATE     = ImVec4(0.12f, 0.08f, 0.15f, 1.0f);
static ImVec4 CLR_SIDEBAR_BG   = ImVec4(0.024f, 0.024f, 0.028f, 1.0f);
static ImVec4 CLR_CHILD_BG     = ImVec4(0.031f, 0.031f, 0.039f, 1.0f);
static ImVec4 CLR_STROKE       = ImVec4(0.055f, 0.055f, 0.063f, 1.0f);
static ImVec4 CLR_ACCENT       = ImVec4(0.557f, 0.518f, 1.0f, 1.0f);
static ImVec4 CLR_TEXT         = ImVec4(0.92f, 0.92f, 0.94f, 1.0f);
static ImVec4 CLR_TEXT_DIM     = ImVec4(0.40f, 0.40f, 0.47f, 1.0f);
static ImVec4 CLR_ELEM_BG      = ImVec4(0.031f, 0.031f, 0.039f, 1.0f);
static ImVec4 CLR_ELEM_BG_HOVER= ImVec4(0.055f, 0.055f, 0.063f, 1.0f);
static ImVec4 CLR_POPUP_BG     = ImVec4(0.039f, 0.039f, 0.055f, 0.94f);

static void ApplyTheme() {
    if (g_darkMode) {
        CLR_MAIN_BG    = ImVec4(0.016f, 0.016f, 0.020f, 1.0f);
        CLR_SIDEBAR_BG = ImVec4(0.024f, 0.024f, 0.028f, 1.0f);
        CLR_CHILD_BG   = ImVec4(0.031f, 0.031f, 0.039f, 1.0f);
        CLR_STROKE     = ImVec4(0.14f, 0.14f, 0.17f, 1.0f);
        CLR_TEXT       = ImVec4(0.92f, 0.92f, 0.94f, 1.0f);
        CLR_TEXT_DIM   = ImVec4(0.40f, 0.40f, 0.47f, 1.0f);
        CLR_ELEM_BG    = ImVec4(0.031f, 0.031f, 0.039f, 1.0f);
        CLR_ELEM_BG_HOVER = ImVec4(0.055f, 0.055f, 0.063f, 1.0f);
        CLR_POPUP_BG   = ImVec4(0.039f, 0.039f, 0.055f, 0.94f);
    } else {
        CLR_MAIN_BG    = ImVec4(0.94f, 0.94f, 0.96f, 1.0f);
        CLR_SIDEBAR_BG = ImVec4(0.90f, 0.90f, 0.92f, 1.0f);
        CLR_CHILD_BG   = ImVec4(0.97f, 0.97f, 0.98f, 1.0f);
        CLR_STROKE     = ImVec4(0.80f, 0.80f, 0.83f, 1.0f);
        CLR_TEXT       = ImVec4(0.10f, 0.10f, 0.12f, 1.0f);
        CLR_TEXT_DIM   = ImVec4(0.45f, 0.45f, 0.50f, 1.0f);
        CLR_ELEM_BG    = ImVec4(0.88f, 0.88f, 0.90f, 1.0f);
        CLR_ELEM_BG_HOVER = ImVec4(0.82f, 0.82f, 0.85f, 1.0f);
        CLR_POPUP_BG   = ImVec4(0.92f, 0.92f, 0.94f, 0.94f);
    }

    // Auto-adapt glow colors to maintain contrast when theme changes
    static bool lastDarkForGlow = !g_darkMode;

    if (lastDarkForGlow != g_darkMode) {
        // Scale brightness: dark theme needs brighter colors, light theme needs darker
        float scale = g_darkMode ? 1.4f : 0.6f;
        auto adaptColor = [scale](float c[3]) {
            for (int i = 0; i < 3; i++) {
                c[i] = c[i] * scale;
                if (c[i] > 1.0f) c[i] = 1.0f;
                if (c[i] < 0.0f) c[i] = 0.0f;
            }
        };
        adaptColor(g_sidebarGlowColor);
        adaptColor(g_lineGlowColor);
        lastDarkForGlow = g_darkMode;
    }

    if (ImGui::GetCurrentContext()) {
        ImGuiStyle& style = ImGui::GetStyle();
        style.Colors[ImGuiCol_WindowBg] = CLR_MAIN_BG;
        style.Colors[ImGuiCol_ChildBg] = ImVec4(0, 0, 0, 0);
        style.Colors[ImGuiCol_Border] = CLR_STROKE;
        style.Colors[ImGuiCol_FrameBg] = CLR_ELEM_BG;
        style.Colors[ImGuiCol_FrameBgHovered] = CLR_ELEM_BG_HOVER;
        style.Colors[ImGuiCol_FrameBgActive] = CLR_ELEM_BG_HOVER;
        style.Colors[ImGuiCol_Button] = CLR_ELEM_BG;
        style.Colors[ImGuiCol_ButtonHovered] = CLR_ELEM_BG_HOVER;
        style.Colors[ImGuiCol_ButtonActive] = CLR_ELEM_BG_HOVER;
        style.Colors[ImGuiCol_Text] = CLR_TEXT;
        style.Colors[ImGuiCol_TextDisabled] = CLR_TEXT_DIM;
        if (g_darkMode) {
            style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.02f, 0.02f, 0.025f, 1.0f);
            style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.35f, 0.33f, 0.45f, 1.0f);
            style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.48f, 0.44f, 0.65f, 1.0f);
            style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.55f, 0.48f, 0.95f, 1.0f);
        } else {
            style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.88f, 0.88f, 0.90f, 1.0f);
            style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.60f, 0.60f, 0.65f, 1.0f);
            style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.50f, 0.50f, 0.55f, 1.0f);
            style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.35f, 0.32f, 0.80f, 1.0f);
        }
    }
}

static bool CreateDeviceD3D(HWND hWnd);
static void CleanupDeviceD3D();
static void ResizeSwapChain();

static void RenderSidebarTextGradient(const char* text, float spacing, ImVec2 pos1, ImVec2 pos2,
    float topAlpha, float botAlpha, ImVec4 accentCol) {
    float maxW = 0, totalH = 0;
    const char* t = text;
    int charCount = 0;
    while (*t) {
        if (*t != '\n' && *t != ' ') {
            float w = ImGui::CalcTextSize(t, t + 1).x;
            if (w > maxW) maxW = w;
            totalH += ImGui::GetTextLineHeight() + spacing;
            charCount++;
        }
        t++;
    }
    totalH -= spacing;
    if (charCount == 0) return;

    float centerX = (pos1.x + pos2.x) / 2.0f - maxW / 2.0f;
    ImVec2 pos;
    pos.y = (pos1.y + pos2.y) / 2.0f - totalH / 2.0f;
    pos.x = centerX;

    float regionH = pos2.y - pos1.y;

    const char* p = text;
    while (*p) {
        if (*p != '\n' && *p != ' ') {
            float charCenterY = pos.y + ImGui::GetTextLineHeight() / 2.0f;
            float tNorm = (regionH > 0) ? ImClamp((charCenterY - pos1.y) / regionH, 0.0f, 1.0f) : 0.0f;
            float a = topAlpha + (botAlpha - topAlpha) * tNorm;
            ImU32 col = IM_COL32((int)(accentCol.x * 255), (int)(accentCol.y * 255), (int)(accentCol.z * 255), (int)(a * 255));
            ImGui::SetCursorScreenPos(pos);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col), "%c", *p);
            pos.y += ImGui::GetTextLineHeight() + spacing;
        }
        p++;
    }
}

static ImU32 AccentU32(float alpha = 1.0f) {
    return IM_COL32((int)(CLR_ACCENT.x*255), (int)(CLR_ACCENT.y*255), (int)(CLR_ACCENT.z*255), (int)(alpha*255));
}

static ImU32 Vec4ToU32(const ImVec4& c, float alphaMul = 1.0f) {
    return IM_COL32((int)(c.x*255), (int)(c.y*255), (int)(c.z*255), (int)(c.w*alphaMul*255));
}


void PushNotification(const std::wstring& title, const std::wstring& detail, bool isError);


static void CheckForUpdates(HWND parentHwnd) {
    HINTERNET hSession = WinHttpOpen(L"BlackHole/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        PushNotification(L"UPDATE CHECK FAILED", L"Could not initialize network connection.", true);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.github.com",
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        PushNotification(L"UPDATE CHECK FAILED", L"Could not connect to server.", true);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET",
        L"/repos/axs-offcl/Black-Hole/releases/latest",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        PushNotification(L"UPDATE CHECK FAILED", L"Could not create request.", true);
        return;
    }

    BOOL sent = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!sent || !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        PushNotification(L"UPDATE CHECK FAILED", L"No response from server.", true);
        return;
    }

    std::string responseBody;
    DWORD bytesAvailable = 0;
    while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        std::vector<char> buffer(bytesAvailable + 1, 0);
        DWORD bytesRead = 0;
        WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead);
        responseBody.append(buffer.data(), bytesRead);
        bytesAvailable = 0;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    std::string tagName;
    {
        std::string key = "\"tag_name\"";
        auto pos = responseBody.find(key);
        if (pos != std::string::npos) {
            auto colonPos = responseBody.find(':', pos + key.size());
            auto firstQuote = responseBody.find('"', colonPos + 1);
            auto secondQuote = responseBody.find('"', firstQuote + 1);
            if (firstQuote != std::string::npos && secondQuote != std::string::npos)
                tagName = responseBody.substr(firstQuote + 1, secondQuote - firstQuote - 1);
        }
    }

    if (tagName.empty()) {
        std::string errMsg = "No releases found on GitHub.";
        auto msgPos = responseBody.find("\"message\"");
        if (msgPos != std::string::npos) {
            auto q1 = responseBody.find('"', msgPos + 10);
            auto q2 = responseBody.find('"', q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos)
                errMsg = responseBody.substr(q1 + 1, q2 - q1 - 1);
        }
        std::wstring wErr(errMsg.begin(), errMsg.end());
        PushNotification(L"UPDATE CHECK FAILED", wErr, true);
        return;
    }

    std::string versionStr = tagName;
    if (!versionStr.empty() && (versionStr[0] == 'v' || versionStr[0] == 'V'))
        versionStr = versionStr.substr(1);

    std::vector<int> remoteParts;
    std::string::size_type pos = 0, found;
    std::string temp = versionStr;
    while ((found = temp.find('.', pos)) != std::string::npos) {
        remoteParts.push_back(std::stoi(temp.substr(pos, found - pos)));
        pos = found + 1;
    }
    remoteParts.push_back(std::stoi(temp.substr(pos)));

    std::wstring curVerW(BH_VERSION);
    std::string curVer;
    curVer.reserve(curVerW.size());
    for (wchar_t wc : curVerW) curVer.push_back((char)wc);
    std::vector<int> localParts;
    pos = 0;
    while ((found = curVer.find('.', pos)) != std::string::npos) {
        localParts.push_back(std::stoi(curVer.substr(pos, found - pos)));
        pos = found + 1;
    }
    localParts.push_back(std::stoi(curVer.substr(pos)));

    bool hasUpdate = false;
    size_t maxLen = remoteParts.size() > localParts.size() ? remoteParts.size() : localParts.size();
    for (size_t i = 0; i < maxLen; i++) {
        int r = i < remoteParts.size() ? remoteParts[i] : 0;
        int l = i < localParts.size() ? localParts[i] : 0;
        if (r > l) { hasUpdate = true; break; }
        if (r < l) break;
    }

    if (hasUpdate) {
        std::wstring dlUrl = L"https://github.com/axs-offcl/Black-Hole/releases/download/"
            + std::wstring(tagName.begin(), tagName.end())
            + L"/BlackHole.exe";

        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring exePath = std::wstring(tempPath) + L"BlackHole_v" +
            std::wstring(versionStr.begin(), versionStr.end()) + L".exe";

        HINTERNET dlSession = WinHttpOpen(L"BlackHole/2.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        HINTERNET dlConnect = WinHttpConnect(dlSession, L"github.com",
            INTERNET_DEFAULT_HTTPS_PORT, 0);
        std::wstring urlPath = L"/axs-offcl/Black-Hole/releases/download/"
            + std::wstring(tagName.begin(), tagName.end()) + L"/BlackHole.exe";
        HINTERNET dlRequest = WinHttpOpenRequest(dlConnect, L"GET", urlPath.c_str(),
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

        if (dlSession && dlConnect && dlRequest &&
            WinHttpSendRequest(dlRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(dlRequest, NULL)) {

            std::ofstream dlFile(exePath, std::ios::binary | std::ios::out);
            if (dlFile.is_open()) {
                DWORD avail = 0;
                while (WinHttpQueryDataAvailable(dlRequest, &avail) && avail > 0) {
                    std::vector<char> buf(avail, 0);
                    DWORD read = 0;
                    WinHttpReadData(dlRequest, buf.data(), avail, &read);
                    dlFile.write(buf.data(), read);
                    avail = 0;
                }
                dlFile.close();

                std::wstring verStrW(versionStr.begin(), versionStr.end());
                std::wstring detail = L"Updated to v" + verStrW + L" - restart to apply";
                PushNotification(L"UPDATE SUCCESS", detail, false);

                ShellExecuteW(NULL, L"open", exePath.c_str(), NULL, NULL, SW_SHOWNORMAL);
            }
        }

        if (dlRequest) WinHttpCloseHandle(dlRequest);
        if (dlConnect) WinHttpCloseHandle(dlConnect);
        if (dlSession) WinHttpCloseHandle(dlSession);
    } else {
        std::wstring curVerW2(BH_VERSION);
        std::wstring detail = L"You have the latest version (v" + curVerW2 + L")";
        PushNotification(L"NO NEW UPDATE", detail, false);
    }
}

static void LoadLogs() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_logEntries.clear();
    g_logEntriesUtf8.clear();
    PWSTR appDataPath = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appDataPath)))
        return;
    std::wstring wLogPath(appDataPath);
    CoTaskMemFree(appDataPath);
    wLogPath += L"\\BlackHole\\audit.log";

    std::string logPath8 = WideToUtf8(wLogPath);
    std::ifstream logFile(logPath8);
    if (!logFile.is_open())
        return;

    std::string line;
    while (std::getline(logFile, line)) {
        if (!line.empty() && line.size() > 5) {
            bool isDeletionEntry = (line.find("| Deleted | ") != std::string::npos) ||
                                   (line.find("| Failed | ") != std::string::npos) ||
                                   (line.find("| Blocked | ") != std::string::npos) ||
                                   (line.find("| Scheduled | ") != std::string::npos) ||
                                   (line.find("| Recycled | ") != std::string::npos);
            if (!isDeletionEntry) continue;
            g_logEntries.push_back(Utf8ToWide(line));
            if (line.size() > 110) line = line.substr(0, 107) + "...";
            g_logEntriesUtf8.push_back(std::move(line));
        }
    }
}

static void RemoveLogEntryFromDisk(const std::string& timestamp) {
    PWSTR ap = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &ap))) return;
    std::wstring logDir(ap);
    CoTaskMemFree(ap);
    logDir += L"\\BlackHole";
    std::wstring logPath = logDir + L"\\audit.log";
    SetFileAttributesW(logPath.c_str(), FILE_ATTRIBUTE_NORMAL);

    for (int attempt = 0; attempt < 3; attempt++) {
        HANDLE hFile = CreateFileW(logPath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) { Sleep(50); continue; }

        DWORD fSize = GetFileSize(hFile, NULL);
        if (fSize == 0 || fSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return; }
        std::vector<char> buf(fSize);
        DWORD bytesRead = 0;
        BOOL ok = ReadFile(hFile, buf.data(), fSize, &bytesRead, NULL);
        CloseHandle(hFile);
        if (!ok || bytesRead == 0) { Sleep(50); continue; }

        std::string content(buf.data(), bytesRead);
        std::vector<std::string> remaining;
        size_t pos = 0;
        while (pos < content.size()) {
            size_t eol = content.find('\n', pos);
            std::string ln = (eol != std::string::npos)
                ? content.substr(pos, eol - pos) : content.substr(pos);
            if (!ln.empty() && ln.back() == '\r') ln.pop_back();
            if (!ln.empty() && ln.find(timestamp) == std::string::npos)
                remaining.push_back(ln);
            pos = (eol != std::string::npos) ? eol + 1 : content.size();
        }

        std::string out;
        for (auto& l : remaining) { out += l; out += '\n'; }

        hFile = CreateFileW(logPath.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
        if (hFile == INVALID_HANDLE_VALUE) { Sleep(50); continue; }
        DWORD written = 0;
        ok = WriteFile(hFile, out.data(), (DWORD)out.size(), &written, NULL);
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
        if (ok) { DeleteFileW((logDir + L"\\audit.tmp").c_str()); return; }
        Sleep(50);
    }
}


void PushNotification(const std::wstring& title, const std::wstring& detail, bool isError) {
    std::lock_guard<std::mutex> lock(g_notifMutex);
    NotificationPopup n;
    n.title = title;
    n.detail = detail;
    n.titleUtf8 = WideToUtf8(title);
    n.detailUtf8 = WideToUtf8(detail);
    if (n.detailUtf8.size() > 38) n.detailUtf8 = n.detailUtf8.substr(0, 35) + "...";
    n.isError = isError;
    n.timer = 0.f;
    n.alpha = 0.f;
    n.active = true;
    g_notifications.push_back(n);
    if (g_notifications.size() > 5) g_notifications.erase(g_notifications.begin());
}

static ID3D11ShaderResourceView* CreateTextureFromHIcon(HICON hIcon) {
    if (!hIcon || !g_pd3dDevice) return NULL;

    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = 24;
    bi.bmiHeader.biHeight = -24;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    void* bits = NULL;
    HDC hdc = GetDC(NULL);
    HDC hMemDC = CreateCompatibleDC(hdc);
    HBITMAP hBmp = CreateDIBSection(hMemDC, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    HBITMAP hOld = (HBITMAP)SelectObject(hMemDC, hBmp);
    DrawIconEx(hMemDC, 0, 0, hIcon, 24, 24, 0, NULL, DI_NORMAL);
    SelectObject(hMemDC, hOld);
    DeleteDC(hMemDC);
    ReleaseDC(NULL, hdc);

    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = 24;
    desc.Height = 24;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA initData = {};
    initData.pSysMem = bits;
    initData.SysMemPitch = 24 * 4;

    ID3D11Texture2D* texture = NULL;
    HRESULT hr = g_pd3dDevice->CreateTexture2D(&desc, &initData, &texture);
    DeleteObject(hBmp);

    if (FAILED(hr) || !texture) return NULL;

    D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
    srvDesc.Format = desc.Format;
    srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
    srvDesc.Texture2D.MipLevels = 1;

    ID3D11ShaderResourceView* srv = NULL;
    hr = g_pd3dDevice->CreateShaderResourceView(texture, &srvDesc, &srv);
    texture->Release();

    if (SUCCEEDED(hr) && srv) {
        g_texCreated++;
        char _b[256];
        snprintf(_b, sizeof(_b), "TEX_CREATE: SRV=%p (created=%d released=%d)\n",
                 (void*)srv, g_texCreated.load(), g_texReleased.load());
        OutputDebugStringA(_b);
    }
    return SUCCEEDED(hr) ? srv : NULL;
}

static void CreateDefaultIcon() {
    if (g_defaultIconSRV || !g_pd3dDevice) return;

    HICON hIcon = LoadIcon(NULL, IDI_APPLICATION);
    if (hIcon) {
        g_defaultIconSRV = CreateTextureFromHIcon(hIcon);
    }
    if (g_defaultIconSRV) return;

    HICON hIcon2 = NULL;
    ExtractIconExW(L"imageres.dll", 15, &hIcon2, NULL, 1);
    if (hIcon2) {
        g_defaultIconSRV = CreateTextureFromHIcon(hIcon2);
        DestroyIcon(hIcon2);
    }
    if (g_defaultIconSRV) return;

    BYTE pixels[24 * 24 * 4];
    memset(pixels, 0, sizeof(pixels));
    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = 24; desc.Height = 24; desc.MipLevels = 1; desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1; desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    D3D11_SUBRESOURCE_DATA initData = {};
    initData.pSysMem = pixels;
    initData.SysMemPitch = 24 * 4;
    ID3D11Texture2D* texture = NULL;
    if (SUCCEEDED(g_pd3dDevice->CreateTexture2D(&desc, &initData, &texture))) {
        D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
        srvDesc.Format = desc.Format;
        srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
        srvDesc.Texture2D.MipLevels = 1;
        g_pd3dDevice->CreateShaderResourceView(texture, &srvDesc, &g_defaultIconSRV);
        texture->Release();
    }
}

static void CreateSidebarLogo(int targetW, int targetH) {
    if (g_sidebarLogoSRV || !g_pd3dDevice) return;

    static std::once_flag gdiplusLogoInit;
    static ULONG_PTR gdiplusToken = 0;
    std::call_once(gdiplusLogoInit, []() {
        Gdiplus::GdiplusStartupInput input;
        Gdiplus::GdiplusStartup(&gdiplusToken, &input, NULL);
    });

    IStream* stream = NULL;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, g_logoPngDataSize);
    if (!hMem) return;
    memcpy(GlobalLock(hMem), g_logoPngData, g_logoPngDataSize);
    GlobalUnlock(hMem);
    if (CreateStreamOnHGlobal(hMem, TRUE, &stream) != S_OK) {
        GlobalFree(hMem);
        return;
    }

    Gdiplus::Bitmap* bitmap = Gdiplus::Bitmap::FromStream(stream);
    stream->Release();
    if (!bitmap || bitmap->GetLastStatus() != Gdiplus::Ok) {
        delete bitmap;
        return;
    }

    int srcW = bitmap->GetWidth();
    int srcH = bitmap->GetHeight();

    int texW = (targetW > 0) ? targetW : srcW;
    int texH = (targetH > 0) ? targetH : srcH;

    Gdiplus::Bitmap scaledBitmap(texW, texH, PixelFormat32bppARGB);
    {
        Gdiplus::Graphics graphics(&scaledBitmap);
        graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
        graphics.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHighQuality);
        graphics.DrawImage(bitmap, 0, 0, texW, texH);
    }
    delete bitmap;

    Gdiplus::BitmapData bmpData;
    Gdiplus::Rect rect(0, 0, texW, texH);
    if (scaledBitmap.LockBits(&rect, Gdiplus::ImageLockModeRead, PixelFormat32bppARGB, &bmpData) != Gdiplus::Ok) {
        return;
    }

    int pixBytes = texW * texH * 4;
    BYTE* pixels = new BYTE[pixBytes];

    const BYTE* src = (const BYTE*)bmpData.Scan0;
    int srcStride = bmpData.Stride;
    for (int y = 0; y < texH; y++) {
        memcpy(pixels + y * texW * 4, src + y * srcStride, texW * 4);
    }

    scaledBitmap.UnlockBits(&bmpData);

    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = texW; desc.Height = texH;
    desc.MipLevels = 1; desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    D3D11_SUBRESOURCE_DATA initData = {};
    initData.pSysMem = pixels;
    initData.SysMemPitch = texW * 4;
    ID3D11Texture2D* texture = NULL;
    if (SUCCEEDED(g_pd3dDevice->CreateTexture2D(&desc, &initData, &texture))) {
        D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
        srvDesc.Format = desc.Format;
        srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
        srvDesc.Texture2D.MipLevels = 1;
        g_pd3dDevice->CreateShaderResourceView(texture, &srvDesc, &g_sidebarLogoSRV);
        texture->Release();
    }

    delete[] pixels;
}

std::atomic<bool> g_sizeCalcDone{false};
std::atomic<bool> g_iconThreadDone{false};

static void ProcessPendingIcons() {
    std::vector<PendingIcon> batch;
    {
        std::lock_guard<std::mutex> lock(g_pendingIconMutex);
        if (g_pendingIcons.empty()) return;
        batch.swap(g_pendingIcons);
    }
    int ok = 0, fail = 0, cached = 0;
    for (auto& pi : batch) {
        {
            std::lock_guard<std::mutex> lock(g_iconMutex);
            if (g_iconCache.count(pi.key)) { DestroyIcon(pi.hIcon); cached++; continue; }
        }
        ID3D11ShaderResourceView* srv = CreateTextureFromHIcon(pi.hIcon);
        DestroyIcon(pi.hIcon);
        if (srv) {
            {
                std::lock_guard<std::mutex> lock(g_iconMutex);
                if (g_iconCache.size() >= MAX_ICON_CACHE_ENTRIES) {
                    auto oldest = g_iconCache.begin();
                    if (oldest->second) {
                        oldest->second->Release();
                        g_texReleased++;
                        char _b[256];
                        snprintf(_b, sizeof(_b), "TEX_RELEASE: evict SRV=%p (created=%d released=%d)\n",
                                 (void*)oldest->second, g_texCreated.load(), g_texReleased.load());
                        OutputDebugStringA(_b);
                    }
                    g_iconCache.erase(oldest);
                }
                g_iconCache[pi.key] = srv;
            }
            ok++;
        } else {
            fail++;
        }
    }
    {
        char _buf[256];
        snprintf(_buf, sizeof(_buf), "ProcessPendingIcons: batch=%d ok=%d fail=%d cached=%d cacheSize=%d\n",
                 (int)batch.size(), ok, fail, cached, (int)g_iconCache.size());
        OutputDebugStringA(_buf);
    }
}

static ID3D11ShaderResourceView* CreateTextureFromPixels(const BYTE* pixels, int w, int h) {
    if (!pixels || !g_pd3dDevice) return NULL;

    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = w; desc.Height = h; desc.MipLevels = 1; desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1; desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA initData = {};
    initData.pSysMem = pixels;
    initData.SysMemPitch = w * 4;

    ID3D11Texture2D* texture = NULL;
    if (FAILED(g_pd3dDevice->CreateTexture2D(&desc, &initData, &texture))) return NULL;

    D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
    srvDesc.Format = desc.Format;
    srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
    srvDesc.Texture2D.MipLevels = 1;

    ID3D11ShaderResourceView* srv = NULL;
    HRESULT hr = g_pd3dDevice->CreateShaderResourceView(texture, &srvDesc, &srv);
    texture->Release();
    return SUCCEEDED(hr) ? srv : NULL;
}

static void ProcessPendingCachedPixels() {
    std::vector<PendingCachedIcon> batch;
    {
        std::lock_guard<std::mutex> lock(g_pendingCachedIconMutex);
        if (g_pendingCachedIcons.empty()) return;
        batch.swap(g_pendingCachedIcons);
    }
    int ok = 0, fail = 0;
    for (auto& pi : batch) {
        {
            std::lock_guard<std::mutex> lock(g_iconMutex);
            if (g_iconCache.count(pi.key)) { continue; }
        }
        ID3D11ShaderResourceView* srv = CreateTextureFromPixels(pi.pixels.data(), 24, 24);
        if (srv) {
            std::lock_guard<std::mutex> lock(g_iconMutex);
            if (g_iconCache.size() >= MAX_ICON_CACHE_ENTRIES) {
                auto oldest = g_iconCache.begin();
                if (oldest->second) {
                    oldest->second->Release();
                    g_texReleased++;
                    char _b[256];
                    snprintf(_b, sizeof(_b), "TEX_RELEASE: evict-cached SRV=%p (created=%d released=%d)\n",
                             (void*)oldest->second, g_texCreated.load(), g_texReleased.load());
                    OutputDebugStringA(_b);
                }
                g_iconCache.erase(oldest);
            }
            g_iconCache[pi.key] = srv;
            ok++;
        } else {
            fail++;
        }
    }
}

static void ShowTrayIcon(HWND hwnd) {
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcscpy_s(g_nid.szTip, L"Black Hole (B-H)");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_DROPFILES) {
        HDROP hDrop = (HDROP)wParam;
        UINT fileCount = DragQueryFileW(hDrop, 0xFFFFFFFF, NULL, 0);

        g_batchFiles.clear();

        if (fileCount == 1) {
            wchar_t droppedPath[MAX_PATH];
            if (DragQueryFileW(hDrop, 0, droppedPath, MAX_PATH)) {
                g_selectedFile = droppedPath;
                g_impactAnalysis = {};
                g_showDeleteConfirm = false;
                g_leftoverChecked.clear();
                g_showLeftoverCleanConfirm = false;
                g_lockedByChecked.clear();
                g_dependentAppsChecked.clear();
                g_registryRefsChecked.clear();
                g_serviceRefsChecked.clear();
                g_relatedFilesChecked.clear();
                g_selectedTab = 1;
                g_autoAnalyzeOnStart = true;
            }
        } else if (fileCount > 1) {
            g_batchFiles.resize(fileCount);
            for (UINT i = 0; i < fileCount; i++) {
                wchar_t droppedPath[MAX_PATH];
                if (DragQueryFileW(hDrop, i, droppedPath, MAX_PATH))
                    g_batchFiles[i] = droppedPath;
            }
            g_selectedFile = g_batchFiles[0];
            g_showBatchConfirm = true;
            g_selectedTab = 1;
        }
        DragFinish(hDrop);
        return 0;
    }
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return 1;
    switch (msg) {
        case WM_NCCALCSIZE: {
            if (wParam == TRUE && g_resizableWindow) {
                NCCALCSIZE_PARAMS* params = reinterpret_cast<NCCALCSIZE_PARAMS*>(lParam);
                RECT& rect = params->rgrc[0];
                if (IsZoomed(hWnd)) {
                    HMONITOR mon = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
                    MONITORINFO mi = {};
                    mi.cbSize = sizeof(mi);
                    if (GetMonitorInfoW(mon, &mi)) {
                        rect = mi.rcWork;
                    }
                    g_isMaximized = true;
                } else {
                    g_isMaximized = false;
                }
                return 0;
            }
            break;
        }
        case WM_NCHITTEST: {
            if (g_resizableWindow) {
                POINT cursor;
                cursor.x = GET_X_LPARAM(lParam);
                cursor.y = GET_Y_LPARAM(lParam);
                ScreenToClient(hWnd, &cursor);

                int frameX = GetSystemMetrics(SM_CXFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
                int frameY = GetSystemMetrics(SM_CYFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);

                RECT rc;
                GetClientRect(hWnd, &rc);
                int w = rc.right - rc.left;
                int h = rc.bottom - rc.top;

                bool left = cursor.x < frameX;
                bool right = cursor.x >= w - frameX;
                bool top = cursor.y < frameY;
                bool bottom = cursor.y >= h - frameY;

                if (top && left) return HTTOPLEFT;
                if (top && right) return HTTOPRIGHT;
                if (bottom && left) return HTBOTTOMLEFT;
                if (bottom && right) return HTBOTTOMRIGHT;
                if (left) return HTLEFT;
                if (right) return HTRIGHT;
                if (top) return HTTOP;
                if (bottom) return HTBOTTOM;

                if (cursor.y >= 0 && cursor.y < TITLE_BAR_H) {
                    float sidebarW = g_hideSidebar ? 0.0f : SIDEBAR_W;
                    float cliW = rc.right - rc.left;
                    float contentRight = g_resizableWindow ? (cliW - DOCK_W) : CONTENT_W;
                    if (cursor.x >= sidebarW && cursor.x < contentRight) {
                        float btnR = 7.0f, btnPad = 14.0f, btnGap = 6.0f;
                        float closeX = contentRight - btnPad - btnR;
                        float maxX = closeX - btnR * 2 - btnGap;
                        float minX = maxX - btnR * 2 - btnGap;
                        float btnY = TITLE_BAR_H / 2.0f;
                        if (fabsf((float)cursor.x - closeX) < btnR + 4 && fabsf((float)cursor.y - btnY) < btnR + 4)
                            return HTCLOSE;
                        if (fabsf((float)cursor.x - minX) < btnR + 4 && fabsf((float)cursor.y - btnY) < btnR + 4)
                            return HTMINBUTTON;
                        if (g_resizableWindow && fabsf((float)cursor.x - maxX) < btnR + 4 && fabsf((float)cursor.y - btnY) < btnR + 4)
                            return HTMAXBUTTON;
                        // Moon/sun icon area — let ImGui handle the click
                        float moonR = 7.0f;
                        float moonX = sidebarW + 16.0f;
                        float moonY = TITLE_BAR_H / 2.0f;
                        if (fabsf((float)cursor.x - moonX) < moonR + 4 && fabsf((float)cursor.y - moonY) < moonR + 4)
                            return HTCLIENT;
                        return HTCAPTION;
                    }
                }
                return HTCLIENT;
            }
            break;
        }
        case WM_NCACTIVATE: {
            if (g_resizableWindow) return 1;
            break;
        }
        case WM_NCLBUTTONDOWN: {
            if (g_resizableWindow) {
                if (wParam == HTCLOSE) {
                    g_running.store(false);
                    return 0;
                }
                if (wParam == HTMINBUTTON) {
                    ShowWindow(hWnd, SW_MINIMIZE);
                    return 0;
                }
                if (wParam == HTMAXBUTTON) {
                    if (IsZoomed(hWnd))
                        ShowWindow(hWnd, SW_RESTORE);
                    else
                        ShowWindow(hWnd, SW_MAXIMIZE);
                    return 0;
                }
            }
            break;
        }
        case WM_GETMINMAXINFO: {
            if (g_resizableWindow) {
                MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
                mmi->ptMinTrackSize.x = 600;
                mmi->ptMinTrackSize.y = 400;
                mmi->ptMaxTrackSize.x = 1920;
                mmi->ptMaxTrackSize.y = 1080;
                return 0;
            }
            break;
        }
        case WM_LBUTTONDOWN: {
            if (g_resizableWindow) break;
            POINT pt;
            pt.x = (short)LOWORD(lParam);
            pt.y = (short)HIWORD(lParam);

            if (pt.y < TITLE_BAR_H && pt.x > (g_hideSidebar ? 0 : (int)SIDEBAR_W) && pt.x < (int)CONTENT_W) {
                float btnR = 7.0f, btnPad = 14.0f;
                float closeX = CONTENT_W - btnPad - btnR;
                float minX = closeX - btnR * 2 - 6.0f;
                float btnY = TITLE_BAR_H / 2.0f;
                if (fabsf((float)pt.x - closeX) < btnR + 4 && fabsf((float)pt.y - btnY) < btnR + 4)
                    break;
                if (fabsf((float)pt.x - minX) < btnR + 4 && fabsf((float)pt.y - btnY) < btnR + 4)
                    break;
                gDragging = true;
                gDragOffset.x = pt.x;
                gDragOffset.y = pt.y;
                SetCapture(hWnd);
            }
            break;
        }
        case WM_LBUTTONUP:
            if (gDragging) {
                gDragging = false;
                ReleaseCapture();
            }
            break;
        case WM_MOUSEMOVE:
            if (gDragging) {
                POINT pt;
                pt.x = (short)LOWORD(lParam);
                pt.y = (short)HIWORD(lParam);
                ClientToScreen(hWnd, &pt);
                SetWindowPos(hWnd, NULL, pt.x - gDragOffset.x, pt.y - gDragOffset.y, 0, 0,
                    SWP_NOSIZE | SWP_NOZORDER);
            }
            break;
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED) {
                if (g_hToggleWnd) ShowWindow(g_hToggleWnd, SW_HIDE);
                return 0;
            }
            if (wParam == SIZE_RESTORED || wParam == SIZE_MAXIMIZED) {
                if (g_hToggleWnd) UpdateTogglePosition();
            }
            g_ResizeWidth = (UINT)LOWORD(lParam);
            g_ResizeHeight = (UINT)HIWORD(lParam);
            g_isMaximized = (wParam == SIZE_MAXIMIZED);
            return 0;
        case WM_ACTIVATE:
            if (LOWORD(wParam) == WA_INACTIVE) {
                if (g_hToggleWnd) ShowWindow(g_hToggleWnd, SW_HIDE);
            } else {
                if (g_hToggleWnd) UpdateTogglePosition();
                LoadLogs();
            }
            break;
        case WM_CHAR:
            if (g_phraseFocused && wParam >= 32 && wParam < 127) {
                size_t len = strlen(g_overrideInput);
                if (len < 255) {
                    g_overrideInput[len] = (char)wParam;
                    g_overrideInput[len + 1] = '\0';
                }
                return 0;
            }
            break;
        case WM_KEYDOWN:
            if (g_phraseFocused && wParam == VK_BACK) {
                size_t len = strlen(g_overrideInput);
                if (len > 0) g_overrideInput[len - 1] = '\0';
                return 0;
            }
            if (g_phraseFocused && wParam == VK_ESCAPE) {
                g_phraseFocused = false;
                return 0;
            }
            break;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_CLOSE:
            g_running.store(false);
            DestroyWindow(hWnd);
            return 0;
        case WM_DESTROY:
            if (g_hToggleWnd) { DestroyWindow(g_hToggleWnd); g_hToggleWnd = NULL; }
            Shell_NotifyIconW(NIM_DELETE, &g_nid);
            PostQuitMessage(0);
            return 0;
        case WM_TRAYICON:
            if (lParam == WM_LBUTTONUP) {
                ShowWindow(hWnd, SW_SHOW);
                SetForegroundWindow(hWnd);
            } else if (lParam == WM_RBUTTONUP) {
                HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, 1, L"Show Dashboard");
                AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuW(hMenu, MF_STRING, 4, L"Exit");
                POINT pt;
                GetCursorPos(&pt);
                TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
                DestroyMenu(hMenu);
            }
            return 0;
        case WM_DELETION_COMPLETE:
            delete (std::wstring*)lParam;
            LoadLogs();
            return 0;
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case 1: ShowWindow(hWnd, SW_SHOW); break;
                case 4: PostQuitMessage(0); break;
            }
            return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL levels[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    HRESULT hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0,
        levels, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (FAILED(hr)) return false;
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
    return true;
}

static void CleanupDeviceD3D() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

static void ResizeSwapChain() {
    if (!g_pSwapChain) return;
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
    g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
    g_ResizeWidth = g_ResizeHeight = 0;
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
}

struct GenericThreadData {
    std::function<void()> func;
};

static unsigned __stdcall GenericBigStackThread(void* param) {
    auto* data = static_cast<GenericThreadData*>(param);
    data->func();
    delete data;
    return 0;
}

static void LaunchBigStackThread(std::function<void()> func) {
    auto* data = new GenericThreadData{std::move(func)};
    HANDLE h = (HANDLE)_beginthreadex(nullptr, 4 * 1024 * 1024, GenericBigStackThread, data, 0, nullptr);
    if (h) CloseHandle(h);
}

struct ToastPaintData {
    COLORREF bgCol, titleCol, accentCol, borderCol;
    wchar_t title[64];
    wchar_t detail[256];
    DWORD startTime;
    bool isError;
};

static LRESULT CALLBACK ToastWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CREATE) {
        SetTimer(hWnd, 1, 33, NULL);
        return 0;
    }
    if (msg == WM_TIMER) {
        InvalidateRect(hWnd, NULL, FALSE);
        return 0;
    }
    if (msg == WM_ERASEBKGND) return 1;
    if (msg == WM_PAINT) {
        ToastPaintData* td = (ToastPaintData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        if (!td) return DefWindowProc(hWnd, msg, wParam, lParam);

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        RECT rc;
        GetClientRect(hWnd, &rc);
        int w = rc.right, h = rc.bottom;

        HBRUSH bgBr = CreateSolidBrush(td->bgCol);
        FillRect(hdc, &rc, bgBr);
        DeleteObject(bgBr);

        RECT rcBar = {0, 0, 3, h};
        HBRUSH barBr = CreateSolidBrush(td->accentCol);
        FillRect(hdc, &rcBar, barBr);
        DeleteObject(barBr);

        HPEN hPen = CreatePen(PS_SOLID, 1, td->borderCol);
        HPEN oldPen = (HPEN)SelectObject(hdc, hPen);
        HBRUSH oldBr = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, 0, 0, w, h);
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBr);
        DeleteObject(hPen);

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, td->titleCol);
        HFONT hFont = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        SelectObject(hdc, hFont);
        TextOutW(hdc, 14, 10, td->title, (int)wcslen(td->title));
        SetTextColor(hdc, RGB(102, 102, 120));
        HFONT hFontSm = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        SelectObject(hdc, hFontSm);
        TextOutW(hdc, 14, 32, td->detail, (int)wcslen(td->detail));
        DeleteObject(hFont);
        DeleteObject(hFontSm);

        DWORD elapsed = GetTickCount() - td->startTime;
        float pct = (float)elapsed / 4000.0f;
        if (pct > 1.0f) pct = 1.0f;
        int barX1 = 12, barX2 = w - 12;
        int barY1 = h - 8, barY2 = h - 4;
        RECT rcBg = {barX1, barY1, barX2, barY2};
        HBRUSH bgBarBr = CreateSolidBrush(RGB(20, 20, 26));
        FillRect(hdc, &rcBg, bgBarBr);
        DeleteObject(bgBarBr);
        int fillW = (int)((barX2 - barX1) * (1.0f - pct));
        if (fillW > 0) {
            RECT rcFill = {barX1, barY1, barX1 + fillW, barY2};
            COLORREF barCol = td->isError ? RGB(180, 50, 50) : td->accentCol;
            HBRUSH fillBr = CreateSolidBrush(barCol);
            FillRect(hdc, &rcFill, fillBr);
            DeleteObject(fillBr);
        }

        EndPaint(hWnd, &ps);
        return 0;
    }
    if (msg == WM_DESTROY) {
        KillTimer(hWnd, 1);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    {
        wchar_t tp[MAX_PATH]; GetTempPathW(MAX_PATH, tp);
        std::wstring lp = std::wstring(tp) + L"BlackHole_entry.log";
        HANDLE hf = CreateFileW(lp.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            const char* msg = "wWinMain entered\r\n";
            DWORD w; WriteFile(hf, msg, (DWORD)strlen(msg), &w, NULL); CloseHandle(hf);
        }
    }

    {
        BOOL isAdmin = FALSE;
        PSID adminGroup = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(NULL, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }
        if (!isAdmin) {
            int skipElev = 0;
            {   int targc = 0; LPWSTR* targv = CommandLineToArgvW(GetCommandLineW(), &targc);
                if (targc >= 3) { std::wstring c = targv[1];
                    if (c == L"--delete-list" || c == L"--delete" || c == L"--scan-and-delete") skipElev = 1; }
                if (targv) LocalFree(targv); }
            if (!skipElev) {
            wchar_t exePath[MAX_PATH];
            GetModuleFileNameW(NULL, exePath, MAX_PATH);
            SHELLEXECUTEINFOW sei = { sizeof(sei) };
            sei.lpVerb = L"runas";
            sei.lpFile = exePath;
            int argc = 0;
            LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
            std::wstring params;
            for (int i = 1; i < argc; i++) {
                if (i > 1) params += L" ";
                params += L"\"" + std::wstring(argv[i]) + L"\"";
            }
            sei.lpParameters = params.c_str();
            sei.nShow = SW_SHOWNORMAL;
            ShellExecuteExW(&sei);
            if (argv) LocalFree(argv);
            return 0;
            }
        }
    }

    static char logPathBuf[MAX_PATH];
    GetTempPathA(MAX_PATH, logPathBuf);
    strcat_s(logPathBuf, "BlackHole_crash.log");
    CRASH_LOG_PATH = logPathBuf;

    SetUnhandledExceptionFilter(CrashHandler);
    WriteCrashLogHeader();
    DebugLog("wWinMain entered, crash handler installed");

    std::set_terminate([]() {
        FILE* f = nullptr;
        fopen_s(&f, CRASH_LOG_PATH ? CRASH_LOG_PATH : "crash_log.txt", "a");
        if (f) {
            fprintf(f, "\nstd::terminate called - unhandled C++ exception or noexcept violation\n");
            fclose(f);
        }
        MessageBoxA(NULL, "std::terminate called. Check crash log.", "BlackHole", MB_OK);
        TerminateProcess(GetCurrentProcess(), 1);
    });

    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argc >= 3) {
            std::wstring cmd = argv[1];

            if (cmd == L"--delete-list") {
                std::wstring listPath = argv[2];
                {
                    wchar_t tp2[MAX_PATH]; GetTempPathW(MAX_PATH, tp2);
                    std::wstring lp2 = std::wstring(tp2) + L"BlackHole_entry.log";
                    HANDLE hf2 = CreateFileW(lp2.c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
                    if (hf2 != INVALID_HANDLE_VALUE) {
                        SetFilePointer(hf2, 0, NULL, FILE_END);
                        wchar_t buf[512]; swprintf_s(buf, L"listPath=[%s]\n", listPath.c_str());
                        char abuf[1024]; WideCharToMultiByte(CP_UTF8, 0, buf, -1, abuf, sizeof(abuf), NULL, NULL);
                        DWORD w; WriteFile(hf2, abuf, (DWORD)strlen(abuf), &w, NULL); CloseHandle(hf2);
                    }
                }
                try {
                FILE* fp = nullptr;
                _wfopen_s(&fp, listPath.c_str(), L"r, ccs=UTF-8");
                if (fp) {
                    {   wchar_t tp3[MAX_PATH]; GetTempPathW(MAX_PATH, tp3);
                        std::wstring lp3 = std::wstring(tp3) + L"BlackHole_entry.log";
                        HANDLE hf3 = CreateFileW(lp3.c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
                        if (hf3 != INVALID_HANDLE_VALUE) { SetFilePointer(hf3, 0, NULL, FILE_END);
                        const char* m = "listFile opened, about to LoadConfig\n"; DWORD w3;
                        WriteFile(hf3, m, (DWORD)strlen(m), &w3, NULL); CloseHandle(hf3); } }
                    LoadConfig();
                    BlackHole::BlacklistModule blacklist;
                    BlackHole::PrivilegeManager priv;
                    BlackHole::Deletor deletor;
                    priv.EnableAllPrivileges();

                    {   wchar_t tp3[MAX_PATH]; GetTempPathW(MAX_PATH, tp3);
                        std::wstring lp3 = std::wstring(tp3) + L"BlackHole_entry.log";
                        HANDLE hf3 = CreateFileW(lp3.c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
                        if (hf3 != INVALID_HANDLE_VALUE) { SetFilePointer(hf3, 0, NULL, FILE_END);
                        const char* m = "privileges enabled, starting loop\n"; DWORD w3;
                        WriteFile(hf3, m, (DWORD)strlen(m), &w3, NULL); CloseHandle(hf3); } }

                    int total = 0, success = 0, failed = 0, scheduled = 0;
                    wchar_t wbuf[32768];
                    std::vector<std::wstring> batchPaths;
                    while (fgetws(wbuf, 32768, fp)) {
                        std::wstring line(wbuf);
                        while (!line.empty() && (line.back() == L'\n' || line.back() == L'\r')) line.pop_back();
                        if (line.empty()) continue;
                        total++;
                        bool blocked = blacklist.IsInBlacklist(line);
                        if (blocked) { failed++; continue; }

                        try {
                            bool isDir = std::filesystem::is_directory(line);
                            if (isDir) {
                                std::error_code ec;
                                std::uintmax_t count = std::filesystem::remove_all(line, ec);
                                if (ec.value() == 0 && count > 0) success++;
                                else failed++;
                            } else {
                                batchPaths.push_back(line);
                            }
                        } catch (...) {
                            failed++;
                        }
                    }
                    fclose(fp);

                    // Use batch engine with single handle snapshot
                    if (!batchPaths.empty()) {
                        auto batchResult = deletor.DeleteFilesBatch(batchPaths);
                        success += batchResult.directDeleted + batchResult.killedAndDeleted;
                        scheduled += batchResult.scheduledReboot;
                        failed += batchResult.failed;
                    }

                    DeleteFileW(listPath.c_str());

                    wchar_t detail[128];
                    swprintf_s(detail, L"%d OK / %d Scheduled / %d Failed (of %d)", success, scheduled, failed, total);
                    bool hasFailed = (failed > 0);
                    bool allDone = (success + scheduled == total);

                    HMODULE hUser32 = LoadLibraryW(L"user32.dll");
                    typedef BOOL (WINAPI *pSetProcessDPIAware)();
                    if (hUser32) {
                        auto fn = (pSetProcessDPIAware)GetProcAddress(hUser32, "SetProcessDPIAware");
                        if (fn) fn();
                        FreeLibrary(hUser32);
                    }

                    std::wstring msgText = detail;
                    std::wstring msgTitle = allDone ? L"BATCH DELETE COMPLETE" : L"BATCH DELETE";

                    struct DarkMsgData { std::wstring title; std::wstring body; };
                    DarkMsgData* pData = new DarkMsgData{ msgTitle, msgText };

                    HWND hDarkMsg = NULL;

                    WNDCLASSEXW wc = {};
                    wc.cbSize = sizeof(wc);
                    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
                        if (msg == WM_ERASEBKGND) {
                            HDC hdc = (HDC)wParam;
                            RECT rc;
                            GetClientRect(hwnd, &rc);
                            HBRUSH hBg = CreateSolidBrush(RGB(18, 18, 22));
                            FillRect(hdc, &rc, hBg);
                            DeleteObject(hBg);
                            return 1;
                        }
                        if (msg == WM_PAINT) {
                            PAINTSTRUCT ps;
                            HDC hdc = BeginPaint(hwnd, &ps);
                            RECT rc;
                            GetClientRect(hwnd, &rc);

                            HBRUSH hBg = CreateSolidBrush(RGB(18, 18, 22));
                            FillRect(hdc, &rc, hBg);
                            DeleteObject(hBg);

                            HPEN hBorder = CreatePen(PS_SOLID, 1, RGB(60, 60, 70));
                            SelectObject(hdc, hBorder);
                            Rectangle(hdc, 0, 0, rc.right, rc.bottom);
                            DeleteObject(hBorder);

                            SetBkMode(hdc, TRANSPARENT);

                            DarkMsgData* pd = (DarkMsgData*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
                            if (pd) {
                                HFONT hTitleFont = CreateFontW(20, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, 0, 0, 0, 0, 0, L"Segoe UI");
                                SelectObject(hdc, hTitleFont);
                                SetTextColor(hdc, RGB(220, 180, 60));
                                TextOutW(hdc, 20, 16, pd->title.c_str(), (int)pd->title.size());
                                DeleteObject(hTitleFont);

                                HFONT hBodyFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, 0, L"Segoe UI");
                                SelectObject(hdc, hBodyFont);
                                SetTextColor(hdc, RGB(200, 200, 210));
                                TextOutW(hdc, 20, 50, pd->body.c_str(), (int)pd->body.size());
                                DeleteObject(hBodyFont);
                            }

                            RECT btnRc = { rc.right - 100, rc.bottom - 40, rc.right - 16, rc.bottom - 12 };
                            HBRUSH hBtnBg = CreateSolidBrush(RGB(40, 40, 50));
                            FillRect(hdc, &btnRc, hBtnBg);
                            DeleteObject(hBtnBg);
                            HPEN hBtnBorder = CreatePen(PS_SOLID, 1, RGB(80, 80, 100));
                            SelectObject(hdc, hBtnBorder);
                            Rectangle(hdc, btnRc.left, btnRc.top, btnRc.right, btnRc.bottom);
                            DeleteObject(hBtnBorder);
                            HFONT hBtnFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, 0, L"Segoe UI");
                            SelectObject(hdc, hBtnFont);
                            SetTextColor(hdc, RGB(200, 200, 210));
                            DrawTextW(hdc, L"OK", -1, &btnRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                            DeleteObject(hBtnFont);

                            EndPaint(hwnd, &ps);
                            return 0;
                        }
                        if (msg == WM_LBUTTONDOWN) {
                            POINT pt;
                            GetCursorPos(&pt);
                            ScreenToClient(hwnd, &pt);
                            RECT rc;
                            GetClientRect(hwnd, &rc);
                            RECT btnRc = { rc.right - 100, rc.bottom - 40, rc.right - 16, rc.bottom - 12 };
                            if (pt.x >= btnRc.left && pt.x <= btnRc.right && pt.y >= btnRc.top && pt.y <= btnRc.bottom) {
                                DestroyWindow(hwnd);
                            }
                        }
                        if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
                            DestroyWindow(hwnd);
                        }
                        if (msg == WM_DESTROY) {
                            PostQuitMessage(0);
                        }
                        return DefWindowProcW(hwnd, msg, wParam, lParam);
                    };
                    HBRUSH hDarkBrush = CreateSolidBrush(RGB(18, 18, 22));
                    wc.hInstance = hInstance;
                    wc.lpszClassName = L"BlackHoleDarkMsg";
                    wc.hbrBackground = hDarkBrush;
                    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
                    RegisterClassExW(&wc);

                    int dw = 380, dh = 130;
                    int sx = GetSystemMetrics(SM_CXSCREEN);
                    int sy = GetSystemMetrics(SM_CYSCREEN);
                    hDarkMsg = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED, L"BlackHoleDarkMsg", msgTitle.c_str(),
                        WS_POPUP, (sx - dw) / 2, (sy - dh) / 2, dw, dh, NULL, NULL, hInstance, NULL);

                    SetWindowLongPtrW(hDarkMsg, GWLP_USERDATA, (LONG_PTR)pData);

                    {
                        HDC hScreenDC = GetDC(NULL);
                        HDC hMemDC = CreateCompatibleDC(hScreenDC);

                        BITMAPINFO bmi = {};
                        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
                        bmi.bmiHeader.biWidth = dw;
                        bmi.bmiHeader.biHeight = -dh;
                        bmi.bmiHeader.biPlanes = 1;
                        bmi.bmiHeader.biBitCount = 32;
                        bmi.bmiHeader.biCompression = BI_RGB;

                        void* pBits = NULL;
                        HBITMAP hBitmap = CreateDIBSection(hScreenDC, &bmi, DIB_RGB_COLORS, &pBits, NULL, 0);
                        HBITMAP hOldBmp = (HBITMAP)SelectObject(hMemDC, hBitmap);

                        BYTE* pixels = (BYTE*)pBits;
                        for (int i = 0; i < dw * dh; i++) {
                            pixels[i * 4 + 0] = 22;   // B
                            pixels[i * 4 + 1] = 18;   // G
                            pixels[i * 4 + 2] = 18;   // R
                            pixels[i * 4 + 3] = 255;  // A
                        }

                        HPEN hBorder = CreatePen(PS_SOLID, 1, RGB(60, 60, 70));
                        SelectObject(hMemDC, hBorder);
                        HBRUSH hNullBrush = (HBRUSH)GetStockObject(NULL_BRUSH);
                        HBRUSH hOldBr = (HBRUSH)SelectObject(hMemDC, hNullBrush);
                        Rectangle(hMemDC, 0, 0, dw, dh);
                        SelectObject(hMemDC, hOldBr);
                        DeleteObject(hBorder);

                        SetBkMode(hMemDC, TRANSPARENT);

                        HFONT hTitleFont = CreateFontW(20, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, 0, 0, 0, 0, 0, L"Segoe UI");
                        SelectObject(hMemDC, hTitleFont);
                        SetTextColor(hMemDC, RGB(220, 180, 60));
                        TextOutW(hMemDC, 20, 16, pData->title.c_str(), (int)pData->title.size());
                        DeleteObject(hTitleFont);

                        HFONT hBodyFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, 0, L"Segoe UI");
                        SelectObject(hMemDC, hBodyFont);
                        SetTextColor(hMemDC, RGB(200, 200, 210));
                        TextOutW(hMemDC, 20, 50, pData->body.c_str(), (int)pData->body.size());
                        DeleteObject(hBodyFont);

                        RECT btnRc = { dw - 100, dh - 40, dw - 16, dh - 12 };
                        HBRUSH hBtnBg = CreateSolidBrush(RGB(40, 40, 50));
                        FillRect(hMemDC, &btnRc, hBtnBg);
                        DeleteObject(hBtnBg);
                        HPEN hBtnBorder = CreatePen(PS_SOLID, 1, RGB(80, 80, 100));
                        SelectObject(hMemDC, hBtnBorder);
                        HBRUSH hBtnOldBr = (HBRUSH)SelectObject(hMemDC, GetStockObject(NULL_BRUSH));
                        Rectangle(hMemDC, btnRc.left, btnRc.top, btnRc.right, btnRc.bottom);
                        SelectObject(hMemDC, hBtnOldBr);
                        DeleteObject(hBtnBorder);
                        HFONT hBtnFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, 0, L"Segoe UI");
                        SelectObject(hMemDC, hBtnFont);
                        SetTextColor(hMemDC, RGB(200, 200, 210));
                        DrawTextW(hMemDC, L"OK", -1, &btnRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                        DeleteObject(hBtnFont);

                        for (int i = 0; i < dw * dh; i++) {
                            if (pixels[i * 4 + 3] == 0 && (pixels[i * 4 + 0] != 0 || pixels[i * 4 + 1] != 0 || pixels[i * 4 + 2] != 0)) {
                                pixels[i * 4 + 3] = 255;
                            }
                        }

                        POINT ptSrc = { 0, 0 };
                        SIZE sizeWnd = { dw, dh };
                        BLENDFUNCTION blend = {};
                        blend.BlendOp = AC_SRC_OVER;
                        blend.SourceConstantAlpha = 255;
                        blend.AlphaFormat = AC_SRC_ALPHA;
                        UpdateLayeredWindow(hDarkMsg, hScreenDC, NULL, &sizeWnd, hMemDC, &ptSrc, 0, &blend, ULW_ALPHA);

                        SelectObject(hMemDC, hOldBmp);
                        DeleteObject(hBitmap);
                        DeleteDC(hMemDC);
                        ReleaseDC(NULL, hScreenDC);
                    }

                    ShowWindow(hDarkMsg, SW_SHOW);

                    SetTimer(hDarkMsg, 1, 5000, [](HWND hwnd, UINT, UINT_PTR, DWORD) {
                        DestroyWindow(hwnd);
                    });

                    MSG msg;
                    while (GetMessageW(&msg, NULL, 0, 0)) {
                        TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }

                    delete pData;
                } } catch (...) {
                    wchar_t tp4[MAX_PATH]; GetTempPathW(MAX_PATH, tp4);
                    std::wstring lp4 = std::wstring(tp4) + L"BlackHole_entry.log";
                    HANDLE hf4 = CreateFileW(lp4.c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
                    if (hf4 != INVALID_HANDLE_VALUE) { SetFilePointer(hf4, 0, NULL, FILE_END);
                    const char* m = "EXCEPTION CAUGHT in --delete-list\n"; DWORD w4;
                    WriteFile(hf4, m, (DWORD)strlen(m), &w4, NULL); CloseHandle(hf4); }
                }
                LocalFree(argv);
                return 0;
            }

            std::wstring filePath = argv[2];
            if (cmd == L"--delete") {
                LoadConfig();
                BlackHole::BlacklistModule blacklist;
                bool blocked = blacklist.IsInBlacklist(filePath);
                BlackHole::LogEventType logType;
                std::wstring errMsg;
                DWORD errCode = 0;

                if (!blocked) {
                    BlackHole::PrivilegeManager priv;
                    BlackHole::Deletor deletor;

                    if (g_sendToRecycleBin) {
                        bool ok = deletor.MoveToRecycleBin(filePath);
                        if (ok) {
                            logType = BlackHole::LogEventType::DeletionSuccess;
                            errMsg = L"Moved to Recycle Bin";
                        } else {
                            logType = BlackHole::LogEventType::DeletionFailed;
                            errMsg = L"Move to Recycle Bin failed";
                            errCode = GetLastError();
                        }
                    } else {
                    priv.EnableAllPrivileges();
                    auto result = deletor.DeleteFileSafely(filePath);
                    logType = (result.result == BlackHole::DeletionResult::Success
                            || result.result == BlackHole::DeletionResult::Scheduled_Reboot)
                        ? BlackHole::LogEventType::DeletionSuccess
                        : BlackHole::LogEventType::DeletionFailed;
                    errMsg = result.errorMessage;
                    errCode = result.errorCode;
                    }
                } else {
                    logType = BlackHole::LogEventType::DeletionBlocked;
                    errMsg = L"File is in the blacklist";
                }

                bool success = (logType == BlackHole::LogEventType::DeletionSuccess);
                bool scheduled = (logType == BlackHole::LogEventType::DeletionScheduled);
                bool trashed = (errMsg == L"Moved to Recycle Bin");

                {
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
                        std::wstring label = trashed ? L"Recycled" : (scheduled ? L"Scheduled" : (success ? L"Deleted" : L"Failed"));
                        std::wstring entry = std::wstring(ts) + L" | " + label + L" | " + filePath + L"\n";

                        std::string logPath8 = WideToUtf8(wlp);
                        SetFileAttributesW(wlp.c_str(), FILE_ATTRIBUTE_NORMAL);
                        std::string entry8 = WideToUtf8(entry);
                        std::ofstream logF(logPath8, std::ios::app | std::ios::out);
                        if (logF.is_open()) {
                            logF << entry8;
                            logF.flush();
                            logF.close();
                        }
                    }
                }

                ToastPaintData* td = new ToastPaintData{};

                if (trashed) {
                    td->bgCol = RGB(10, 14, 12);
                    td->titleCol = RGB(60, 200, 140);
                    td->accentCol = RGB(50, 180, 80);
                    td->borderCol = RGB(16, 40, 24);
                    wcscpy_s(td->title, L"MOVED TO TRASH");
                    wcscpy_s(td->detail, L"File sent to Recycle Bin");
                } else if (scheduled) {
                    td->bgCol = RGB(18, 16, 10);
                    td->titleCol = RGB(220, 180, 60);
                    td->accentCol = RGB(180, 150, 40);
                    td->borderCol = RGB(40, 36, 16);
                    wcscpy_s(td->title, L"DELETE SCHEDULED");
                    wcscpy_s(td->detail, L"Reboot required to complete deletion");
                } else if (success) {
                    td->bgCol = RGB(10, 18, 14);
                    td->titleCol = RGB(80, 220, 120);
                    td->accentCol = RGB(50, 180, 80);
                    td->borderCol = RGB(16, 40, 24);
                    wcscpy_s(td->title, L"DELETE SUCCESS");
                    std::wstring shortP = filePath;
                    if (shortP.size() > 38) shortP = shortP.substr(0, 35) + L"...";
                    wcscpy_s(td->detail, shortP.c_str());
                } else {
                    td->bgCol = RGB(20, 10, 10);
                    td->titleCol = RGB(220, 80, 80);
                    td->accentCol = RGB(180, 50, 50);
                    td->borderCol = RGB(40, 16, 16);
                    wcscpy_s(td->title, L"DELETE FAILED");
                    wcscpy_s(td->detail, L"Access denied or file in use");
                }
                td->startTime = GetTickCount();
                td->isError = !success && !scheduled && !trashed;

                WNDCLASSEXW wc = {};
                wc.cbSize = sizeof(wc);
                wc.lpfnWndProc = ToastWndProc;
                wc.hInstance = hInstance;
                wc.lpszClassName = L"BlackHoleToast";
                wc.hbrBackground = NULL;
                RegisterClassExW(&wc);

                typedef HRESULT (WINAPI *pfnDwmSetWindowAttribute)(HWND, DWORD, LPCVOID, DWORD);
                static pfnDwmSetWindowAttribute fnDwm = nullptr;
                static std::once_flag dwmFlag;
                std::call_once(dwmFlag, []() {
                    HMODULE h = LoadLibraryW(L"dwmapi.dll");
                    if (h) fnDwm = (pfnDwmSetWindowAttribute)GetProcAddress(h, "DwmSetWindowAttribute");
                });

                int screenW = GetSystemMetrics(SM_CXSCREEN);
                int toastW = 310, toastH = 56;
                int toastX = screenW - toastW - 20;
                int toastY = GetSystemMetrics(SM_CYSCREEN) - toastH - 60;
                HWND hToast = CreateWindowExW(0, wc.lpszClassName, L"",
                    WS_POPUP | WS_VISIBLE, toastX, toastY, toastW, toastH,
                    NULL, NULL, hInstance, NULL);

                if (fnDwm) {
                    DWORD pref = 2;
                    fnDwm(hToast, 2, &pref, sizeof(pref));
                }

                SetWindowLongPtr(hToast, GWLP_USERDATA, (LONG_PTR)td);
                InvalidateRect(hToast, NULL, FALSE);

                MSG msg;
                DWORD startTime = GetTickCount();
                while (GetTickCount() - startTime < 4000) {
                    if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                        TranslateMessage(&msg);
                        DispatchMessage(&msg);
                    }
                    Sleep(16);
                }

                delete td;
                DestroyWindow(hToast);
                UnregisterClassW(wc.lpszClassName, hInstance);
                return success ? 0 : 1;
            }
        }
        if (argv) LocalFree(argv);
    }

    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argc >= 3) {
            std::wstring cmd = argv[1];
            std::wstring filePath = argv[2];
            if (cmd == L"--scan-and-delete") {
                if (argv) LocalFree(argv);
                return BlackHole::RunScanDeletePopup(hInstance, filePath);
            }
        }
        if (argv) LocalFree(argv);
    }

    BlackHole::GetLogger().Initialize();
    LoadConfig();

    if (g_installMonitorEnabled) {
        BlackHole::GetInstallMonitor().StartMonitoring();
    }

    {
        static const wchar_t* kStalePaths[] = {
            L"Drive\\shell\\BlackHole_ForceDelete",
            L"AllFileSystemObjects\\shell\\BlackHole_ForceDelete",
            L"Drive\\shell\\BlackHole_Analyze",
            L"AllFileSystemObjects\\shell\\BlackHole_Analyze",
            L"Drive\\shell\\BlackHole_ScanDelete",
            L"AllFileSystemObjects\\shell\\BlackHole_ScanDelete",
            L"*\\shell\\BlackHole_ForceDelete",
            L"Directory\\shell\\BlackHole_ForceDelete",
            L"Directory\\Background\\shell\\BlackHole_ForceDelete",
            L"Folder\\shell\\BlackHole_ForceDelete",
            L"*\\shell\\BlackHole_Analyze",
            L"Directory\\shell\\BlackHole_Analyze",
            L"Directory\\Background\\shell\\BlackHole_Analyze",
            L"Folder\\shell\\BlackHole_Analyze",
            L"*\\shell\\BlackHole_ScanDelete",
            L"Directory\\shell\\BlackHole_ScanDelete",
            L"Directory\\Background\\shell\\BlackHole_ScanDelete",
            L"Folder\\shell\\BlackHole_ScanDelete",
            L"*\\shell\\BlackHole",
            L"*\\shell\\BlackHole.Delete",
            L"Directory\\shell\\BlackHole",
            L"Directory\\Background\\shell\\BlackHole",
            L"Folder\\shell\\BlackHole",
            L"Folder\\Background\\shell\\BlackHole",
            L"Drive\\shell\\BlackHole",
            L"AllFileSystemObjects\\shell\\BlackHole",
        };
        for (auto p : kStalePaths) {
            RegDeleteTreeW(HKEY_CLASSES_ROOT, p);
            HKEY hClasses;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes", 0, KEY_ALL_ACCESS, &hClasses) == ERROR_SUCCESS) {
                RegDeleteTreeW(hClasses, p);
                RegCloseKey(hClasses);
            }
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Classes", 0, KEY_ALL_ACCESS, &hClasses) == ERROR_SUCCESS) {
                RegDeleteTreeW(hClasses, p);
                RegCloseKey(hClasses);
            }
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Classes\\Wow6432Node", 0, KEY_ALL_ACCESS, &hClasses) == ERROR_SUCCESS) {
                RegDeleteTreeW(hClasses, p);
                RegCloseKey(hClasses);
            }
        }
    }

    InitCommonControls();

    g_wc.cbSize = sizeof(WNDCLASSEXW);
    g_wc.style = CS_HREDRAW | CS_VREDRAW | CS_DROPSHADOW;
    g_wc.lpfnWndProc = WndProc;
    g_wc.hInstance = hInstance;
    g_wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    g_wc.lpszClassName = L"BlackHoleClass";
    RegisterClassExW(&g_wc);

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int winW = (int)(CONTENT_W + DOCK_W), winH = 640;
    int winX = (screenW - winW) / 2, winY = (screenH - winH) / 2;

    g_hMainWindow = CreateWindowExW(WS_EX_ACCEPTFILES, g_wc.lpszClassName, L"Black Hole (B-H)",
        WS_POPUP | WS_VISIBLE | (g_resizableWindow ? (WS_THICKFRAME | WS_MAXIMIZEBOX | WS_MINIMIZEBOX) : 0),
        winX, winY, winW, winH, NULL, NULL, hInstance, NULL);

    {
        CHANGEFILTERSTRUCT cf = {};
        cf.cbSize = sizeof(CHANGEFILTERSTRUCT);
        ChangeWindowMessageFilterEx(g_hMainWindow, WM_DROPFILES, MSGFLT_ALLOW, &cf);
        ChangeWindowMessageFilterEx(g_hMainWindow, WM_COPYDATA, MSGFLT_ALLOW, &cf);
    }

    if (g_resizableWindow) {
        int policy = 2;
        DwmSetWindowAttribute(g_hMainWindow, 2, &policy, sizeof(policy));
    }

    UpdateDockRegion();

    if (!CreateDeviceD3D(g_hMainWindow)) {
        CleanupDeviceD3D();
        UnregisterClassW(g_wc.lpszClassName, hInstance);
        return 1;
    }

    ShowWindow(g_hMainWindow, SW_SHOWDEFAULT);
    UpdateWindow(g_hMainWindow);
    DragAcceptFiles(g_hMainWindow, TRUE);

    typedef BOOL (WINAPI *pChangeMsgFilter)(UINT, DWORD);
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32) {
        auto pFunc = (pChangeMsgFilter)GetProcAddress(hUser32, "ChangeWindowMessageFilter");
        if (pFunc) {
            pFunc(WM_DROPFILES, 1);
            pFunc(0x0049, 1);
        }
    }

    CreateToggleWindow(hInstance);
    UpdateTogglePosition();

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
    io.IniFilename = nullptr;

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    style.FrameRounding = 0.0f;
    style.GrabRounding = 0.0f;
    style.ScrollbarRounding = 0.0f;
    style.WindowPadding = ImVec2(0, 0);
    style.FramePadding = ImVec2(0, 0);
    style.ItemSpacing = ImVec2(0, 0);
    style.WindowBorderSize = 0.0f;
    style.ChildBorderSize = 0.0f;
    style.FrameBorderSize = 0.0f;

    style.Colors[ImGuiCol_PopupBg]      = g_darkMode ? ImVec4(0.04f, 0.04f, 0.05f, 0.94f) : ImVec4(0.92f, 0.92f, 0.94f, 0.94f);
    ApplyTheme();

    ImGui_ImplWin32_Init(g_hMainWindow);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    {
        if (g_embeddedFontDataSize > 0) {
            void* data1 = ImGui::MemAlloc(g_embeddedFontDataSize);
            memcpy(data1, g_embeddedFontData, g_embeddedFontDataSize);
            void* data2 = ImGui::MemAlloc(g_embeddedFontDataSize);
            memcpy(data2, g_embeddedFontData, g_embeddedFontDataSize);

            ImFontConfig cfg1;
            cfg1.FontDataOwnedByAtlas = true;
            cfg1.SizePixels = 15.0f;
            g_fontDefault = io.Fonts->AddFontFromMemoryTTF(data1, g_embeddedFontDataSize, 15.0f, &cfg1);

            ImFontConfig cfg2;
            cfg2.FontDataOwnedByAtlas = true;
            cfg2.SizePixels = 22.0f;
            g_fontSidebar = io.Fonts->AddFontFromMemoryTTF(data2, g_embeddedFontDataSize, 22.0f, &cfg2);

            void* data3 = ImGui::MemAlloc(g_embeddedFontDataSize);
            memcpy(data3, g_embeddedFontData, g_embeddedFontDataSize);
            ImFontConfig cfg3;
            cfg3.FontDataOwnedByAtlas = true;
            cfg3.SizePixels = 12.0f;
            g_fontPill = io.Fonts->AddFontFromMemoryTTF(data3, g_embeddedFontDataSize, 12.0f, &cfg3);

            if (lucide_font_size > 0) {
                void* iconData = ImGui::MemAlloc(lucide_font_size);
                memcpy(iconData, lucide_font_data, lucide_font_size);
                ImFontConfig iconCfg;
                iconCfg.FontDataOwnedByAtlas = true;
                iconCfg.SizePixels = 18.0f;
                g_fontIcon = io.Fonts->AddFontFromMemoryTTF(iconData, (int)lucide_font_size, 18.0f, &iconCfg);
            }
        }
    }
    if (!g_fontDefault) g_fontDefault = io.Fonts->AddFontDefault();
    if (!g_fontSidebar) g_fontSidebar = g_fontDefault;
    if (!g_fontPill) g_fontPill = g_fontDefault;
    if (!g_fontIcon) g_fontIcon = g_fontDefault;
    io.FontDefault = g_fontDefault;

    std::thread([]() { LoadLogs(); }).detach();
    CleanupAllOldEntries();
    g_installStatus.store(IsContextMenuInstalled());
    ShowTrayIcon(g_hMainWindow);

    MSG msg = {};
    while (g_running.load()) {
        bool hadMsg = false;
        while (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) g_running.store(false);
            if (msg.message != WM_MOUSEMOVE || msg.message == WM_PAINT) hadMsg = true;
        }
        if (!g_running.load()) break;
        if (g_ResizeWidth != 0 || g_ResizeHeight != 0) ResizeSwapChain();

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        float dt = io.DeltaTime;
        if (g_phraseWrongTimer > 0.0f) g_phraseWrongTimer -= dt;

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        RECT clientRc;
        GetClientRect(g_hMainWindow, &clientRc);
        ImGui::SetNextWindowSize(ImVec2((float)(clientRc.right - clientRc.left), (float)(clientRc.bottom - clientRc.top)));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);

        ImGuiWindowFlags mainFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBringToFrontOnFocus |
            ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoSavedSettings;

        ImGui::Begin("##Main", nullptr, mainFlags);
        {
            ImVec2 wPos = ImGui::GetWindowPos();
            ImVec2 wSize = ImGui::GetWindowSize();
            ImDrawList* dl = ImGui::GetWindowDrawList();
            float contentRightX = g_hideDock ? (g_resizableWindow ? wSize.x : CONTENT_W + DOCK_W) : (g_resizableWindow ? (wSize.x - DOCK_W) : CONTENT_W);

            float mainRadius = g_isMaximized ? 0.0f : 12.0f;
            dl->AddRectFilled(wPos, ImVec2(wPos.x + wSize.x, wPos.y + wSize.y),
                Vec4ToU32(CLR_MAIN_BG), mainRadius);

            float sidebarW = g_hideSidebar ? 0.0f : SIDEBAR_W;

            if (!g_hideSidebar) {
                float sbRadius = g_isMaximized ? 0.0f : 12.0f;
                dl->AddRectFilled(ImVec2(wPos.x, wPos.y), ImVec2(wPos.x + SIDEBAR_W, wPos.y + wSize.y),
                    Vec4ToU32(CLR_SIDEBAR_BG), sbRadius);
                dl->AddRectFilled(ImVec2(wPos.x + SIDEBAR_W - 1, wPos.y),
                    ImVec2(wPos.x + SIDEBAR_W, wPos.y + wSize.y),
                    Vec4ToU32(CLR_STROKE));
                float pulseFactor = 0.4f + (sinf(ImGui::GetTime() * 1.5f) + 1.0f) * 0.3f;
                if (g_sidebarGlowEnabled) {
                    ImU32 sidebarGlow = IM_COL32(
                        (int)(g_sidebarGlowColor[0] * 255),
                        (int)(g_sidebarGlowColor[1] * 255),
                        (int)(g_sidebarGlowColor[2] * 255),
                        (int)(pulseFactor * 255));
                    ImVec2 sbMin(wPos.x, wPos.y);
                    ImVec2 sbMax(wPos.x + SIDEBAR_W, wPos.y + wSize.y);
                    dl->AddRect(sbMin, sbMax, sidebarGlow, 12.0f, 1.5f, ImDrawFlags_RoundCornersAll);
                }
                {
                    int acR = g_darkMode ? 200 : 40;
                    int acG = g_darkMode ? 200 : 40;
                    int acB = g_darkMode ? 220 : 50;
                    ImU32 accentCol2 = IM_COL32(acR, acG, acB, (int)(0.15f * 255));
                    ImU32 accentFade2 = IM_COL32(acR, acG, acB, 0);
                    dl->AddRectFilledMultiColor(ImVec2(wPos.x + contentRightX / 2, wPos.y),
                        ImVec2(wPos.x + contentRightX, wPos.y + 1), accentCol2, accentFade2, accentFade2, accentCol2);
                    dl->AddRectFilledMultiColor(ImVec2(wPos.x + sidebarW, wPos.y),
                        ImVec2(wPos.x + contentRightX / 2, wPos.y + 1), accentFade2, accentCol2, accentCol2, accentFade2);
                    dl->AddRectFilledMultiColor(ImVec2(wPos.x + contentRightX / 2, wPos.y + wSize.y - 1),
                        ImVec2(wPos.x + contentRightX, wPos.y + wSize.y), accentCol2, accentFade2, accentFade2, accentCol2);
                    dl->AddRectFilledMultiColor(ImVec2(wPos.x + sidebarW, wPos.y + wSize.y - 1),
                        ImVec2(wPos.x + contentRightX / 2, wPos.y + wSize.y), accentFade2, accentCol2, accentCol2, accentFade2);
                }

                {
                    const char* sidebarText = "BLACKHOLE";
                    float charSpacing = 3.0f;
                    float sidebarTop = wPos.y + 20.0f;
                    float sidebarBot = wPos.y + wSize.y - 20.0f;
                    float sidebarH = sidebarBot - sidebarTop;

                    int charCount = 0;
                    for (const char* p = sidebarText; *p; p++) {
                        if (*p != '\n' && *p != ' ') charCount++;
                    }
                    float lineH = ImGui::GetTextLineHeight();
                    float textH = (charCount > 0) ? charCount * (lineH + charSpacing) - charSpacing : 0.0f;

                    float logoH = 60.0f;
                    float gap = 70.0f;
                    float totalContent = textH + gap + logoH + gap + textH;
                    float startY = sidebarTop + (sidebarH - totalContent) / 2.0f;

                    float textTop = startY;
                    float textBot = startY + textH;
                    float logoTop = textBot + gap;
                    float logoBot = logoTop + logoH;
                    float lineTop = logoBot + gap;
                    float lineBot = lineTop + textH;

                    ImVec4 sideTextColor = g_darkMode
                        ? ImVec4(1.0f, 1.0f, 1.0f, 1.0f)
                        : ImVec4(0.0f, 0.0f, 0.0f, 1.0f);

                    RenderSidebarTextGradient(sidebarText, charSpacing,
                        ImVec2(wPos.x, textTop), ImVec2(wPos.x + SIDEBAR_W, textBot),
                        1.0f, 0.0f, sideTextColor);

                    if (g_lineGlowEnabled) {
                        float lineX = wPos.x + SIDEBAR_W / 2.0f;
                        int lr = (int)(g_lineGlowColor[0] * 255);
                        int lg = (int)(g_lineGlowColor[1] * 255);
                        int lb = (int)(g_lineGlowColor[2] * 255);

                        for (int i = 0; i < 3; i++) {
                            float spread = (float)i * 1.0f;
                            float a = pulseFactor * (1.0f - (float)i / 3.0f);
                            ImU32 lineCol = IM_COL32(lr, lg, lb, (int)(a * 255));
                            dl->AddLine(ImVec2(lineX - spread, lineTop), ImVec2(lineX - spread, lineBot), lineCol, 1.0f);
                            dl->AddLine(ImVec2(lineX + spread, lineTop), ImVec2(lineX + spread, lineBot), lineCol, 1.0f);
                        }
                        ImU32 centerCol = IM_COL32(lr, lg, lb, (int)(pulseFactor * 255));
                        dl->AddLine(ImVec2(lineX, lineTop), ImVec2(lineX, lineBot), centerCol, 1.5f);
                    }

                    float logoW = 60.0f;
                    float logoX = wPos.x + (SIDEBAR_W - logoW) / 2.0f;
                    float logoY = logoTop;
                    dl->AddRectFilled(ImVec2(logoX, logoY), ImVec2(logoX + logoW, logoY + logoH),
                        Vec4ToU32(CLR_ELEM_BG), 8.0f);
                    dl->AddRect(ImVec2(logoX, logoY), ImVec2(logoX + logoW, logoY + logoH),
                        Vec4ToU32(CLR_STROKE), 8.0f, 0, 1.0f);

                    if (g_sidebarLogoSRV) {
                        float pad = 8.0f;
                        dl->AddImage((ImTextureID)g_sidebarLogoSRV,
                            ImVec2(logoX + pad, logoY + pad),
                            ImVec2(logoX + logoW - pad, logoY + logoH - pad),
                            ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, 255));
                    } else {
                        if (g_fontSidebar) ImGui::PushFont(g_fontSidebar);
                        const char* bText = "B";
                        ImVec2 bSize = ImGui::CalcTextSize(bText);
                        dl->AddText(ImVec2(logoX + (logoW - bSize.x) / 2, logoY + (logoH - bSize.y) / 2),
                            Vec4ToU32(CLR_TEXT), bText);
                        if (g_fontSidebar) ImGui::PopFont();
                    }
                }
            }

            float titleBarY = wPos.y;
            dl->AddRectFilled(ImVec2(wPos.x + sidebarW, titleBarY),
                ImVec2(wPos.x + contentRightX, titleBarY + TITLE_BAR_H),
                Vec4ToU32(CLR_SIDEBAR_BG));


            {
                float moonR = 7.0f;
                float moonX = wPos.x + sidebarW + 16.0f;
                float moonY = titleBarY + TITLE_BAR_H / 2.0f;
                bool moonHov = fabsf(io.MousePos.x - moonX) < moonR + 4 &&
                               fabsf(io.MousePos.y - moonY) < moonR + 4;

                if (g_darkMode) {
                    ImU32 moonCol = moonHov ? IM_COL32(240, 240, 250, 220) : IM_COL32(200, 200, 210, 180);
                    dl->AddCircleFilled(ImVec2(moonX, moonY), moonR, moonCol, 16);
                    dl->AddCircleFilled(ImVec2(moonX + 3.5f, moonY - 2.5f), moonR * 0.75f,
                        Vec4ToU32(CLR_SIDEBAR_BG), 16);
                } else {
                    ImU32 sunCol = moonHov ? IM_COL32(240, 160, 30, 240) : IM_COL32(220, 140, 20, 200);
                    dl->AddCircleFilled(ImVec2(moonX, moonY), moonR, sunCol, 16);
                    for (int r = 0; r < 8; r++) {
                        float angle = (float)r / 8.0f * 2.0f * PI;
                        float x1 = moonX + cosf(angle) * (moonR + 2.0f);
                        float y1 = moonY + sinf(angle) * (moonR + 2.0f);
                        float x2 = moonX + cosf(angle) * (moonR + 5.0f);
                        float y2 = moonY + sinf(angle) * (moonR + 5.0f);
                        dl->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), sunCol, 1.5f);
                    }
                }

                if (moonHov) {
                    ImVec2 ttSz = ImGui::CalcTextSize("Toggle theme");
                    float ttX = moonX + moonR + 8.0f;
                    float ttY = moonY - ttSz.y / 2.0f;
                    dl->AddRectFilled(ImVec2(ttX - 5.0f, ttY - 3.0f),
                        ImVec2(ttX + ttSz.x + 5.0f, ttY + ttSz.y + 3.0f),
                        Vec4ToU32(CLR_POPUP_BG), 4.0f);
                    dl->AddRect(ImVec2(ttX - 5.0f, ttY - 3.0f),
                        ImVec2(ttX + ttSz.x + 5.0f, ttY + ttSz.y + 3.0f),
                        Vec4ToU32(CLR_STROKE), 4.0f, 0, 1.0f);
                    dl->AddText(ImVec2(ttX, ttY), Vec4ToU32(CLR_TEXT_DIM), "Toggle theme");
                }

                if (io.MouseClicked[0] && moonHov) {
                    g_darkMode = !g_darkMode;
                    ApplyTheme();
                    SaveConfig();
                }
            }

            {
                ImVec2 ts = ImGui::CalcTextSize("B-H");
                float tx = wPos.x + sidebarW + (contentRightX - sidebarW - ts.x) / 2.0f;
                dl->AddText(ImVec2(tx, titleBarY + (TITLE_BAR_H - ts.y) / 2.0f),
                    Vec4ToU32(CLR_TEXT), "B-H");
            }

            {
                float btnR = 7.0f;
                float btnPad = 14.0f;
                float btnGap = 6.0f;
                float btnY = titleBarY + TITLE_BAR_H / 2.0f;
                float closeX = wPos.x + contentRightX - btnPad - btnR;
                float minX, maxX;

                if (g_resizableWindow) {
                    maxX = closeX - btnR * 2 - btnGap;
                    minX = maxX - btnR * 2 - btnGap;
                } else {
                    minX = closeX - btnR * 2 - btnGap;
                }

                dl->AddCircleFilled(ImVec2(closeX, btnY), btnR, IM_COL32(200, 60, 60, 255));
                dl->AddCircleFilled(ImVec2(minX, btnY), btnR, IM_COL32(220, 190, 50, 255));

                if (g_resizableWindow) {
                    dl->AddCircleFilled(ImVec2(maxX, btnY), btnR, IM_COL32(80, 200, 120, 255));
                }

                if (io.MouseClicked[0]) {
                    ImVec2 m = io.MousePos;
                    if (fabsf(m.x - closeX) < btnR && fabsf(m.y - btnY) < btnR)
                        g_running.store(false);
                    if (fabsf(m.x - minX) < btnR && fabsf(m.y - btnY) < btnR)
                        ShowWindow(g_hMainWindow, SW_MINIMIZE);
                    if (g_resizableWindow && fabsf(m.x - maxX) < btnR && fabsf(m.y - btnY) < btnR) {
                        if (g_isMaximized)
                            ShowWindow(g_hMainWindow, SW_RESTORE);
                        else
                            ShowWindow(g_hMainWindow, SW_MAXIMIZE);
                    }
                }

                if (io.MouseDoubleClicked[0]) {
                    ImVec2 m = io.MousePos;
                    if (g_resizableWindow && m.y < titleBarY + TITLE_BAR_H
                        && m.x > (g_hideSidebar ? wPos.x : wPos.x + SIDEBAR_W)
                        && m.x < wPos.x + contentRightX
                        && fabsf(m.x - closeX) > btnR + 4
                        && fabsf(m.x - minX) > btnR + 4
                        && fabsf(m.x - maxX) > btnR + 4) {
                        if (g_isMaximized)
                            ShowWindow(g_hMainWindow, SW_RESTORE);
                        else
                            ShowWindow(g_hMainWindow, SW_MAXIMIZE);
                    }
                }
            }

            float contentX = wPos.x + sidebarW + 12.0f;
            float contentY = wPos.y + TITLE_BAR_H + 8.0f;
            float contentW = contentRightX - sidebarW - 24.0f;
            float contentH = wSize.y - TITLE_BAR_H - 16.0f;

            ImGui::SetCursorPos(ImVec2(sidebarW + 12.0f, TITLE_BAR_H + 8.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 6.0f);
            ImGui::BeginChild("##Content", ImVec2(contentW, contentH), true,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBackground);
            {
                ImVec2 cPos = ImGui::GetWindowPos();
                ImVec2 cSize = ImGui::GetWindowSize();
                ImDrawList* cdl = ImGui::GetWindowDrawList();

                cdl->AddRectFilled(cPos, ImVec2(cPos.x + cSize.x, cPos.y + cSize.y),
                    Vec4ToU32(CLR_CHILD_BG), 6.0f);
                cdl->AddRect(cPos, ImVec2(cPos.x + cSize.x, cPos.y + cSize.y),
                    Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);

                float innerY = cPos.y + 8.0f;
                float innerH = cSize.y - 16.0f;
                float pad = 8.0f;

                if (g_selectedTab == 2) {
                    static float logRefreshTimer = 0.0f;
                    logRefreshTimer += dt;
                    if (logRefreshTimer > 2.0f) {
                        logRefreshTimer = 0.0f;
                        LoadLogs();
                    }

                    cdl->AddRectFilled(ImVec2(cPos.x + pad, innerY),
                        ImVec2(cPos.x + cSize.x - pad, innerY + innerH),
                        Vec4ToU32(CLR_CHILD_BG), 4.0f);

                    const char* statusText = g_logEntries.empty() ? "Ready" : "Logs active";
                    ImVec2 stSz = ImGui::CalcTextSize(statusText);
                    cdl->AddText(ImVec2(cPos.x + 12.0f, innerY + 6.0f),
                        Vec4ToU32(ImVec4(0.56f, 0.56f, 0.60f, 1.0f)), statusText);

                    {
                        const char* clearLabel = "Clear Logs";
                        ImVec2 csz = ImGui::CalcTextSize(clearLabel);
                        float btnW = csz.x + 20.0f;
                        float btnH = csz.y + 8.0f;
                        float btnX = cPos.x + cSize.x - pad - btnW;
                        float btnY = innerY + innerH - btnH - 4.0f;
                        ImU32 btnBg = IM_COL32(80, 25, 25, 255);
                        ImU32 btnBorder = IM_COL32(140, 40, 40, 255);
                        ImU32 btnText = g_darkMode ? IM_COL32(220, 80, 80, 255) : IM_COL32(180, 30, 30, 255);

                        ImVec2 m = io.MousePos;
                        bool hovered = m.x >= btnX && m.x <= btnX + btnW && m.y >= btnY && m.y <= btnY + btnH;
                        if (hovered) {
                            btnBg = IM_COL32(100, 30, 30, 255);
                            btnBorder = IM_COL32(180, 50, 50, 255);
                        }
                        cdl->AddRectFilled(ImVec2(btnX, btnY), ImVec2(btnX + btnW, btnY + btnH), btnBg, 3.0f);
                        cdl->AddRect(ImVec2(btnX, btnY), ImVec2(btnX + btnW, btnY + btnH), btnBorder, 3.0f, 0, 1.0f);
                        cdl->AddText(ImVec2(btnX + 10.0f, btnY + 4.0f), btnText, clearLabel);

                        if (hovered && io.MouseClicked[0]) {
                            PWSTR appDataPath = nullptr;
                            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appDataPath))) {
                                std::wstring wLogPath(appDataPath);
                                CoTaskMemFree(appDataPath);
                                wLogPath += L"\\BlackHole\\audit.log";
                                SetFileAttributesW(wLogPath.c_str(), FILE_ATTRIBUTE_NORMAL);
                                DeleteFileW(wLogPath.c_str());
                                HANDLE hF = CreateFileW(wLogPath.c_str(), GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    NULL, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, NULL);
                                if (hF != INVALID_HANDLE_VALUE) CloseHandle(hF);
                            }
                            std::lock_guard<std::mutex> lock(g_logMutex);
                            g_logEntries.clear();
                            g_logEntriesUtf8.clear();
                        }
                    }

                    float listY = innerY + 24.0f;
                    float listH = innerH - 56.0f;

                    if (g_logEntries.empty()) {
                        ImVec2 ph = ImGui::CalcTextSize("No log entries");
                        cdl->AddText(ImVec2(cPos.x + (cSize.x - ph.x) / 2, listY + listH / 2 - ph.y / 2),
                            Vec4ToU32(CLR_TEXT_DIM), "No log entries");
                    } else {
                        float lineY = listY + 8.0f;
                        float lineH = 20.0f;
                        int maxVisible = (int)(listH / lineH);
                        int startIdx = ImMax(0, (int)g_logEntriesUtf8.size() - maxVisible);

                        float colClearX = cPos.x + cSize.x - pad - 44.0f;
                        float colRestoreX = colClearX - 10.0f - 58.0f;
                        float textMaxX = colRestoreX - 8.0f;
                        for (int i = startIdx; i < (int)g_logEntriesUtf8.size(); i++) {
                            if (lineY > listY + listH - 4.0f) break;

                            float rowMinX = cPos.x + 8.0f;
                            float rowMaxX = cPos.x + cSize.x - pad;
                            bool rowHover = (io.MousePos.x >= rowMinX && io.MousePos.x <= rowMaxX &&
                                             io.MousePos.y >= lineY && io.MousePos.y <= lineY + lineH);
                            if (rowHover) {
                                cdl->AddRectFilled(ImVec2(rowMinX, lineY), ImVec2(rowMaxX, lineY + lineH),
                                    g_darkMode ? IM_COL32(255, 255, 255, 8) : IM_COL32(0, 0, 0, 10), 3.0f);
                            }

                            ImVec4 logColor = ImVec4(0.51f, 0.51f, 0.55f, 1.0f);
                            std::string logLine = g_logEntriesUtf8[i];

                            bool isDeletionFailed = logLine.find("| Failed | ") != std::string::npos;
                            bool isDeletionSuccess = (logLine.find("| Deleted | ") != std::string::npos ||
                                                      logLine.find("| Trashed | ") != std::string::npos);
                            if (isDeletionFailed)
                                logColor = ImVec4(0.9f, 0.35f, 0.35f, 1.0f);
                            else if (isDeletionSuccess)
                                logColor = ImVec4(0.3f, 0.8f, 0.5f, 1.0f);

                            float availTextW = textMaxX - (cPos.x + 12.0f);
                            ImVec2 fullTxtSz = ImGui::CalcTextSize(logLine.c_str());
                            const char* drawStr = logLine.c_str();
                            std::string truncated;
                            if (fullTxtSz.x > availTextW && availTextW > 40.0f) {
                                int chars = (int)(logLine.size() * (availTextW / fullTxtSz.x));
                                if (chars > 3) {
                                    truncated = logLine.substr(0, chars - 3) + "...";
                                    drawStr = truncated.c_str();
                                }
                            }
                            cdl->AddText(ImVec2(cPos.x + 12.0f, lineY),
                                Vec4ToU32(logColor), drawStr);

                            {
                                bool isRecycled = logLine.find("| Recycled | ") != std::string::npos;
                                if (isRecycled) {
                                    float ubW = 58.0f;
                                    float ubH = 16.0f;
                                    float ubX = colRestoreX;
                                    float ubY = lineY + 2.0f;
                                    ImVec2 ubMin(ubX, ubY);
                                    ImVec2 ubMax(ubX + ubW, ubY + ubH);
                                    bool ubHov = ImGui::IsMouseHoveringRect(ubMin, ubMax);
                                    ImU32 ubBg = ubHov ? IM_COL32(50, 120, 80, 255) : IM_COL32(35, 90, 60, 200);
                                    cdl->AddRectFilled(ubMin, ubMax, ubBg, 3.0f);
                                    cdl->AddRect(ubMin, ubMax, IM_COL32(70, 170, 110, 200), 3.0f, 0, 1.0f);
                                    cdl->AddText(ImVec2(ubX + 4.0f, ubY + 1.0f), g_darkMode ? IM_COL32(120, 235, 160, 255) : IM_COL32(20, 120, 50, 255), "Restore");
                                    if (ubHov && io.MouseClicked[0]) {
                                        std::string entry = g_logEntriesUtf8[i];
                                        size_t p1 = entry.find(" | ");
                                        if (p1 != std::string::npos) {
                                            size_t p2 = entry.find(" | ", p1 + 3);
                                            if (p2 != std::string::npos) {
                                                std::wstring origPath = Utf8ToWide(entry.substr(p2 + 3));
                                                bool ok = false;
                                                try {
                                                    BlackHole::Deletor deletor;
                                                    ok = deletor.RestoreFromRecycleBin(origPath);
                                                } catch (...) {}
                                                if (ok) {
                                                    std::string ts = entry.substr(0, entry.find(" | "));
                                                    {
                                                        std::lock_guard<std::mutex> lock(g_logMutex);
                                                        g_logEntries.erase(g_logEntries.begin() + i);
                                                        g_logEntriesUtf8.erase(g_logEntriesUtf8.begin() + i);
                                                    }
                                                    i--;
                                                    RemoveLogEntryFromDisk(ts);
                                                    PushNotification(L"Restored", std::filesystem::path(origPath).filename().wstring(), false);
                                                } else {
                                                    PushNotification(L"Restore Failed", std::filesystem::path(origPath).filename().wstring(), true);
                                                }
                                            }
                                        }
                                    }
                                }

                                float clW = 44.0f;
                                float clX = colClearX;
                                float clY = lineY + 2.0f;
                                float clH = 16.0f;
                                ImVec2 clMin(clX, clY);
                                ImVec2 clMax(clX + clW, clY + clH);
                                bool clHov = ImGui::IsMouseHoveringRect(clMin, clMax);
                                ImU32 clBg = clHov ? IM_COL32(100, 30, 30, 255) : IM_COL32(80, 25, 25, 200);
                                cdl->AddRectFilled(clMin, clMax, clBg, 3.0f);
                                cdl->AddRect(clMin, clMax, IM_COL32(160, 50, 50, 200), 3.0f, 0, 1.0f);
                                cdl->AddText(ImVec2(clX + 8.0f, clY + 1.0f), g_darkMode ? IM_COL32(220, 80, 80, 255) : IM_COL32(180, 30, 30, 255), "Clear");
                                if (clHov && io.MouseClicked[0]) {
                                    std::string clearedUtf8 = g_logEntriesUtf8[i];
                                    std::string timestamp = clearedUtf8.substr(0, clearedUtf8.find(" | "));
                                    int clearIdx = i;
                                    {
                                        std::lock_guard<std::mutex> lock(g_logMutex);
                                        g_logEntries.erase(g_logEntries.begin() + clearIdx);
                                        g_logEntriesUtf8.erase(g_logEntriesUtf8.begin() + clearIdx);
                                    }
                                    i--;
                                    RemoveLogEntryFromDisk(timestamp);
                                }
                            }

                            lineY += lineH;
                        }
                    }
                } else if (g_selectedTab == 1) {
                    float treeX = cPos.x + 16.0f;
                    float treeY = innerY + 12.0f;
                    float treeW = contentW - 32.0f;
                    g_analysisAnimTime += dt;

                    // === DRAG AND DROP ZONE (when no file selected) ===
                    if (g_selectedFile.empty()) {
                        float dropH = innerH - 24.0f;
                        ImVec2 dropMin(treeX, treeY);
                        ImVec2 dropMax(treeX + treeW, treeY + dropH);
                        bool dropHover = ImGui::IsMouseHoveringRect(dropMin, dropMax);

                        ImU32 dropBg = dropHover ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG);
                        ImU32 dropBorder = dropHover ? Vec4ToU32(CLR_STROKE) : Vec4ToU32(CLR_STROKE);
                        cdl->AddRectFilled(dropMin, dropMax, dropBg, 12.0f);
                        cdl->AddRect(dropMin, dropMax, dropBorder, 12.0f, 0, dropHover ? 2.0f : 1.0f);

                        float centerX = treeX + treeW / 2.0f;
                        float centerY = treeY + dropH / 2.0f;

                        // Upload icon (arrow up)
                        float iconR = 24.0f;
                        ImU32 iconCol = dropHover ? Vec4ToU32(CLR_TEXT) : Vec4ToU32(CLR_TEXT_DIM);
                        cdl->AddLine(ImVec2(centerX, centerY - iconR), ImVec2(centerX, centerY + 4), iconCol, 2.5f);
                        cdl->AddLine(ImVec2(centerX - 10, centerY - 14), ImVec2(centerX, centerY - 24), iconCol, 2.5f);
                        cdl->AddLine(ImVec2(centerX + 10, centerY - 14), ImVec2(centerX, centerY - 24), iconCol, 2.5f);
                        // Base line
                        cdl->AddLine(ImVec2(centerX - 14, centerY + 4), ImVec2(centerX + 14, centerY + 4), iconCol, 2.5f);

                        const char* dropText = "Drop a file or folder here";
                        ImVec2 dtSize = ImGui::CalcTextSize(dropText);
                        cdl->AddText(ImVec2(centerX - dtSize.x / 2, centerY + 20),
                            dropHover ? Vec4ToU32(CLR_TEXT) : Vec4ToU32(CLR_TEXT_DIM), dropText);

                        const char* subText = "or click a button below";
                        ImVec2 stSize = ImGui::CalcTextSize(subText);
                        cdl->AddText(ImVec2(centerX - stSize.x / 2, centerY + 40),
                            Vec4ToU32(CLR_TEXT_DIM), subText);

                        // Buttons at bottom of drop zone
                        float btnW = 110.0f, btnH = 34.0f;
                        float btnGap2 = 8.0f;
                        float btnY2 = treeY + dropH - btnH - 16.0f;
                        float totalBtnW = btnW * 2 + btnGap2;
                        float btnStartX = treeX + treeW / 2 - totalBtnW / 2;

                        ImVec2 sfMin2(btnStartX, btnY2);
                        ImVec2 sfMax2(btnStartX + btnW, btnY2 + btnH);
                        bool sfHov2 = ImGui::IsMouseHoveringRect(sfMin2, sfMax2);
                        cdl->AddRectFilled(sfMin2, sfMax2, sfHov2 ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 8.0f);
                        cdl->AddRect(sfMin2, sfMax2, Vec4ToU32(CLR_STROKE), 8.0f, 0, 1.0f);
                        ImVec2 sfLabelSz = ImGui::CalcTextSize("Select File");
                        cdl->AddText(ImVec2((sfMin2.x + sfMax2.x - sfLabelSz.x) / 2, (sfMin2.y + sfMax2.y - sfLabelSz.y) / 2),
                            Vec4ToU32(CLR_TEXT), "Select File");

                        ImVec2 sf2Min(btnStartX + btnW + btnGap2, btnY2);
                        ImVec2 sf2Max(btnStartX + btnW * 2 + btnGap2, btnY2 + btnH);
                        bool sf2Hov = ImGui::IsMouseHoveringRect(sf2Min, sf2Max);
                        cdl->AddRectFilled(sf2Min, sf2Max, sf2Hov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 8.0f);
                        cdl->AddRect(sf2Min, sf2Max, Vec4ToU32(CLR_STROKE), 8.0f, 0, 1.0f);
                        ImVec2 sf2LabelSz = ImGui::CalcTextSize("Select Folder");
                        cdl->AddText(ImVec2((sf2Min.x + sf2Max.x - sf2LabelSz.x) / 2, (sf2Min.y + sf2Max.y - sf2LabelSz.y) / 2),
                            Vec4ToU32(CLR_TEXT), "Select Folder");

                        if (io.MouseClicked[0] && sfHov2)
                            SelectFile(g_hMainWindow);
                        if (io.MouseClicked[0] && sf2Hov)
                            SelectFolder(g_hMainWindow);

                    } else {
                    // === FILE SELECTOR BAR (when file is selected) ===
                    float selBarH = 40.0f;
                    cdl->AddRectFilled(ImVec2(treeX, treeY), ImVec2(treeX + treeW, treeY + selBarH), Vec4ToU32(CLR_ELEM_BG), 6.0f);
                    cdl->AddRect(ImVec2(treeX, treeY), ImVec2(treeX + treeW, treeY + selBarH), Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);

                    bool isDir = (GetFileAttributesW(g_selectedFile.c_str()) & FILE_ATTRIBUTE_DIRECTORY) != 0;
                    ImU32 pathIconCol = isDir ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_TEXT_DIM);
                    cdl->AddText(ImVec2(treeX + 10, treeY + (selBarH - 14) / 2), pathIconCol, isDir ? "[DIR]" : "[FILE]");

                    std::wstring fname = std::filesystem::path(g_selectedFile).filename().wstring();
                    int fsz = WideCharToMultiByte(CP_UTF8, 0, fname.c_str(), (int)fname.size(), NULL, 0, NULL, NULL);
                    std::string fnameStr(fsz, 0);
                    WideCharToMultiByte(CP_UTF8, 0, fname.c_str(), (int)fname.size(), &fnameStr[0], fsz, NULL, NULL);
                    if (fnameStr.size() > 75) fnameStr = fnameStr.substr(0, 72) + "...";
                    cdl->AddText(ImVec2(treeX + 52, treeY + (selBarH - 14) / 2), Vec4ToU32(CLR_TEXT), fnameStr.c_str());

                    // X button to clear selection
                    float xBtnSize = 20.0f;
                    ImVec2 xMin(treeX + treeW - xBtnSize - 6, treeY + (selBarH - xBtnSize) / 2);
                    ImVec2 xMax(xMin.x + xBtnSize, xMin.y + xBtnSize);
                    bool xHov = ImGui::IsMouseHoveringRect(xMin, xMax);
                    if (xHov) cdl->AddRectFilled(xMin, xMax, Vec4ToU32(CLR_ELEM_BG_HOVER), 4.0f);
                    ImVec2 xT = ImGui::CalcTextSize("X");
                    cdl->AddText(ImVec2((xMin.x + xMax.x - xT.x) / 2, (xMin.y + xMax.y - xT.y) / 2),
                        xHov ? Vec4ToU32(CLR_TEXT) : Vec4ToU32(CLR_TEXT_DIM), "X");
                    if (io.MouseClicked[0] && xHov) {
                        g_selectedFile.clear();
                        g_impactAnalysis = {};
                        g_showDeleteConfirm = false;
                        g_leftoverChecked.clear();
                        g_showLeftoverCleanConfirm = false;
                        g_lockedByChecked.clear();
                        g_dependentAppsChecked.clear();
                        g_registryRefsChecked.clear();
                        g_serviceRefsChecked.clear();
                        g_relatedFilesChecked.clear();
                    }

                    if (g_autoAnalyzeOnStart && !g_selectedFile.empty() && !g_analysisRunning) {
                        g_autoAnalyzeOnStart = false;
                        g_analysisRunning = true;
                        g_impactAnalysis = {};
                        std::wstring path = g_selectedFile;
                        LaunchBigStackThread([path]() {
                            BlackHole::ImpactAnalyzer analyzer;
                            g_impactAnalysis = analyzer.Analyze(path);
                            g_analysisRunning = false;
                        });
                    }

                    // === BUTTONS ===
                    float btnW = 90.0f, btnH = 32.0f;
                    float btnY = treeY + selBarH + 10.0f;
                    float btnGap = 6.0f;

                    // Select File button
                    ImVec2 selMin(treeX, btnY);
                    ImVec2 selMax(treeX + btnW, btnY + btnH);
                    bool selHov = ImGui::IsMouseHoveringRect(selMin, selMax);
                    cdl->AddRectFilled(selMin, selMax, selHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                    cdl->AddRect(selMin, selMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                    ImVec2 selT = ImGui::CalcTextSize("Select File");
                    cdl->AddText(ImVec2((selMin.x + selMax.x - selT.x) / 2, (selMin.y + selMax.y - selT.y) / 2), Vec4ToU32(CLR_TEXT), "Select File");

                    // Select Folder button
                    ImVec2 sfMin(treeX + btnW + btnGap, btnY);
                    ImVec2 sfMax(treeX + (btnW + btnGap) * 2, btnY + btnH);
                    bool sfHov = ImGui::IsMouseHoveringRect(sfMin, sfMax);
                    cdl->AddRectFilled(sfMin, sfMax, sfHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                    cdl->AddRect(sfMin, sfMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                    ImVec2 sfT = ImGui::CalcTextSize("Select Folder");
                    cdl->AddText(ImVec2((sfMin.x + sfMax.x - sfT.x) / 2, (sfMin.y + sfMax.y - sfT.y) / 2), Vec4ToU32(CLR_TEXT), "Select Folder");

                    // Analyze button
                    ImVec2 anaMin(treeX + (btnW + btnGap) * 2, btnY);
                    ImVec2 anaMax(treeX + (btnW + btnGap) * 3, btnY + btnH);
                    bool canAnalyze = !g_selectedFile.empty() && !g_analysisRunning;
                    bool anaHov = canAnalyze && ImGui::IsMouseHoveringRect(anaMin, anaMax);
                    cdl->AddRectFilled(anaMin, anaMax, anaHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                    cdl->AddRect(anaMin, anaMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                    ImVec2 anaT = ImGui::CalcTextSize(g_analysisRunning ? "Analyzing..." : "Analyze");
                    cdl->AddText(ImVec2((anaMin.x + anaMax.x - anaT.x) / 2, (anaMin.y + anaMax.y - anaT.y) / 2),
                        canAnalyze ? Vec4ToU32(CLR_TEXT) : Vec4ToU32(CLR_TEXT_DIM), g_analysisRunning ? "Analyzing..." : "Analyze");

                    // Delete button
                    ImVec2 delMin(treeX + (btnW + btnGap) * 3, btnY);
                    ImVec2 delMax(treeX + (btnW + btnGap) * 4, btnY + btnH);
                    bool canDel = !g_selectedFile.empty() && g_impactAnalysis.analyzed;
                    bool delHov = canDel && ImGui::IsMouseHoveringRect(delMin, delMax);
                    cdl->AddRectFilled(delMin, delMax, delHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                    cdl->AddRect(delMin, delMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                    ImVec2 delT = ImGui::CalcTextSize("Delete");
                    cdl->AddText(ImVec2((delMin.x + delMax.x - delT.x) / 2, (delMin.y + delMax.y - delT.y) / 2),
                        canDel ? Vec4ToU32(CLR_TEXT) : Vec4ToU32(CLR_TEXT_DIM), "Delete");

                    if (io.MouseClicked[0]) {
                        ImVec2 m = io.MousePos;
                        if (m.x >= selMin.x && m.x <= selMax.x && m.y >= selMin.y && m.y <= selMax.y)
                            SelectFile(g_hMainWindow);
                        if (m.x >= sfMin.x && m.x <= sfMax.x && m.y >= sfMin.y && m.y <= sfMax.y)
                            SelectFolder(g_hMainWindow);
                        if (canAnalyze && m.x >= anaMin.x && m.x <= anaMax.x && m.y >= anaMin.y && m.y <= anaMax.y) {
                            g_analysisRunning = true;
                            g_impactAnalysis = {};
                            std::wstring path = g_selectedFile;
                            LaunchBigStackThread([path]() {
                                BlackHole::ImpactAnalyzer analyzer;
                                g_impactAnalysis = analyzer.Analyze(path);
                                g_analysisRunning = false;
                            });
                        }
                        if (canDel && m.x >= delMin.x && m.x <= delMax.x && m.y >= delMin.y && m.y <= delMax.y) {
                            g_showDeleteConfirm = true;
                        }
                    }

                    // === ANALYSIS PROGRESS ANIMATION ===
                    if (g_analysisRunning) {
                        float animY = btnY + btnH + 30.0f;
                        float centerX = treeX + treeW / 2.0f;

                        // Pulsing dots
                        for (int i = 0; i < 3; i++) {
                            float phase = g_analysisAnimTime * 3.0f + i * 2.1f;
                            float pulse = (sinf(phase) + 1.0f) * 0.5f;
                            float dotR = 4.0f + pulse * 2.0f;
                            ImU32 dotCol = Vec4ToU32(CLR_STROKE);
                            float dotAlpha = 0.5f + pulse * 0.5f;
                            dotCol = (dotCol & 0x00FFFFFF) | ((ImU32)(dotAlpha * 255) << 24);
                            cdl->AddCircleFilled(ImVec2(centerX - 20 + i * 20, animY), dotR, dotCol, 12);
                        }

                        const char* analyzingText = "Analyzing file dependencies...";
                        ImVec2 atSize = ImGui::CalcTextSize(analyzingText);
                        cdl->AddText(ImVec2(centerX - atSize.x / 2, animY + 16),
                            Vec4ToU32(CLR_TEXT_DIM), analyzingText);
                    }

                    // === FILE INFO CARD + ANALYSIS RESULTS ===
                    if (g_impactAnalysis.analyzed && !g_analysisRunning) {
                        if (g_leftoverChecked.size() != g_impactAnalysis.leftovers.size())
                            g_leftoverChecked.assign(g_impactAnalysis.leftovers.size(), true);
                        if (g_lockedByChecked.size() != g_impactAnalysis.lockedBy.size())
                            g_lockedByChecked.assign(g_impactAnalysis.lockedBy.size(), true);
                        if (g_dependentAppsChecked.size() != g_impactAnalysis.dependentApps.size())
                            g_dependentAppsChecked.assign(g_impactAnalysis.dependentApps.size(), true);
                        if (g_registryRefsChecked.size() != g_impactAnalysis.registryRefs.size())
                            g_registryRefsChecked.assign(g_impactAnalysis.registryRefs.size(), true);
                        if (g_serviceRefsChecked.size() != g_impactAnalysis.serviceRefs.size())
                            g_serviceRefsChecked.assign(g_impactAnalysis.serviceRefs.size(), true);
                        if (g_relatedFilesChecked.size() != g_impactAnalysis.relatedFiles.size())
                            g_relatedFilesChecked.assign(g_impactAnalysis.relatedFiles.size(), true);
                        float curY = btnY + btnH + 16.0f;

                        // --- FILE INFO CARD ---
                        float cardH = 80.0f;
                        cdl->AddRectFilled(ImVec2(treeX, curY), ImVec2(treeX + treeW, curY + cardH), Vec4ToU32(CLR_ELEM_BG), 8.0f);
                        cdl->AddRect(ImVec2(treeX, curY), ImVec2(treeX + treeW, curY + cardH), Vec4ToU32(CLR_STROKE), 8.0f, 0, 1.0f);

                        bool cardIsDir = (GetFileAttributesW(g_impactAnalysis.filePath.c_str()) & FILE_ATTRIBUTE_DIRECTORY) != 0;
                        float cardPad = 12.0f;

                        // File type icon (large)
                        ImU32 fileIconCol = cardIsDir ? IM_COL32(140, 140, 160, 255) : IM_COL32(160, 155, 140, 255);
                        const char* typeTag = cardIsDir ? "DIR" : "FILE";
                        ImVec2 tagSize = ImGui::CalcTextSize(typeTag);
                        cdl->AddRectFilled(ImVec2(treeX + cardPad, curY + cardPad),
                            ImVec2(treeX + cardPad + tagSize.x + 10, curY + cardPad + tagSize.y + 6), fileIconCol, 4.0f);
                        cdl->AddText(ImVec2(treeX + cardPad + 5, curY + cardPad + 3), Vec4ToU32(CLR_ELEM_BG), typeTag);

                        // Filename
                        std::string fileNameUtf8;
                        {
                            int fsz2 = WideCharToMultiByte(CP_UTF8, 0, g_impactAnalysis.fileName.c_str(), -1, NULL, 0, NULL, NULL);
                            fileNameUtf8.assign(fsz2 > 1 ? fsz2 - 1 : 0, 0);
                            WideCharToMultiByte(CP_UTF8, 0, g_impactAnalysis.fileName.c_str(), -1, &fileNameUtf8[0], fsz2, NULL, NULL);
                        }
                        cdl->AddText(ImVec2(treeX + cardPad, curY + cardPad + tagSize.y + 12), Vec4ToU32(CLR_TEXT), fileNameUtf8.c_str());

                        // File size (right-aligned)
                        char sizeBuf[32];
                        if (g_impactAnalysis.fileSize > 1024 * 1024 * 1024)
                            sprintf_s(sizeBuf, "%.1f GB", g_impactAnalysis.fileSize / (1024.0 * 1024.0 * 1024.0));
                        else if (g_impactAnalysis.fileSize > 1024 * 1024)
                            sprintf_s(sizeBuf, "%.1f MB", g_impactAnalysis.fileSize / (1024.0 * 1024.0));
                        else if (g_impactAnalysis.fileSize > 1024)
                            sprintf_s(sizeBuf, "%.1f KB", g_impactAnalysis.fileSize / 1024.0);
                        else
                            sprintf_s(sizeBuf, "%llu B", g_impactAnalysis.fileSize);
                        ImVec2 sizeText = ImGui::CalcTextSize(sizeBuf);
                        cdl->AddText(ImVec2(treeX + treeW - sizeText.x - cardPad, curY + cardPad + tagSize.y + 12),
                            Vec4ToU32(CLR_TEXT_DIM), sizeBuf);

                        // Metadata row: Publisher | Version | Signature
                        float metaY = curY + cardPad + tagSize.y + 32;
                        float metaX = treeX + cardPad;
                        auto DrawMeta = [&](const char* label, const std::wstring& value, ImU32 valCol) {
                            if (value.empty()) return;
                            std::string valUtf8;
                            {
                                int sz = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, NULL, 0, NULL, NULL);
                                valUtf8.assign(sz > 1 ? sz - 1 : 0, 0);
                                WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, &valUtf8[0], sz, NULL, NULL);
                            }
                            if (valUtf8.size() > 30) valUtf8 = valUtf8.substr(0, 27) + "...";
                            std::string text = std::string(label) + ": " + valUtf8;
                            ImVec2 textSize = ImGui::CalcTextSize(text.c_str());
                            if (metaX + textSize.x > treeX + treeW) return;
                            cdl->AddText(ImVec2(metaX, metaY), Vec4ToU32(CLR_TEXT_DIM), label);
                            cdl->AddText(ImVec2(metaX + ImGui::CalcTextSize(label).x, metaY), valCol, valUtf8.c_str());
                            metaX += textSize.x + 16.0f;
                        };

                        ImU32 sigCol = g_impactAnalysis.isSigned ? IM_COL32(130, 170, 140, 255) : IM_COL32(170, 140, 130, 255);
                        DrawMeta("Publisher", g_impactAnalysis.publisher, Vec4ToU32(CLR_TEXT));
                        DrawMeta("Version", g_impactAnalysis.version, Vec4ToU32(CLR_TEXT));
                        DrawMeta("Signed", g_impactAnalysis.isSigned ? L"Yes" : L"No", sigCol);
                        if (g_impactAnalysis.isSystemFile) {
                            DrawMeta("Type", L"System File", Vec4ToU32(CLR_TEXT_DIM));
                        }

                        // Full path
                        std::string pathUtf8;
                        {
                            int psz = WideCharToMultiByte(CP_UTF8, 0, g_impactAnalysis.filePath.c_str(), -1, NULL, 0, NULL, NULL);
                            pathUtf8.assign(psz > 1 ? psz - 1 : 0, 0);
                            WideCharToMultiByte(CP_UTF8, 0, g_impactAnalysis.filePath.c_str(), -1, &pathUtf8[0], psz, NULL, NULL);
                        }
                        if (pathUtf8.size() > 85) pathUtf8 = "..." + pathUtf8.substr(pathUtf8.size() - 82);
                        cdl->AddText(ImVec2(treeX + cardPad, metaY + 16), Vec4ToU32(CLR_TEXT_DIM), pathUtf8.c_str());

                        curY += cardH + 12.0f;

                        // --- SECTION CARDS WITH LEFT BORDER ---
                        float lineH = 24.0f;
                        float indent = 12.0f;
                        float bulletR = 4.0f;

                        auto DrawSectionCard = [&](const char* label, int count, ImU32 accentCol, bool hasItems, std::atomic<bool>* expanded) {
                            if (curY >= innerY + innerH - 10) return;

                            // Card background
                            cdl->AddRectFilled(ImVec2(treeX, curY), ImVec2(treeX + treeW, curY + lineH), Vec4ToU32(CLR_ELEM_BG), 4.0f);

                            // Left accent border
                            if (hasItems)
                                cdl->AddRectFilled(ImVec2(treeX, curY), ImVec2(treeX + 3, curY + lineH), accentCol, 2.0f);

                            // Bullet
                            float bulletX = treeX + indent + 4;
                            float bulletY = curY + lineH / 2.0f;
                            if (hasItems)
                                cdl->AddCircleFilled(ImVec2(bulletX, bulletY), bulletR, accentCol, 8);
                            else
                                cdl->AddCircleFilled(ImVec2(bulletX, bulletY), bulletR, Vec4ToU32(CLR_STROKE), 8);

                            // Label
                            cdl->AddText(ImVec2(bulletX + 10, curY + (lineH - 14) / 2),
                                hasItems ? Vec4ToU32(CLR_TEXT) : Vec4ToU32(CLR_TEXT_DIM), label);

                            // Count badge
                            if (count > 0) {
                                char countBuf[16];
                                sprintf_s(countBuf, "%d", count);
                                ImVec2 countSize = ImGui::CalcTextSize(countBuf);
                                float badgeW = countSize.x + 10.0f;
                                float badgeX = bulletX + 10 + ImGui::CalcTextSize(label).x + 8;
                                float badgeY = curY + (lineH - 16) / 2.0f;
                                ImU32 badgeBg = accentCol & 0x00FFFFFF;
                                badgeBg = badgeBg | (ImU32)(40 << 24);
                                cdl->AddRectFilled(ImVec2(badgeX, badgeY), ImVec2(badgeX + badgeW, badgeY + 16.0f), badgeBg, 8.0f);
                                cdl->AddText(ImVec2(badgeX + 5.0f, badgeY + 1.0f), Vec4ToU32(CLR_TEXT), countBuf);
                            }

                            // Chevron
                            if (hasItems && expanded) {
                                float chevX = treeX + treeW - 20;
                                float chevY = curY + (lineH - 10) / 2.0f;
                                ImU32 chevCol = Vec4ToU32(CLR_TEXT_DIM);
                                ImVec2 chevMin(chevX - 8, chevY - 4);
                                ImVec2 chevMax(chevX + 16, chevY + 16);
                                bool chevHov = ImGui::IsMouseHoveringRect(chevMin, chevMax);
                                if (chevHov) chevCol = Vec4ToU32(CLR_TEXT);

                                if (*expanded) {
                                    cdl->AddLine(ImVec2(chevX, chevY + 2), ImVec2(chevX + 5, chevY + 8), chevCol, 1.8f);
                                    cdl->AddLine(ImVec2(chevX + 5, chevY + 8), ImVec2(chevX + 10, chevY + 2), chevCol, 1.8f);
                                } else {
                                    cdl->AddLine(ImVec2(chevX + 2, chevY), ImVec2(chevX + 8, chevY + 5), chevCol, 1.8f);
                                    cdl->AddLine(ImVec2(chevX + 8, chevY + 5), ImVec2(chevX + 2, chevY + 10), chevCol, 1.8f);
                                }

                                if (io.MouseClicked[0] && chevHov) *expanded = !(*expanded);
                            }

                            curY += lineH + 4;
                        };

                        auto DrawCheckItem = [&](const char* text, ImU32 col, bool checked, int idx, std::vector<bool>& checkVec) {
                            if (curY >= innerY + innerH - 10) return;
                            float itemH = 20.0f;
                            float cbSize = 12.0f;
                            float cbX = treeX + indent + 16;
                            float cbY = curY + (itemH - cbSize) / 2.0f;

                            ImU32 cbBg = checked ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG);
                            ImU32 cbBd = checked ? Vec4ToU32(CLR_STROKE) : Vec4ToU32(CLR_STROKE);
                            cdl->AddRectFilled(ImVec2(cbX, cbY), ImVec2(cbX + cbSize, cbY + cbSize), cbBg, 2.0f);
                            cdl->AddRect(ImVec2(cbX, cbY), ImVec2(cbX + cbSize, cbY + cbSize), cbBd, 2.0f, 0, 1.0f);
                            if (checked) {
                                cdl->AddLine(ImVec2(cbX + 3, cbY + 6), ImVec2(cbX + 5, cbY + 8), Vec4ToU32(CLR_TEXT), 1.5f);
                                cdl->AddLine(ImVec2(cbX + 5, cbY + 8), ImVec2(cbX + 9, cbY + 3), Vec4ToU32(CLR_TEXT), 1.5f);
                            }

                            ImVec2 cbClickMin(cbX - 2, cbY - 2);
                            ImVec2 cbClickMax(cbX + cbSize + 200, cbY + cbSize + 2);
                            if (io.MouseClicked[0] && ImGui::IsMouseHoveringRect(cbClickMin, cbClickMax)) {
                                if (idx >= 0 && idx < (int)checkVec.size())
                                    checkVec[idx] = !checkVec[idx];
                            }

                            cdl->AddText(ImVec2(cbX + cbSize + 6, curY + (itemH - 14) / 2.0f),
                                checked ? col : Vec4ToU32(CLR_TEXT_DIM), text);
                            curY += itemH;
                        };

                        // --- SECTIONS ---
                        DrawSectionCard("LOCKED BY", (int)g_impactAnalysis.lockedBy.size(),
                            IM_COL32(180, 140, 90, 255), !g_impactAnalysis.lockedBy.empty(), &g_showLockDetails);
                        if (g_showLockDetails && !g_impactAnalysis.lockedBy.empty()) {
                            for (int li = 0; li < (int)g_impactAnalysis.lockedBy.size(); li++) {
                                auto& lock = g_impactAnalysis.lockedBy[li];
                                std::string procUtf8;
                                {
                                    int wsz = WideCharToMultiByte(CP_UTF8, 0, lock.processName.c_str(), -1, NULL, 0, NULL, NULL);
                                    procUtf8.assign(wsz > 1 ? wsz - 1 : 0, 0);
                                    WideCharToMultiByte(CP_UTF8, 0, lock.processName.c_str(), -1, &procUtf8[0], wsz, NULL, NULL);
                                }
                                std::string info = procUtf8 + " (PID " + std::to_string(lock.pid) + ")";
                                DrawCheckItem(info.c_str(), Vec4ToU32(CLR_TEXT),
                                    li < (int)g_lockedByChecked.size() ? g_lockedByChecked[li] : true, li, g_lockedByChecked);
                            }
                        }

                        DrawSectionCard("DEPENDENT APPS", (int)g_impactAnalysis.dependentApps.size(),
                            IM_COL32(170, 130, 100, 255), !g_impactAnalysis.dependentApps.empty(), &g_showDependentDetails);
                        if (g_showDependentDetails && !g_impactAnalysis.dependentApps.empty()) {
                            for (int di = 0; di < (int)g_impactAnalysis.dependentApps.size(); di++) {
                                auto& app = g_impactAnalysis.dependentApps[di];
                                std::string appUtf8;
                                {
                                    int wsz = WideCharToMultiByte(CP_UTF8, 0, app.appName.c_str(), -1, NULL, 0, NULL, NULL);
                                    appUtf8.assign(wsz > 1 ? wsz - 1 : 0, 0);
                                    WideCharToMultiByte(CP_UTF8, 0, app.appName.c_str(), -1, &appUtf8[0], wsz, NULL, NULL);
                                }
                                DrawCheckItem(appUtf8.c_str(), Vec4ToU32(CLR_TEXT),
                                    di < (int)g_dependentAppsChecked.size() ? g_dependentAppsChecked[di] : true, di, g_dependentAppsChecked);
                            }
                        }

                        DrawSectionCard("REGISTRY REFERENCES", (int)g_impactAnalysis.registryRefs.size(),
                            IM_COL32(140, 150, 130, 255), !g_impactAnalysis.registryRefs.empty(), &g_showRegistryDetails);
                        if (g_showRegistryDetails && !g_impactAnalysis.registryRefs.empty()) {
                            for (int ri = 0; ri < (int)g_impactAnalysis.registryRefs.size(); ri++) {
                                auto& ref = g_impactAnalysis.registryRefs[ri];
                                std::string keyUtf8;
                                {
                                    int wsz = WideCharToMultiByte(CP_UTF8, 0, ref.keyPath.c_str(), -1, NULL, 0, NULL, NULL);
                                    keyUtf8.assign(wsz > 1 ? wsz - 1 : 0, 0);
                                    WideCharToMultiByte(CP_UTF8, 0, ref.keyPath.c_str(), -1, &keyUtf8[0], wsz, NULL, NULL);
                                }
                                if (keyUtf8.size() > 70) keyUtf8 = keyUtf8.substr(0, 67) + "...";
                                DrawCheckItem(keyUtf8.c_str(), Vec4ToU32(CLR_TEXT_DIM),
                                    ri < (int)g_registryRefsChecked.size() ? g_registryRefsChecked[ri] : true, ri, g_registryRefsChecked);
                            }
                        }

                        DrawSectionCard("SERVICES", (int)g_impactAnalysis.serviceRefs.size(),
                            IM_COL32(130, 140, 160, 255), !g_impactAnalysis.serviceRefs.empty(), &g_showServiceDetails);
                        if (g_showServiceDetails && !g_impactAnalysis.serviceRefs.empty()) {
                            for (int si = 0; si < (int)g_impactAnalysis.serviceRefs.size(); si++) {
                                auto& svc = g_impactAnalysis.serviceRefs[si];
                                std::string svcUtf8;
                                {
                                    int wsz = WideCharToMultiByte(CP_UTF8, 0, svc.serviceName.c_str(), -1, NULL, 0, NULL, NULL);
                                    svcUtf8.assign(wsz > 1 ? wsz - 1 : 0, 0);
                                    WideCharToMultiByte(CP_UTF8, 0, svc.serviceName.c_str(), -1, &svcUtf8[0], wsz, NULL, NULL);
                                }
                                DrawCheckItem(svcUtf8.c_str(), Vec4ToU32(CLR_TEXT),
                                    si < (int)g_serviceRefsChecked.size() ? g_serviceRefsChecked[si] : true, si, g_serviceRefsChecked);
                            }
                        }

                        DrawSectionCard("RELATED FILES", (int)g_impactAnalysis.relatedFiles.size(),
                            IM_COL32(120, 150, 140, 255), !g_impactAnalysis.relatedFiles.empty(), &g_showRelatedDetails);
                        if (g_showRelatedDetails && !g_impactAnalysis.relatedFiles.empty()) {
                            int shown = 0;
                            for (int fi = 0; fi < (int)g_impactAnalysis.relatedFiles.size(); fi++) {
                                if (shown >= 15) break;
                                auto& rf = g_impactAnalysis.relatedFiles[fi];
                                std::string rfUtf8;
                                {
                                    int wsz = WideCharToMultiByte(CP_UTF8, 0, rf.path.c_str(), -1, NULL, 0, NULL, NULL);
                                    rfUtf8.assign(wsz > 1 ? wsz - 1 : 0, 0);
                                    WideCharToMultiByte(CP_UTF8, 0, rf.path.c_str(), -1, &rfUtf8[0], wsz, NULL, NULL);
                                }
                                if (rfUtf8.size() > 70) rfUtf8 = rfUtf8.substr(0, 67) + "...";
                                DrawCheckItem(rfUtf8.c_str(), Vec4ToU32(CLR_TEXT_DIM),
                                    fi < (int)g_relatedFilesChecked.size() ? g_relatedFilesChecked[fi] : true, fi, g_relatedFilesChecked);
                                shown++;
                            }
                        }

                        DrawSectionCard("LEFTOVERS AFTER DELETION", (int)g_impactAnalysis.leftovers.size(),
                            IM_COL32(160, 150, 110, 255), !g_impactAnalysis.leftovers.empty(), &g_showLeftoverDetails);
                        if (g_showLeftoverDetails && !g_impactAnalysis.leftovers.empty()) {
                            for (int li = 0; li < (int)g_impactAnalysis.leftovers.size(); li++) {
                                auto& lr = g_impactAnalysis.leftovers[li];
                                if (curY >= innerY + innerH - 10) break;

                                std::string lrTypeUtf8, lrPathUtf8;
                                {
                                    int wsz = WideCharToMultiByte(CP_UTF8, 0, lr.typeName.c_str(), -1, NULL, 0, NULL, NULL);
                                    lrTypeUtf8.assign(wsz > 1 ? wsz - 1 : 0, 0);
                                    WideCharToMultiByte(CP_UTF8, 0, lr.typeName.c_str(), -1, &lrTypeUtf8[0], wsz, NULL, NULL);
                                }
                                {
                                    int wsz = WideCharToMultiByte(CP_UTF8, 0, lr.path.c_str(), -1, NULL, 0, NULL, NULL);
                                    lrPathUtf8.assign(wsz > 1 ? wsz - 1 : 0, 0);
                                    WideCharToMultiByte(CP_UTF8, 0, lr.path.c_str(), -1, &lrPathUtf8[0], wsz, NULL, NULL);
                                }

                                float itemH = 20.0f;
                                float cbSize = 12.0f;
                                float cbX = treeX + indent + 20;
                                float cbY = curY + (itemH - cbSize) / 2.0f;

                                // Checkbox box
                                bool checked = (li < (int)g_leftoverChecked.size()) ? g_leftoverChecked[li] : true;
                                ImU32 cbBg = checked ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG);
                                ImU32 cbBorder = Vec4ToU32(CLR_STROKE);
                                cdl->AddRectFilled(ImVec2(cbX, cbY), ImVec2(cbX + cbSize, cbY + cbSize), cbBg, 2.0f);
                                cdl->AddRect(ImVec2(cbX, cbY), ImVec2(cbX + cbSize, cbY + cbSize), cbBorder, 2.0f, 0, 1.0f);

                                // Checkmark
                                if (checked) {
                                    cdl->AddLine(ImVec2(cbX + 3, cbY + 6), ImVec2(cbX + 5, cbY + 8), Vec4ToU32(CLR_TEXT), 1.5f);
                                    cdl->AddLine(ImVec2(cbX + 5, cbY + 8), ImVec2(cbX + 9, cbY + 3), Vec4ToU32(CLR_TEXT), 1.5f);
                                }

                                // Click area for checkbox
                                ImVec2 cbClickMin(cbX - 2, cbY - 2);
                                ImVec2 cbClickMax(cbX + cbSize + 180, cbY + cbSize + 2);
                                if (io.MouseClicked[0] && ImGui::IsMouseHoveringRect(cbClickMin, cbClickMax)) {
                                    if (li < (int)g_leftoverChecked.size())
                                        g_leftoverChecked[li] = !g_leftoverChecked[li];
                                }

                                // Item text
                                std::string info = "[" + lrTypeUtf8 + "] " + lrPathUtf8;
                                if (info.size() > 70) info = info.substr(0, 67) + "...";
                                cdl->AddText(ImVec2(cbX + cbSize + 6, curY + (itemH - 14) / 2.0f),
                                    checked ? Vec4ToU32(CLR_TEXT_DIM) : Vec4ToU32(CLR_TEXT_DIM), info.c_str());

                                curY += itemH;
                            }

                            // Clean Leftovers button
                            int checkedCount = 0;
                            for (bool b : g_leftoverChecked) if (b) checkedCount++;
                            if (checkedCount > 0 && curY + 30 < innerY + innerH) {
                                curY += 6;
                                float clBtnW = 140.0f, clBtnH = 28.0f;
                                ImVec2 clMin(treeX + treeW - clBtnW - 4, curY);
                                ImVec2 clMax(treeX + treeW - 4, curY + clBtnH);
                                bool clHov = ImGui::IsMouseHoveringRect(clMin, clMax);
                                cdl->AddRectFilled(clMin, clMax, clHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                                cdl->AddRect(clMin, clMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);

                                char clLabel[64];
                                sprintf_s(clLabel, "Clean (%d)", checkedCount);
                                ImVec2 clT = ImGui::CalcTextSize(clLabel);
                                cdl->AddText(ImVec2((clMin.x + clMax.x - clT.x) / 2, (clMin.y + clMax.y - clT.y) / 2),
                                    Vec4ToU32(CLR_TEXT), clLabel);

                                if (io.MouseClicked[0] && clHov)
                                    g_showLeftoverCleanConfirm = true;

                                curY += clBtnH + 6;
                            }
                        }

                        // --- RISK SCORE GAUGE (circular arc) ---
                        curY += 8;
                        if (curY < innerY + innerH - 60) {
                            ImU32 riskCol;
                            const char* riskLabel;
                            switch (g_impactAnalysis.riskLevel) {
                                case BlackHole::RiskLevel::Critical: riskCol = IM_COL32(220, 40, 40, 255); riskLabel = "CRITICAL"; break;
                                case BlackHole::RiskLevel::High: riskCol = IM_COL32(220, 120, 40, 255); riskLabel = "HIGH"; break;
                                case BlackHole::RiskLevel::Medium: riskCol = IM_COL32(220, 200, 40, 255); riskLabel = "MEDIUM"; break;
                                case BlackHole::RiskLevel::Low: riskCol = IM_COL32(80, 200, 120, 255); riskLabel = "LOW"; break;
                                default: riskCol = IM_COL32(100, 100, 120, 255); riskLabel = "SAFE"; break;
                            }

                            float gaugeR = 32.0f;
                            float gaugeCenterX = treeX + 40;
                            float gaugeCenterY = curY + gaugeR + 8;

                            // Background arc (full circle, dim)
                            float arcStart = 0.75f * 3.14159f;
                            float arcEnd = 2.25f * 3.14159f;
                            int segments = 40;
                            ImU32 arcBg = Vec4ToU32(CLR_ELEM_BG);
                            for (int i = 0; i < segments; i++) {
                                float t1 = arcStart + (arcEnd - arcStart) * (i / (float)segments);
                                float t2 = arcStart + (arcEnd - arcStart) * ((i + 1) / (float)segments);
                                ImVec2 p1(gaugeCenterX + cosf(t1) * gaugeR, gaugeCenterY + sinf(t1) * gaugeR);
                                ImVec2 p2(gaugeCenterX + cosf(t2) * gaugeR, gaugeCenterY + sinf(t2) * gaugeR);
                                cdl->AddLine(p1, p2, arcBg, 6.0f);
                            }

                            // Filled arc
                            float fillAngle = arcStart + (arcEnd - arcStart) * (g_impactAnalysis.riskScore / 100.0f);
                            int fillSegments = (int)(segments * (g_impactAnalysis.riskScore / 100.0f));
                            for (int i = 0; i < fillSegments; i++) {
                                float t1 = arcStart + (arcEnd - arcStart) * (i / (float)segments);
                                float t2 = arcStart + (arcEnd - arcStart) * ((i + 1) / (float)segments);
                                ImVec2 p1(gaugeCenterX + cosf(t1) * gaugeR, gaugeCenterY + sinf(t1) * gaugeR);
                                ImVec2 p2(gaugeCenterX + cosf(t2) * gaugeR, gaugeCenterY + sinf(t2) * gaugeR);
                                cdl->AddLine(p1, p2, riskCol, 6.0f);
                            }

                            // Score text in center
                            char scoreBuf[16];
                            sprintf_s(scoreBuf, "%d", g_impactAnalysis.riskScore);
                            ImVec2 scoreSize = ImGui::CalcTextSize(scoreBuf);
                            cdl->AddText(ImVec2(gaugeCenterX - scoreSize.x / 2, gaugeCenterY - scoreSize.y / 2 - 4),
                                Vec4ToU32(CLR_TEXT), scoreBuf);

                            // Risk label + recommendation (to the right of gauge)
                            float textX = gaugeCenterX + gaugeR + 20;
                            cdl->AddText(ImVec2(textX, curY + 10), riskCol, riskLabel);
                            char maxBuf[16];
                            sprintf_s(maxBuf, "/ 100");
                            ImVec2 maxT = ImGui::CalcTextSize(maxBuf);
                                cdl->AddText(ImVec2(textX + ImGui::CalcTextSize(riskLabel).x + 6, curY + 10),
                                    Vec4ToU32(CLR_TEXT_DIM), maxBuf);

                            if (!g_impactAnalysis.recommendation.empty() && curY + 30 < innerY + innerH - 10) {
                                std::string recUtf8;
                                {
                                    int wsz = WideCharToMultiByte(CP_UTF8, 0, g_impactAnalysis.recommendation.c_str(), -1, NULL, 0, NULL, NULL);
                                    recUtf8.assign(wsz > 1 ? wsz - 1 : 0, 0);
                                    WideCharToMultiByte(CP_UTF8, 0, g_impactAnalysis.recommendation.c_str(), -1, &recUtf8[0], wsz, NULL, NULL);
                                }
                                if (recUtf8.size() > 80) recUtf8 = recUtf8.substr(0, 77) + "...";
                                cdl->AddText(ImVec2(textX, curY + 30), Vec4ToU32(CLR_TEXT_DIM), recUtf8.c_str());
                            }

                            curY += gaugeR * 2 + 20;
                        }
                    }

                    // === DELETE CONFIRMATION DIALOG ===
                    if (g_showDeleteConfirm) {
                        ImGui::OpenPopup("Confirm Delete##delconfirm");
                        ImVec2 confirmSize(420, 220);
                        ImVec2 confirmPos(g_mainWinPos.x + g_mainWinSize.x / 2 - confirmSize.x / 2,
                                          g_mainWinPos.y + g_mainWinSize.y / 2 - confirmSize.y / 2);
                        ImGui::SetNextWindowPos(confirmPos, ImGuiCond_Always);
                        ImGui::SetNextWindowSize(confirmSize, ImGuiCond_Always);

                        if (ImGui::BeginPopupModal("Confirm Delete##delconfirm", NULL,
                            ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar)) {

                            ImU32 confirmBg = Vec4ToU32(CLR_ELEM_BG);
                            ImVec2 cWPos = ImGui::GetWindowPos();
                            ImVec2 cWSize = ImGui::GetWindowSize();
                            cdl->AddRectFilled(cWPos, ImVec2(cWPos.x + cWSize.x, cWPos.y + cWSize.y), confirmBg, 8.0f);

                            // Warning icon
                            float warnY = cWPos.y + 24;
                            cdl->AddText(ImVec2(cWPos.x + cWSize.x / 2 - 8, warnY), Vec4ToU32(CLR_TEXT), "!");

                            const char* confirmTitle = "Are you sure you want to delete?";
                            ImVec2 ctSize = ImGui::CalcTextSize(confirmTitle);
                            cdl->AddText(ImVec2(cWPos.x + (cWSize.x - ctSize.x) / 2, warnY + 24),
                                Vec4ToU32(CLR_TEXT), confirmTitle);

                            // File name
                            std::string confirmFile;
                            {
                                int cfsz = WideCharToMultiByte(CP_UTF8, 0, g_impactAnalysis.fileName.c_str(), -1, NULL, 0, NULL, NULL);
                                confirmFile.assign(cfsz > 1 ? cfsz - 1 : 0, 0);
                                WideCharToMultiByte(CP_UTF8, 0, g_impactAnalysis.fileName.c_str(), -1, &confirmFile[0], cfsz, NULL, NULL);
                            }
                            if (confirmFile.size() > 50) confirmFile = confirmFile.substr(0, 47) + "...";
                            ImVec2 cfSize = ImGui::CalcTextSize(confirmFile.c_str());
                            cdl->AddText(ImVec2(cWPos.x + (cWSize.x - cfSize.x) / 2, warnY + 46),
                                Vec4ToU32(CLR_TEXT), confirmFile.c_str());

                            // Risk summary
                            ImU32 confirmRiskCol;
                            switch (g_impactAnalysis.riskLevel) {
                                case BlackHole::RiskLevel::Critical: confirmRiskCol = IM_COL32(220, 40, 40, 255); break;
                                case BlackHole::RiskLevel::High: confirmRiskCol = IM_COL32(220, 120, 40, 255); break;
                                case BlackHole::RiskLevel::Medium: confirmRiskCol = IM_COL32(220, 200, 40, 255); break;
                                case BlackHole::RiskLevel::Low: confirmRiskCol = IM_COL32(80, 200, 120, 255); break;
                                default: confirmRiskCol = IM_COL32(100, 100, 120, 255); break;
                            }
                            char confirmRisk[64];
                            sprintf_s(confirmRisk, "Risk Score: %d / 100", g_impactAnalysis.riskScore);
                            ImVec2 crSize = ImGui::CalcTextSize(confirmRisk);
                            cdl->AddText(ImVec2(cWPos.x + (cWSize.x - crSize.x) / 2, warnY + 68),
                                confirmRiskCol, confirmRisk);

                            // Buttons
                            float cBtnW = 130.0f, cBtnH = 34.0f;
                            float cBtnY = cWPos.y + cWSize.y - cBtnH - 18;

                            // Cancel button
                            ImVec2 cCancelMin(cWPos.x + cWSize.x / 2 - cBtnW - 6, cBtnY);
                            ImVec2 cCancelMax(cWPos.x + cWSize.x / 2 - 6, cBtnY + cBtnH);
                            bool cCancelHov = ImGui::IsMouseHoveringRect(cCancelMin, cCancelMax);
                            cdl->AddRectFilled(cCancelMin, cCancelMax, cCancelHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                            cdl->AddRect(cCancelMin, cCancelMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                            const char* cancelLabel = "Cancel";
                            ImVec2 cancelLS = ImGui::CalcTextSize(cancelLabel);
                            cdl->AddText(ImVec2((cCancelMin.x + cCancelMax.x - cancelLS.x) / 2, (cCancelMin.y + cCancelMax.y - cancelLS.y) / 2),
                                Vec4ToU32(CLR_TEXT), cancelLabel);

                            // Confirm delete button
                            ImVec2 cDelMin(cWPos.x + cWSize.x / 2 + 6, cBtnY);
                            ImVec2 cDelMax(cWPos.x + cWSize.x / 2 + cBtnW + 6, cBtnY + cBtnH);
                            bool cDelHov = ImGui::IsMouseHoveringRect(cDelMin, cDelMax);
                            cdl->AddRectFilled(cDelMin, cDelMax, cDelHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                            cdl->AddRect(cDelMin, cDelMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                            const char* delConfirmLabel = "Delete";
                            ImVec2 delConfirmLS = ImGui::CalcTextSize(delConfirmLabel);
                            cdl->AddText(ImVec2((cDelMin.x + cDelMax.x - delConfirmLS.x) / 2, (cDelMin.y + cDelMax.y - delConfirmLS.y) / 2),
                                Vec4ToU32(CLR_TEXT), delConfirmLabel);

                            if (io.MouseClicked[0]) {
                                if (cCancelHov) {
                                    g_showDeleteConfirm = false;
                                    ImGui::CloseCurrentPopup();
                                }
                                if (cDelHov) {
                                    g_showDeleteConfirm = false;
                                    ImGui::CloseCurrentPopup();
                                    std::thread(PerformDeletion, g_selectedFile, g_hMainWindow).detach();
                                }
                            }

                            ImGui::EndPopup();
                        }
                    }

                    // === BATCH DELETE CONFIRMATION DIALOG ===
                    if (g_showBatchConfirm) {
                        ImGui::OpenPopup("Batch Delete##batchconfirm");
                        ImVec2 confirmSize(440, 260);
                        ImVec2 confirmPos(g_mainWinPos.x + g_mainWinSize.x / 2 - confirmSize.x / 2,
                                          g_mainWinPos.y + g_mainWinSize.y / 2 - confirmSize.y / 2);
                        ImGui::SetNextWindowPos(confirmPos, ImGuiCond_Always);
                        ImGui::SetNextWindowSize(confirmSize, ImGuiCond_Always);

                        if (ImGui::BeginPopupModal("Batch Delete##batchconfirm", NULL,
                            ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar)) {

                            ImU32 confirmBg = Vec4ToU32(CLR_ELEM_BG);
                            ImVec2 cWPos = ImGui::GetWindowPos();
                            ImVec2 cWSize = ImGui::GetWindowSize();
                            cdl->AddRectFilled(cWPos, ImVec2(cWPos.x + cWSize.x, cWPos.y + cWSize.y), confirmBg, 8.0f);

                            const char* confirmTitle = "Batch Delete";
                            ImVec2 ctSize = ImGui::CalcTextSize(confirmTitle);
                            cdl->AddText(ImVec2(cWPos.x + (cWSize.x - ctSize.x) / 2, cWPos.y + 24),
                                Vec4ToU32(CLR_TEXT), confirmTitle);

                            char countStr[128];
                            sprintf_s(countStr, "%d files selected for deletion", (int)g_batchFiles.size());
                            ImVec2 countSize = ImGui::CalcTextSize(countStr);
                            cdl->AddText(ImVec2(cWPos.x + (cWSize.x - countSize.x) / 2, cWPos.y + 52),
                                Vec4ToU32(CLR_TEXT), countStr);

                            // Show first few file names
                            float listY = cWPos.y + 80;
                            int showCount = min((int)g_batchFiles.size(), 5);
                            for (int i = 0; i < showCount; i++) {
                                std::string fname = WideToUtf8(g_batchFiles[i]);
                                if (fname.size() > 55) fname = fname.substr(0, 52) + "...";
                                ImVec2 fsz = ImGui::CalcTextSize(fname.c_str());
                                cdl->AddText(ImVec2(cWPos.x + (cWSize.x - fsz.x) / 2, listY + i * 18),
                                    Vec4ToU32(CLR_TEXT_DIM), fname.c_str());
                            }
                            if ((int)g_batchFiles.size() > 5) {
                                char moreStr[64];
                                sprintf_s(moreStr, "...and %d more", (int)g_batchFiles.size() - 5);
                                ImVec2 moreSz = ImGui::CalcTextSize(moreStr);
                                cdl->AddText(ImVec2(cWPos.x + (cWSize.x - moreSz.x) / 2, listY + showCount * 18),
                                    Vec4ToU32(CLR_TEXT_DIM), moreStr);
                            }

                            // Buttons
                            float cBtnW = 130.0f, cBtnH = 34.0f;
                            float cBtnY = cWPos.y + cWSize.y - cBtnH - 18;

                            ImVec2 cCancelMin(cWPos.x + cWSize.x / 2 - cBtnW - 6, cBtnY);
                            ImVec2 cCancelMax(cWPos.x + cWSize.x / 2 - 6, cBtnY + cBtnH);
                            bool cCancelHov = ImGui::IsMouseHoveringRect(cCancelMin, cCancelMax);
                            cdl->AddRectFilled(cCancelMin, cCancelMax, cCancelHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                            cdl->AddRect(cCancelMin, cCancelMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                            const char* cancelLabel = "Cancel";
                            ImVec2 cancelLS = ImGui::CalcTextSize(cancelLabel);
                            cdl->AddText(ImVec2((cCancelMin.x + cCancelMax.x - cancelLS.x) / 2, (cCancelMin.y + cCancelMax.y - cancelLS.y) / 2),
                                Vec4ToU32(CLR_TEXT), cancelLabel);

                            ImVec2 cDelMin(cWPos.x + cWSize.x / 2 + 6, cBtnY);
                            ImVec2 cDelMax(cWPos.x + cWSize.x / 2 + cBtnW + 6, cBtnY + cBtnH);
                            bool cDelHov = ImGui::IsMouseHoveringRect(cDelMin, cDelMax);
                            cdl->AddRectFilled(cDelMin, cDelMax, cDelHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                            cdl->AddRect(cDelMin, cDelMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                            const char* delConfirmLabel = "Delete All";
                            ImVec2 delConfirmLS = ImGui::CalcTextSize(delConfirmLabel);
                            cdl->AddText(ImVec2((cDelMin.x + cDelMax.x - delConfirmLS.x) / 2, (cDelMin.y + cDelMax.y - delConfirmLS.y) / 2),
                                Vec4ToU32(CLR_TEXT), delConfirmLabel);

                            if (io.MouseClicked[0]) {
                                if (cCancelHov) {
                                    g_showBatchConfirm = false;
                                    g_batchFiles.clear();
                                    ImGui::CloseCurrentPopup();
                                }
                                if (cDelHov) {
                                    g_showBatchConfirm = false;
                                    ImGui::CloseCurrentPopup();
                                    for (auto& f : g_batchFiles) {
                                        std::thread(PerformDeletion, f, g_hMainWindow).detach();
                                    }
                                    g_batchFiles.clear();
                                }
                            }

                            ImGui::EndPopup();
                        }
                    }

                    if (g_showDeleteSelectedConfirm) {
                        int selCount = 0;
                        for (auto s : g_rowSelected) if (s) selCount++;
                        if (selCount > 0) {
                            ImGui::OpenPopup("Confirm Batch Delete##batchdel");
                            ImVec2 bSize(420, 180);
                            ImVec2 bPos(g_mainWinPos.x + g_mainWinSize.x / 2 - bSize.x / 2,
                                        g_mainWinPos.y + g_mainWinSize.y / 2 - bSize.y / 2);
                            ImGui::SetNextWindowPos(bPos, ImGuiCond_Always);
                            ImGui::SetNextWindowSize(bSize, ImGuiCond_Always);
                            if (ImGui::BeginPopupModal("Confirm Batch Delete##batchdel", NULL,
                                ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar)) {
                                ImVec2 wP = ImGui::GetWindowPos();
                                ImVec2 wS = ImGui::GetWindowSize();
                                cdl->AddRectFilled(wP, ImVec2(wP.x + wS.x, wP.y + wS.y), Vec4ToU32(CLR_ELEM_BG), 8.0f);
                                char bMsg[128];
                                snprintf(bMsg, sizeof(bMsg), "Schedule uninstall for %d selected programs?", selCount);
                                ImVec2 bMsgSz = ImGui::CalcTextSize(bMsg);
                                cdl->AddText(ImVec2(wP.x + (wS.x - bMsgSz.x) / 2, wP.y + 30),
                                    Vec4ToU32(CLR_TEXT), bMsg);
                                cdl->AddText(ImVec2(wP.x + (wS.x - ImGui::CalcTextSize("Requires restart to take effect").x) / 2, wP.y + 54),
                                    Vec4ToU32(CLR_TEXT_DIM), "Requires restart to take effect");
                                float bBtnW = 100.0f, bBtnH = 28.0f;
                                float bBtnY = wP.y + wS.y - bBtnH - 16.0f;
                                ImVec2 bCancelMin(wP.x + wS.x / 2 - bBtnW - 6, bBtnY);
                                ImVec2 bCancelMax(wP.x + wS.x / 2 - 6, bBtnY + bBtnH);
                                ImVec2 bOkMin(wP.x + wS.x / 2 + 6, bBtnY);
                                ImVec2 bOkMax(wP.x + wS.x / 2 + bBtnW + 6, bBtnY + bBtnH);
                                bool bCancelHov = io.MousePos.x >= bCancelMin.x && io.MousePos.x <= bCancelMax.x &&
                                                  io.MousePos.y >= bCancelMin.y && io.MousePos.y <= bCancelMax.y;
                                bool bOkHov = io.MousePos.x >= bOkMin.x && io.MousePos.x <= bOkMax.x &&
                                              io.MousePos.y >= bOkMin.y && io.MousePos.y <= bOkMax.y;
                                cdl->AddRectFilled(bCancelMin, bCancelMax, bCancelHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 4.0f);
                                cdl->AddRect(bCancelMin, bCancelMax, Vec4ToU32(CLR_STROKE), 4.0f, 0, 1.0f);
                                ImVec2 bCancelTxt = ImVec2(bCancelMin.x + (bBtnW - ImGui::CalcTextSize("Cancel").x) / 2, bCancelMin.y + 6);
                                cdl->AddText(bCancelTxt, Vec4ToU32(CLR_TEXT), "Cancel");
                                cdl->AddRectFilled(bOkMin, bOkMax, bOkHov ? IM_COL32(180, 50, 50, 255) : IM_COL32(140, 40, 40, 255), 4.0f);
                                cdl->AddRect(bOkMin, bOkMax, IM_COL32(200, 60, 60, 180), 4.0f, 0, 1.0f);
                                ImVec2 bOkTxt = ImVec2(bOkMin.x + (bBtnW - ImGui::CalcTextSize("Delete All").x) / 2, bOkMin.y + 6);
                                cdl->AddText(bOkTxt, IM_COL32(255, 220, 220, 255), "Delete All");
                                if (bCancelHov && io.MouseClicked[0]) {
                                    g_showDeleteSelectedConfirm = false;
                                    ImGui::CloseCurrentPopup();
                                }
                                if (bOkHov && io.MouseClicked[0]) {
                                    g_showDeleteSelectedConfirm = false;
                                    ImGui::CloseCurrentPopup();
                                    for (int si = 0; si < (int)g_rowSelected.size(); si++) {
                                        if (g_rowSelected[si] && si < (int)g_filteredIndicesCache.size()) {
                                            int entryIdx = g_filteredIndicesCache[si];
                                            auto& se = g_uninstallEntries[entryIdx];
                                            std::wstring uninstallCmd = se.uninstallString;
                                            if (!uninstallCmd.empty()) {
                                                STARTUPINFOW si2 = {};
                                                si2.cb = sizeof(si2);
                                                PROCESS_INFORMATION pi = {};
                                                CreateProcessW(NULL, (LPWSTR)uninstallCmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si2, &pi);
                                                if (pi.hProcess) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
                                            }
                                        }
                                    }
                                    g_rowSelected.assign(g_rowSelected.size(), false);
                                }
                                ImGui::EndPopup();
                            }
                        } else {
                            g_showDeleteSelectedConfirm = false;
                        }
                    }

                    // === LEFTOVER CLEAN CONFIRMATION DIALOG ===
                    if (g_showLeftoverCleanConfirm) {
                        ImGui::OpenPopup("Confirm Clean##leftoverclean");
                        ImVec2 clConfirmSize(400, 180);
                        ImVec2 clConfirmPos(g_mainWinPos.x + g_mainWinSize.x / 2 - clConfirmSize.x / 2,
                                            g_mainWinPos.y + g_mainWinSize.y / 2 - clConfirmSize.y / 2);
                        ImGui::SetNextWindowPos(clConfirmPos, ImGuiCond_Always);
                        ImGui::SetNextWindowSize(clConfirmSize, ImGuiCond_Always);

                        if (ImGui::BeginPopupModal("Confirm Clean##leftoverclean", NULL,
                            ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar)) {

                            ImVec2 cWPos = ImGui::GetWindowPos();
                            ImVec2 cWSize = ImGui::GetWindowSize();
                            cdl->AddRectFilled(cWPos, ImVec2(cWPos.x + cWSize.x, cWPos.y + cWSize.y), Vec4ToU32(CLR_ELEM_BG), 8.0f);

                            int clCheckedCount = 0;
                            for (bool b : g_leftoverChecked) if (b) clCheckedCount++;

                            float warnY = cWPos.y + 24;
                            cdl->AddText(ImVec2(cWPos.x + cWSize.x / 2 - 6, warnY), Vec4ToU32(CLR_TEXT), "!");

                            const char* clTitle = "Clean selected leftovers?";
                            ImVec2 cltSize = ImGui::CalcTextSize(clTitle);
                            cdl->AddText(ImVec2(cWPos.x + (cWSize.x - cltSize.x) / 2, warnY + 24),
                                Vec4ToU32(CLR_TEXT), clTitle);

                            char clDetail[128];
                            sprintf_s(clDetail, "%d items will be removed", clCheckedCount);
                            ImVec2 cldSize = ImGui::CalcTextSize(clDetail);
                            cdl->AddText(ImVec2(cWPos.x + (cWSize.x - cldSize.x) / 2, warnY + 48),
                                Vec4ToU32(CLR_TEXT_DIM), clDetail);

                            float cBtnW = 130.0f, cBtnH = 34.0f;
                            float cBtnY = cWPos.y + cWSize.y - cBtnH - 18;

                            ImVec2 cCancelMin(cWPos.x + cWSize.x / 2 - cBtnW - 6, cBtnY);
                            ImVec2 cCancelMax(cWPos.x + cWSize.x / 2 - 6, cBtnY + cBtnH);
                            bool cCancelHov = ImGui::IsMouseHoveringRect(cCancelMin, cCancelMax);
                            cdl->AddRectFilled(cCancelMin, cCancelMax, cCancelHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                            cdl->AddRect(cCancelMin, cCancelMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                            ImVec2 cancelLS = ImGui::CalcTextSize("Cancel");
                            cdl->AddText(ImVec2((cCancelMin.x + cCancelMax.x - cancelLS.x) / 2, (cCancelMin.y + cCancelMax.y - cancelLS.y) / 2),
                                Vec4ToU32(CLR_TEXT), "Cancel");

                            ImVec2 cCleanMin(cWPos.x + cWSize.x / 2 + 6, cBtnY);
                            ImVec2 cCleanMax(cWPos.x + cWSize.x / 2 + cBtnW + 6, cBtnY + cBtnH);
                            bool cCleanHov = ImGui::IsMouseHoveringRect(cCleanMin, cCleanMax);
                            cdl->AddRectFilled(cCleanMin, cCleanMax, cCleanHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                            cdl->AddRect(cCleanMin, cCleanMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                            ImVec2 cleanLS = ImGui::CalcTextSize("Clean");
                            cdl->AddText(ImVec2((cCleanMin.x + cCleanMax.x - cleanLS.x) / 2, (cCleanMin.y + cCleanMax.y - cleanLS.y) / 2),
                                Vec4ToU32(CLR_TEXT), "Clean");

                            if (io.MouseClicked[0]) {
                                if (cCancelHov) {
                                    g_showLeftoverCleanConfirm = false;
                                    ImGui::CloseCurrentPopup();
                                }
                                if (cCleanHov) {
                                    g_showLeftoverCleanConfirm = false;
                                    ImGui::CloseCurrentPopup();
                                    std::vector<BlackHole::LeftoverRef> selectedItems;
                                    for (int i = 0; i < (int)g_impactAnalysis.leftovers.size(); i++) {
                                        if (i < (int)g_leftoverChecked.size() && g_leftoverChecked[i])
                                            selectedItems.push_back(g_impactAnalysis.leftovers[i]);
                                    }
                                    std::vector<bool> allChecked(selectedItems.size(), true);
                                    std::thread(PerformLeftoverClean, selectedItems, allChecked, g_hMainWindow).detach();
                                }
                            }

                            ImGui::EndPopup();
                        }
                    }
                    }
                } else if (g_selectedTab == 0) {
                    ProcessPendingIcons();
                    ProcessPendingCachedPixels();

                    static float uninstallRefreshTimer = 0.0f;
                    uninstallRefreshTimer += dt;
                    if (!g_initialScanStarted && g_uninstallEntries.empty()) {
                        g_initialScanStarted = true;
                        g_scanComplete.store(false);
                        g_scanPhase2Started.store(false);
                        g_scanPhase2Complete.store(false);
                        LaunchBigStackThread([]() {
                            DebugLog("SCAN: Phase 1 start - ScanInstalled");
                            BlackHole::Uninstaller u;
                            auto entries = u.ScanInstalled();
                            DebugLog("SCAN: Phase 1 done");
                            {
                                std::lock_guard<std::mutex> lock(g_scanResultMutex);
                                g_scanResultPending = entries;
                            }
                            g_scanComplete.store(true);
                            DebugLog("SCAN: Phase 2 start - orphans + enrich");
                            g_scanPhase2Started.store(true);
                            auto orphans = u.ScanDirectoryOrphans();
                            entries.insert(entries.end(), orphans.begin(), orphans.end());
                            u.EnrichEntriesBackground(entries);
                            {
                                std::lock_guard<std::mutex> lock(g_scanResultMutex);
                                g_scanResultPending = std::move(entries);
                            }
                            g_scanPhase2Complete.store(true);
                            DebugLog("SCAN: Phase 2 done");
                            g_initialScanStarted2 = true;
                            g_scanComplete2.store(false);
                            auto extras = u.ScanExtras();
                            {
                                std::lock_guard<std::mutex> lock(g_extrasMutex);
                                g_extrasPending = std::move(extras);
                            }
                            g_scanComplete2.store(true);
                            DebugLog("SCAN: Extras done");
                        });
                    }
                    if (g_scanComplete.load() && g_initialScanStarted) {
                        g_initialScanStarted = false;
                        {
                            std::lock_guard<std::mutex> lock(g_scanResultMutex);
                            g_uninstallEntries = std::move(g_scanResultPending);
                        }
                        g_selectedUninstallIdx = -1;
                        g_rowSelected.assign(g_uninstallEntries.size(), false);
                        g_iconThreadGeneration.store(0);
                        g_iconThreadRunning.store(false);
                        g_iconThreadDone.store(false);
                        g_filteredIndicesDirty = true;
                    }

                    static bool diskCachePreloaded = false;
                    if (g_scanPhase2Complete.load() && g_scanPhase2Started.load()) {
                        g_scanPhase2Complete.store(false);
                        g_scanPhase2Started.store(false);
                        {
                            std::lock_guard<std::mutex> lock(g_scanResultMutex);
                            g_uninstallEntries = std::move(g_scanResultPending);
                        }
                        g_rowSelected.assign(g_uninstallEntries.size(), false);
                        g_filteredIndicesDirty = true;
                        diskCachePreloaded = false;
                    }
                    if (g_scanComplete2.load() && g_initialScanStarted2) {
                        g_initialScanStarted2 = false;
                        {
                            std::lock_guard<std::mutex> lock(g_extrasMutex);
                            for (auto& ex : g_extrasPending) {
                                bool found = false;
                                for (auto& existing : g_uninstallEntries) {
                                    if (existing.displayNameLower == ex.displayNameLower) {
                                        found = true; break;
                                    }
                                }
                                if (!found) g_uninstallEntries.push_back(std::move(ex));
                            }
                            g_extrasPending.clear();
                        }
                        g_filteredIndicesDirty = true;
                    }

                    if (g_batchLeftoverComplete.load()) {
                        g_batchLeftoverComplete.store(false);
                        std::lock_guard<std::mutex> lock(g_batchLeftoverMutex);
                        g_leftoverItems = g_batchLeftoverItems;
                        g_leftoverSnapshot = g_batchLeftoverItems;
                        g_batchPurgeNames = g_batchLeftoverProgramNames;
                        g_leftoverSearchFilter[0] = '\0';
                        if (!g_leftoverItems.empty()) {
                            g_showLeftoverPopup.store(true);
                        }
                    }

                    if (!diskCachePreloaded && !g_uninstallEntries.empty() && g_pd3dDevice) {
                        CreateDefaultIcon();
                        ImGuiIO& io2 = ImGui::GetIO();
                        float scale = (io2.DisplayFramebufferScale.x > 0) ? io2.DisplayFramebufferScale.x : 1.0f;
                        int logoPixW = (int)((60.0f - 16.0f) * scale);
                        int logoPixH = (int)((60.0f - 16.0f) * scale);
                        CreateSidebarLogo(logoPixW, logoPixH);
                        for (auto& e : g_uninstallEntries) {
                            std::vector<BYTE> cachedPixels;
                            if (LoadIconFromDiskCache(e.displayName, cachedPixels)) {
                                {
                                    std::lock_guard<std::mutex> lock(g_iconMutex);
                                    if (g_iconCache.count(e.displayName)) continue;
                                }
                                {
                                    std::lock_guard<std::mutex> lock(g_pendingCachedIconMutex);
                                    g_pendingCachedIcons.push_back({e.displayName, std::move(cachedPixels)});
                                }
                            }
                        }
                        for (int i = 0; i < 100; i++) {
                            ProcessPendingCachedPixels();
                            if (g_pendingCachedIcons.empty()) break;
                        }
                        DWORD startTime = GetTickCount();
                        for (auto& e : g_uninstallEntries) {
                            {
                                std::lock_guard<std::mutex> lock(g_iconMutex);
                                if (g_iconCache.count(e.displayName)) continue;
                            }
                            HICON hIcon = BlackHole::ExtractAppIcon(e);
                            if (hIcon) {
                                SaveIconToDiskCache(e.displayName, hIcon);
                                {
                                    std::lock_guard<std::mutex> lock(g_pendingIconMutex);
                                    g_pendingIcons.push_back({e.displayName, hIcon});
                                }
                            }
                        }
                        ProcessPendingIcons();
                        diskCachePreloaded = true;
                    }

                    if (g_iconThreadDone.load() == false && g_iconThreadRunning.load() == false && !g_uninstallEntries.empty() && g_pd3dDevice) {
                        CreateDefaultIcon();
                        int gen = g_iconThreadGeneration.load();
                        g_iconThreadGeneration.store(gen + 1);
                        g_iconThreadRunning.store(true);
                        g_sizeCalcDone.store(false);
                        std::thread(LoadIconsBackground, g_uninstallEntries).detach();
                    }

                    cdl->AddRectFilled(ImVec2(cPos.x + pad, innerY),
                        ImVec2(cPos.x + cSize.x - pad, innerY + innerH),
                        Vec4ToU32(CLR_CHILD_BG), 4.0f);

                    {
                        float rowY = innerY + 2.0f;
                        float rowH = 18.0f;
                        float pad = 12.0f;
                        float refreshW = 60.0f;
                        float columnsW = 70.0f;
                        float filtersW = 60.0f;
                        float searchW = 200.0f;

                        float rightBlockW = filtersW + 4.0f + columnsW + 4.0f + refreshW;
                        float searchX = cPos.x + (cSize.x - searchW) / 2.0f;
                        float rightX = cPos.x + cSize.x - pad - refreshW;
                        float columnsX = rightX - columnsW - 4.0f;
                        float filtersX = columnsX - filtersW - 4.0f;

                        struct LegendItem { ImVec4 color; const char* label; const char* letter; };
                        LegendItem legendItems[] = {
                            { ImVec4(0.20f, 0.90f, 0.40f, 1.0f), "Verified", "V" },
                            { ImVec4(1.00f, 0.65f, 0.10f, 1.0f), "Unverified", "U" },
                            { ImVec4(0.95f, 0.20f, 0.25f, 1.0f), "Orphaned", "O" },
                            { ImVec4(0.25f, 0.55f, 1.00f, 1.0f), "Store App", "S" },
                            { ImVec4(0.75f, 0.40f, 1.00f, 1.0f), "Update", "P" },
                            { ImVec4(0.50f, 0.50f, 0.55f, 1.0f), "Invalid", "I" },
                        };
                        cdl->AddText(ImVec2(cPos.x + pad, rowY + 1.0f),
                            Vec4ToU32(ImVec4(0.56f, 0.56f, 0.60f, 1.0f)),
                            std::to_string((int)g_filteredIndicesCache.size()).c_str());

                        float numW = ImGui::CalcTextSize(std::to_string((int)g_filteredIndicesCache.size()).c_str()).x;
                        float lx = cPos.x + pad + numW + 8.0f;
                        float legendY = innerY + 3.0f;
                        float pillW = 24.0f;
                        float pillH = 12.0f;
                        for (int li = 0; li < 6; li++) {
                            auto& item = legendItems[li];
                            bool isActive = (g_colorFilter == li);
                            ImVec2 pillMin(lx, legendY);
                            ImVec2 pillMax(lx + pillW, legendY + pillH);
                            bool hov = io.MousePos.x >= pillMin.x && io.MousePos.x <= pillMax.x &&
                                       io.MousePos.y >= pillMin.y && io.MousePos.y <= pillMax.y;

                            ImU32 colColor = Vec4ToU32(item.color);

                            if (isActive) {
                                cdl->AddRectFilled(pillMin, pillMax, colColor, 6.0f);
                            } else {
                                ImU32 darkHalf = g_darkMode ? IM_COL32(18, 18, 24, 255) : IM_COL32(220, 220, 225, 255);
                                cdl->AddRectFilled(pillMin, pillMax, darkHalf, 6.0f);
                                ImVec2 clipMin(lx, legendY);
                                ImVec2 clipMax(lx + pillW * 0.45f, legendY + pillH);
                                cdl->PushClipRect(clipMin, clipMax, true);
                                cdl->AddRectFilled(pillMin, pillMax, colColor, 6.0f);
                                cdl->PopClipRect();
                            }

                            ImU32 borderColor = isActive ? colColor : (g_darkMode ? IM_COL32(50, 50, 60, 180) : IM_COL32(180, 180, 190, 180));
                            cdl->AddRect(pillMin, pillMax, borderColor, 6.0f, 0, isActive ? 1.5f : 1.0f);

                            const char* letter = item.letter;
                            ImVec2 letterSz = g_fontPill->CalcTextSizeA(g_fontPill->LegacySize, FLT_MAX, 0.0f, letter);
                            float fsz = g_fontPill->LegacySize;
                            float textX = lx + (pillW - letterSz.x) * 0.5f;
                            float textY = legendY + (pillH - fsz) * 0.5f;

                            if (isActive) {
                                ImU32 glowOuter = Vec4ToU32(ImVec4(item.color.x, item.color.y, item.color.z, 0.3f));
                                ImU32 glowMid = Vec4ToU32(ImVec4(item.color.x, item.color.y, item.color.z, 0.6f));
                                cdl->AddText(g_fontPill, fsz, ImVec2(textX - 3.0f, textY), glowOuter, letter, NULL, 0.0f, NULL);
                                cdl->AddText(g_fontPill, fsz, ImVec2(textX + 3.0f, textY), glowOuter, letter, NULL, 0.0f, NULL);
                                cdl->AddText(g_fontPill, fsz, ImVec2(textX, textY - 3.0f), glowOuter, letter, NULL, 0.0f, NULL);
                                cdl->AddText(g_fontPill, fsz, ImVec2(textX, textY + 3.0f), glowOuter, letter, NULL, 0.0f, NULL);
                                cdl->AddText(g_fontPill, fsz, ImVec2(textX - 2.0f, textY - 2.0f), glowMid, letter, NULL, 0.0f, NULL);
                                cdl->AddText(g_fontPill, fsz, ImVec2(textX + 2.0f, textY - 2.0f), glowMid, letter, NULL, 0.0f, NULL);
                                cdl->AddText(g_fontPill, fsz, ImVec2(textX - 2.0f, textY + 2.0f), glowMid, letter, NULL, 0.0f, NULL);
                                cdl->AddText(g_fontPill, fsz, ImVec2(textX + 2.0f, textY + 2.0f), glowMid, letter, NULL, 0.0f, NULL);
                            }
                            cdl->AddText(g_fontPill, fsz, ImVec2(textX, textY), IM_COL32(255, 255, 255, 255), letter, NULL, 0.0f, NULL);

                            if (hov && io.MouseClicked[0]) {
                                g_colorFilter = (g_colorFilter == li) ? -1 : li;
                                g_filteredIndicesDirty = true;
                            }
                            if (hov) {
                                ImDrawList* fg = ImGui::GetForegroundDrawList();
                                ImVec2 ttTextSz = ImGui::CalcTextSize(item.label);
                                ImVec2 ttPos(lx + pillW / 2.0f - ttTextSz.x / 2.0f, pillMin.y - 8.0f - ttTextSz.y - 4.0f);
                                ImVec2 ttMin(ttPos.x - 6.0f, ttPos.y - 3.0f);
                                ImVec2 ttMax(ttPos.x + ttTextSz.x + 6.0f, ttPos.y + ttTextSz.y + 3.0f);
                                if (ttMin.y < 4.0f) {
                                    ttPos.y = pillMax.y + 6.0f;
                                    ttMin = ImVec2(ttPos.x - 6.0f, ttPos.y - 3.0f);
                                    ttMax = ImVec2(ttPos.x + ttTextSz.x + 6.0f, ttPos.y + ttTextSz.y + 3.0f);
                                }
                                fg->AddRectFilled(ttMin, ttMax, Vec4ToU32(CLR_POPUP_BG), 5.0f);
                                fg->AddRect(ttMin, ttMax, colColor, 5.0f, 0, 1.0f);
                                fg->AddText(ttPos, Vec4ToU32(CLR_TEXT), item.label);
                            }
                            lx += pillW + 6.0f;
                        }

                        ImVec2 searchMin(searchX, rowY);
                        ImVec2 searchMax(searchX + searchW, rowY + rowH);
                    ImU32 searchBorder = g_uninstallFilterFocused ?
                        Vec4ToU32(CLR_ACCENT) : Vec4ToU32(CLR_STROKE);
                        cdl->AddRectFilled(searchMin, searchMax, Vec4ToU32(CLR_ELEM_BG), 3.0f);
                        cdl->AddRect(searchMin, searchMax, searchBorder, 3.0f, 0, g_uninstallFilterFocused ? 1.5f : 1.0f);

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            g_uninstallFilterFocused = (m.x >= searchMin.x && m.x <= searchMax.x &&
                                                        m.y >= searchMin.y && m.y <= searchMax.y);
                        }
                        if (g_uninstallFilterFocused) {
                            for (int c = 0; c < io.InputQueueCharacters.Size; c++) {
                                wchar_t ch = (wchar_t)io.InputQueueCharacters[c];
                                if (ch == 8) {
                                    if (!g_uninstallFilter.empty()) g_uninstallFilter.pop_back();
                                } else if (ch >= 32 && ch < 127) {
                                    g_uninstallFilter += (char)ch;
                                }
                            }
                        }
                        if (g_uninstallFilter.empty() && !g_uninstallFilterFocused) {
                            ImVec2 phSz = ImGui::CalcTextSize("Search programs...");
                            cdl->AddText(ImVec2(searchMin.x + searchW / 2.0f - phSz.x / 2.0f, searchMin.y + 2),
                                Vec4ToU32(CLR_TEXT_DIM), "Search programs...");
                        } else if (g_uninstallFilter.empty() && g_uninstallFilterFocused) {
                            ImVec2 phSz = ImGui::CalcTextSize("Search programs...");
                            cdl->AddText(ImVec2(searchMin.x + searchW / 2.0f - phSz.x / 2.0f, searchMin.y + 2),
                                Vec4ToU32(ImVec4(0.55f, 0.55f, 0.60f, 1.0f)), "Search programs...");
                        } else {
                            ImVec2 txtSz = ImGui::CalcTextSize(g_uninstallFilter.c_str());
                            float tx = searchMin.x + 6.0f;
                            if (tx + txtSz.x > searchMax.x - 6.0f)
                                tx = searchMax.x - 6.0f - txtSz.x;
                            cdl->AddText(ImVec2(tx, searchMin.y + 1),
                                Vec4ToU32(CLR_TEXT), g_uninstallFilter.c_str());
                        }
                        if (g_uninstallFilterFocused) {
                            ImVec2 txtSz = ImGui::CalcTextSize(g_uninstallFilter.c_str());
                            float cx = searchMin.x + 6.0f + txtSz.x;
                            if (cx > searchMax.x - 4.0f) cx = searchMax.x - 4.0f;
                            if (fmodf((float)ImGui::GetTime(), 1.0f) < 0.5f)
                                cdl->AddLine(ImVec2(cx, searchMin.y + 3),
                                    ImVec2(cx, searchMin.y + rowH - 3),
                                    Vec4ToU32(CLR_TEXT), 1.0f);
                        }

                        {
                            float btnPillR = 7.0f;
                            float btnPillH = 16.0f;
                            float btnY = legendY - 2.0f;
                            ImVec2 colBtnMin(columnsX, btnY);
                            ImVec2 colBtnMax(columnsX + columnsW, btnY + btnPillH);
                            bool colBtnHov = io.MousePos.x >= colBtnMin.x && io.MousePos.x <= colBtnMax.x &&
                                             io.MousePos.y >= colBtnMin.y && io.MousePos.y <= colBtnMax.y;
                            ImU32 colBtnBg = colBtnHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG);
                            cdl->AddRectFilled(colBtnMin, colBtnMax, colBtnBg, btnPillR);
                            ImU32 colBtnBorder = colBtnHov ? IM_COL32(142, 132, 255, 220) : IM_COL32(142, 132, 255, 120);
                            cdl->AddRect(colBtnMin, colBtnMax, colBtnBorder, btnPillR, 0, colBtnHov ? 1.5f : 1.0f);
                            ImVec2 colTxt = ImGui::CalcTextSize("Columns");
                            cdl->AddText(ImVec2(colBtnMin.x + (columnsW - colTxt.x) / 2, colBtnMin.y + 2),
                                Vec4ToU32(CLR_TEXT), "Columns");
                            if (colBtnHov && io.MouseClicked[0]) {
                                g_showColumnChooser = !g_showColumnChooser;
                            }
                        }

                        // Filters button
                        {
                            bool anyFilterOff = !g_filterShowMicrosoft || !g_filterShowPortable ||
                                                !g_filterShowStore || !g_filterShowSystem ||
                                                !g_filterShowUpdates || !g_filterShowProtected ||
                                                !g_filterShowOrphans || !g_filterShowChocolatey ||
                                                !g_filterShowScoop || !g_filterShowTweaks ||
                                                !g_filterShowUnregistered;
                            float btnPillR = 7.0f;
                            float btnPillH = 16.0f;
                            float btnY = legendY - 2.0f;
                            ImVec2 fBtnMin(filtersX, btnY);
                            ImVec2 fBtnMax(filtersX + filtersW, btnY + btnPillH);
                            bool fBtnHov = io.MousePos.x >= fBtnMin.x && io.MousePos.x <= fBtnMax.x &&
                                           io.MousePos.y >= fBtnMin.y && io.MousePos.y <= fBtnMax.y;
                            ImU32 fBtnBg = fBtnHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG);
                            cdl->AddRectFilled(fBtnMin, fBtnMax, fBtnBg, btnPillR);
                            ImU32 fBtnBorder = anyFilterOff
                                ? (fBtnHov ? IM_COL32(220, 180, 80, 240) : IM_COL32(220, 180, 80, 160))
                                : (fBtnHov ? IM_COL32(220, 180, 80, 220) : IM_COL32(220, 180, 80, 100));
                            cdl->AddRect(fBtnMin, fBtnMax, fBtnBorder, btnPillR, 0, fBtnHov ? 1.5f : 1.0f);
                            ImVec2 fTxt = ImGui::CalcTextSize("Filters");
                            cdl->AddText(ImVec2(fBtnMin.x + (filtersW - fTxt.x) / 2, fBtnMin.y + 2),
                                Vec4ToU32(CLR_TEXT), "Filters");
                            if (fBtnHov && io.MouseClicked[0]) {
                                g_showFilterChooser = !g_showFilterChooser;
                            }
                        }

                        if (g_showColumnChooser) {
                            ImVec2 popPos(columnsX, legendY - 2.0f + 16.0f + 4.0f);
                            ImGui::SetNextWindowPos(popPos);
                            ImGui::SetNextWindowSize(ImVec2(160, 0));
                            bool colChooserOpen = g_showColumnChooser.load();
                            ImGui::Begin("##colChooser", &colChooserOpen,
                                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                                ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                                ImGuiWindowFlags_AlwaysAutoResize);
                            ImGui::TextDisabled("Columns");
                            ImGui::Separator();
                            for (int ci = 0; ci < 11; ci++) {
                                if (ImGui::Checkbox(g_colNames[ci], &g_colVisible[ci])) {
                                    g_filteredIndicesDirty = true;
                                }
                            }
                            ImGui::Separator();
                            if (ImGui::SmallButton("Reset All")) {
                                for (int ci = 0; ci < 11; ci++) g_colVisible[ci] = true;
                                g_filteredIndicesDirty = true;
                            }
                            ImGui::End();
                            g_showColumnChooser.store(colChooserOpen);
                        }

                        if (g_showFilterChooser) {
                            ImVec2 popPos(filtersX, legendY - 2.0f + 16.0f + 4.0f);
                            ImGui::SetNextWindowPos(popPos);
                            ImGui::SetNextWindowSize(ImVec2(160, 0));
                            bool filterChooserOpen = g_showFilterChooser.load();
                            ImGui::Begin("##filterChooser", &filterChooserOpen,
                                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                                ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                                ImGuiWindowFlags_AlwaysAutoResize);
                            ImGui::TextDisabled("Filters");
                            ImGui::Separator();
                            if (ImGui::Checkbox("Microsoft", &g_filterShowMicrosoft)) g_filteredIndicesDirty = true;
                            if (ImGui::Checkbox("Portable", &g_filterShowPortable)) g_filteredIndicesDirty = true;
                            if (ImGui::Checkbox("Windows Store", &g_filterShowStore)) g_filteredIndicesDirty = true;
                            if (ImGui::Checkbox("System", &g_filterShowSystem)) g_filteredIndicesDirty = true;
                            if (ImGui::Checkbox("Updates", &g_filterShowUpdates)) g_filteredIndicesDirty = true;
                            if (ImGui::Checkbox("Protected", &g_filterShowProtected)) g_filteredIndicesDirty = true;
                            if (ImGui::Checkbox("Orphans", &g_filterShowOrphans)) g_filteredIndicesDirty = true;
                            if (ImGui::Checkbox("Chocolatey", &g_filterShowChocolatey)) g_filteredIndicesDirty = true;
                            if (ImGui::Checkbox("Scoop", &g_filterShowScoop)) g_filteredIndicesDirty = true;
                            if (ImGui::Checkbox("Tweaks", &g_filterShowTweaks)) g_filteredIndicesDirty = true;
                            if (ImGui::Checkbox("Unregistered", &g_filterShowUnregistered)) g_filteredIndicesDirty = true;
                            ImGui::Separator();
                            if (ImGui::SmallButton("Reset All")) {
                                g_filterShowMicrosoft = true;
                                g_filterShowPortable = true;
                                g_filterShowStore = true;
                                g_filterShowSystem = true;
                                g_filterShowUpdates = true;
                                g_filterShowProtected = true;
                                g_filterShowOrphans = true;
                                g_filterShowChocolatey = true;
                                g_filterShowScoop = true;
                                g_filterShowTweaks = true;
                                g_filterShowUnregistered = true;
                                g_uninstallFilter.clear();
                                g_filteredIndicesDirty = true;
                            }
                            ImGui::End();
                            g_showFilterChooser.store(filterChooserOpen);
                        }

                        {
                            float btnPillR = 7.0f;
                            float btnPillH = 16.0f;
                            float btnY = legendY - 2.0f;
                            ImVec2 refMin(rightX, btnY);
                            ImVec2 refMax(rightX + refreshW, btnY + btnPillH);
                            bool refHover = io.MousePos.x >= refMin.x && io.MousePos.x <= refMax.x &&
                                            io.MousePos.y >= refMin.y && io.MousePos.y <= refMax.y;
                            ImU32 refBg = refHover ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG);
                            cdl->AddRectFilled(refMin, refMax, refBg, btnPillR);
                            ImU32 refBorder = refHover ? IM_COL32(80, 200, 160, 220) : IM_COL32(80, 200, 160, 120);
                            cdl->AddRect(refMin, refMax, refBorder, btnPillR, 0, refHover ? 1.5f : 1.0f);
                            ImVec2 refTxt = ImGui::CalcTextSize("Refresh");
                            cdl->AddText(ImVec2(refMin.x + (refreshW - refTxt.x) / 2, refMin.y + 2),
                                Vec4ToU32(CLR_TEXT), "Refresh");
                            if (refHover && io.MouseClicked[0]) {
                                g_iconThreadRunning.store(false);
                                g_sizeCalcDone.store(true);
                                g_iconThreadGeneration.store(0);
                                g_iconThreadDone.store(false);
                                diskCachePreloaded = false;
                                g_initialScanStarted = true;
                                g_scanComplete.store(false);
                                g_scanPhase.store(0);
                                g_selectedUninstallIdx = -1;
                                g_filteredIndicesDirty = true;
                                LaunchBigStackThread([]() {
                                    BlackHole::Uninstaller u;
                                    auto entries = u.ScanInstalled();
                                    auto orphans = u.ScanDirectoryOrphans();
                                    entries.insert(entries.end(), orphans.begin(), orphans.end());
                                    u.EnrichEntriesBackground(entries);
                                    {
                                        std::lock_guard<std::mutex> lock(g_scanResultMutex);
                                        g_scanResultPending = std::move(entries);
                                    }
                                    g_scanComplete.store(true);
                                    g_initialScanStarted2 = true;
                                    g_scanComplete2.store(false);
                                    auto extras = u.ScanExtras();
                                    {
                                        std::lock_guard<std::mutex> lock(g_extrasMutex);
                                        g_extrasPending = std::move(extras);
                                    }
                                    g_scanComplete2.store(true);
                                });
                            }
                        }

                    }

                    bool hasTextFilter = !g_uninstallFilter.empty();
                    if (g_uninstallFilter != g_lastFilterText) {
                        g_lastFilterText = g_uninstallFilter;
                        g_filteredIndicesDirty = true;
                    }

                    if (g_filteredIndicesDirty) {
                        g_filteredIndicesCache.clear();
                        g_filteredIndicesDirty = false;
                        std::string filterLower;
                        if (hasTextFilter) {
                            filterLower = g_uninstallFilter;
                            std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::tolower);
                        }

                        for (int i = 0; i < (int)g_uninstallEntries.size(); i++) {
                            auto& e = g_uninstallEntries[i];

                            bool pass = true;

                            if (!g_filterShowMicrosoft) {
                                if (e.publisherLower.find(L"microsoft") != std::wstring::npos ||
                                    e.displayNameLower.find(L"microsoft") != std::wstring::npos) pass = false;
                            }

                            if (pass && !g_filterShowPortable) {
                                if (e.registryKey.empty() && e.uninstallString.empty()) pass = false;
                            }

                            if (pass && !g_filterShowStore) {
                                if (e.registryKeyLower.find(L"microsoft\\windows\\currentversion\\uninstall\\microsoft.windows.") != std::wstring::npos ||
                                    e.registryKeyLower.find(L"microsoft\\windows\\currentversion\\uninstall\\microsoft.windowsstore") != std::wstring::npos) {
                                    pass = false;
                                }
                                if (pass && e.isSystemComponent) {
                                    if (e.displayNameLower.find(L" (x86)") != std::wstring::npos ||
                                        e.displayNameLower.find(L" (x64)") != std::wstring::npos) {
                                        size_t lastParen = e.displayNameLower.rfind(L" (");
                                        if (lastParen != std::wstring::npos) {
                                            std::wstring_view tail(e.displayNameLower.c_str() + lastParen,
                                                                   e.displayNameLower.size() - lastParen);
                                            if (tail.find(L"package") != std::wstring_view::npos ||
                                                tail.find(L"extension") != std::wstring_view::npos ||
                                                tail.find(L"experience") != std::wstring_view::npos) {
                                                pass = false;
                                            }
                                        }
                                    }
                                }
                            }

                            if (pass && !g_filterShowSystem) {
                                if (e.isSystemComponent) pass = false;
                            }

                            if (pass && !g_filterShowUpdates) {
                                if (e.isUpdate) pass = false;
                            }

                            if (pass && !g_filterShowProtected) {
                                if (e.isProtected) pass = false;
                            }

                            if (pass && !g_filterShowOrphans) {
                                if (e.isOrphaned) pass = false;
                            }

                            if (pass && !g_filterShowChocolatey) {
                                if (e.installerType == BlackHole::InstallerType::Chocolatey) pass = false;
                            }
                            if (pass && !g_filterShowScoop) {
                                if (e.installerType == BlackHole::InstallerType::Scoop) pass = false;
                            }
                            if (pass && !g_filterShowTweaks) {
                                if (e.isUpdate && e.isSystemComponent) pass = false;
                            }
                            if (pass && !g_filterShowUnregistered) {
                                if (e.uninstallString.empty() && e.quietUninstallString.empty() && !e.isSystemComponent) pass = false;
                            }

                            if (pass && g_colorFilter >= 0) {
                                bool matchColor = false;
                                switch (g_colorFilter) {
                                    case 0: matchColor = (e.certStatus == BlackHole::CertStatus::Verified); break;
                                    case 1: matchColor = (e.certStatus == BlackHole::CertStatus::Unverified); break;
                                    case 2: matchColor = e.isOrphaned; break;
                                    case 3: matchColor = BlackHole::IsStoreApp(e); break;
                                    case 4: matchColor = e.isUpdate; break;
                                    case 5: matchColor = e.uninstallString.empty() && e.quietUninstallString.empty(); break;
                                }
                                if (!matchColor) pass = false;
                            }

                            if (pass) {
                                if (!hasTextFilter) {
                                    g_filteredIndicesCache.push_back(i);
                                } else {
                                    std::string dnUtf8;
                                    {
                                        int sz = WideCharToMultiByte(CP_UTF8, 0, e.displayNameLower.c_str(),
                                            (int)e.displayNameLower.size(), NULL, 0, NULL, NULL);
                                        dnUtf8.resize(sz);
                                        WideCharToMultiByte(CP_UTF8, 0, e.displayNameLower.c_str(),
                                            (int)e.displayNameLower.size(), &dnUtf8[0], sz, NULL, NULL);
                                    }
                                    if (dnUtf8.find(filterLower) != std::string::npos)
                                        g_filteredIndicesCache.push_back(i);
                                }
                            }
                        }
                    }
                    std::vector<int>& filteredIndices = g_filteredIndicesCache;

                    float tableX = cPos.x + pad;
                    float tableY = innerY + 26.0f;
                    float tableW = cSize.x - pad * 2 - 10.0f;
                    float tableH = innerH - 26.0f - 4.0f;

                    ImGui::SetCursorScreenPos(ImVec2(tableX, tableY));

                    ImGuiStyle styleBackup = ImGui::GetStyle();
                    ImGui::GetStyle().WindowPadding = ImVec2(0, 0);
                    ImGui::GetStyle().CellPadding = ImVec2(4.0f, 2.0f);
                    ImGui::GetStyle().ItemSpacing = ImVec2(4.0f, 0.0f);
                    ImGui::GetStyle().FrameRounding = 0.0f;
                    ImGui::GetStyle().ScrollbarSize = 10.0f;

                    ImGui::PushStyleColor(ImGuiCol_TableBorderLight, Vec4ToU32(CLR_STROKE));
                    ImGui::PushStyleColor(ImGuiCol_TableBorderStrong, Vec4ToU32(CLR_STROKE));
                    ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, Vec4ToU32(CLR_ELEM_BG));
                    ImGui::PushStyleColor(ImGuiCol_TableRowBg, Vec4ToU32(CLR_CHILD_BG));
                    ImGui::PushStyleColor(ImGuiCol_TableRowBgAlt, g_darkMode ? ImVec4(0.035f, 0.035f, 0.043f, 1.0f) : ImVec4(0.94f, 0.94f, 0.96f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_Text, Vec4ToU32(CLR_TEXT));
                    ImGui::PushStyleColor(ImGuiCol_Header, Vec4ToU32(CLR_ELEM_BG_HOVER));
                    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, Vec4ToU32(CLR_ELEM_BG_HOVER));

                    bool col1Visible = g_colVisible[1];
                    bool col2Visible = g_colVisible[2];
                    bool col3Visible = g_colVisible[3];
                    bool col4Visible = g_colVisible[4];
                    bool col5Visible = g_colVisible[5];
                    bool col6Visible = g_colVisible[6];
                    bool col7Visible = g_colVisible[7];
                    bool col8Visible = g_colVisible[8];
                    bool col9Visible = g_colVisible[9];
                    bool col10Visible = g_colVisible[10];

                    if (ImGui::BeginTable("##uninstallTable", 11,
                        ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Sortable |
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                        ImGuiTableFlags_Resizable,
                        ImVec2(tableW, tableH))) {

                        ImGui::TableSetupScrollFreeze(0, 1);
                        ImGui::TableSetupColumn(g_colVisible[0] ? "Program Name" : "",
                            ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortAscending |
                            ImGuiTableColumnFlags_WidthFixed, g_colVisible[0] ? 300.0f : 0.0f, 0);
                        ImGui::TableSetupColumn(col1Visible ? "Publisher" : "",
                            ImGuiTableColumnFlags_WidthFixed | (col1Visible ? (ImGuiTableColumnFlags)0 : ImGuiTableColumnFlags_NoClip),
                            col1Visible ? 200.0f : 0.0f, 1);
                        ImGui::TableSetupColumn(col2Visible ? "Size" : "",
                            ImGuiTableColumnFlags_PreferSortDescending |
                            ImGuiTableColumnFlags_WidthFixed | (col2Visible ? (ImGuiTableColumnFlags)0 : ImGuiTableColumnFlags_NoClip),
                            col2Visible ? 100.0f : 0.0f, 2);
                        ImGui::TableSetupColumn(col3Visible ? "Installed On" : "",
                            ImGuiTableColumnFlags_PreferSortDescending |
                            ImGuiTableColumnFlags_WidthFixed | (col3Visible ? (ImGuiTableColumnFlags)0 : ImGuiTableColumnFlags_NoClip),
                            col3Visible ? 120.0f : 0.0f, 3);
                        ImGui::TableSetupColumn(col4Visible ? "Cert" : "",
                            ImGuiTableColumnFlags_WidthFixed | (col4Visible ? (ImGuiTableColumnFlags)0 : ImGuiTableColumnFlags_NoClip),
                            col4Visible ? 90.0f : 0.0f, 4);
                        ImGui::TableSetupColumn(col5Visible ? "Arch" : "",
                            ImGuiTableColumnFlags_WidthFixed | (col5Visible ? (ImGuiTableColumnFlags)0 : ImGuiTableColumnFlags_NoClip),
                            col5Visible ? 70.0f : 0.0f, 5);
                        ImGui::TableSetupColumn(col6Visible ? "Version" : "",
                            ImGuiTableColumnFlags_WidthFixed | (col6Visible ? (ImGuiTableColumnFlags)0 : ImGuiTableColumnFlags_NoClip),
                            col6Visible ? 120.0f : 0.0f, 6);
                        ImGui::TableSetupColumn(col7Visible ? "Kind" : "",
                            ImGuiTableColumnFlags_WidthFixed | (col7Visible ? (ImGuiTableColumnFlags)0 : ImGuiTableColumnFlags_NoClip),
                            col7Visible ? 130.0f : 0.0f, 7);
                        ImGui::TableSetupColumn(col8Visible ? "Location" : "",
                            ImGuiTableColumnFlags_WidthFixed | (col8Visible ? (ImGuiTableColumnFlags)0 : ImGuiTableColumnFlags_NoClip),
                            col8Visible ? 220.0f : 0.0f, 8);
                        ImGui::TableSetupColumn(col9Visible ? "Protected" : "",
                            ImGuiTableColumnFlags_WidthFixed | (col9Visible ? (ImGuiTableColumnFlags)0 : ImGuiTableColumnFlags_NoClip),
                            col9Visible ? 80.0f : 0.0f, 9);
                        ImGui::TableSetupColumn(col10Visible ? "Sys Component" : "",
                            ImGuiTableColumnFlags_WidthFixed | (col10Visible ? (ImGuiTableColumnFlags)0 : ImGuiTableColumnFlags_NoClip),
                            col10Visible ? 80.0f : 0.0f, 10);
                        ImGui::TableHeadersRow();

                        if (ImGuiTableSortSpecs* sortSpecs = ImGui::TableGetSortSpecs()) {
                            if (sortSpecs->SpecsDirty && sortSpecs->SpecsCount > 0) {
                                const ImGuiTableColumnSortSpecs& spec = sortSpecs->Specs[0];
                                g_uninstallSortCol = spec.ColumnIndex;
                                g_uninstallSortAsc = (spec.SortDirection == ImGuiSortDirection_Ascending);
                                sortSpecs->SpecsDirty = false;
                            }
                        }

                        {
                            int col = g_uninstallSortCol;
                            bool asc = g_uninstallSortAsc;
                            std::sort(filteredIndices.begin(), filteredIndices.end(),
                                [&](int a, int b) {
                                    auto& ea = g_uninstallEntries[a];
                                    auto& eb = g_uninstallEntries[b];
                                    int cmp = 0;
                                    if (col == 0) {
                                        cmp = _wcsicmp(ea.displayName.c_str(), eb.displayName.c_str());
                                    } else if (col == 1) {
                                        cmp = _wcsicmp(ea.publisher.c_str(), eb.publisher.c_str());
                                    } else if (col == 2) {
                                        cmp = (ea.estimatedSize < eb.estimatedSize) ? -1 :
                                              (ea.estimatedSize > eb.estimatedSize) ? 1 : 0;
                                    } else if (col == 3) {
                                        cmp = ea.installDate.compare(eb.installDate);
                                    } else if (col == 4) {
                                        int ca = (int)ea.certStatus;
                                        int cb = (int)eb.certStatus;
                                        cmp = ca - cb;
                                    } else if (col == 5) {
                                        cmp = (int)ea.bitness - (int)eb.bitness;
                                    } else if (col == 6) {
                                        cmp = ea.displayVersion.compare(eb.displayVersion);
                                    } else if (col == 7) {
                                        cmp = (int)ea.installerType - (int)eb.installerType;
                                    } else if (col == 8) {
                                        cmp = ea.installPath.compare(eb.installPath);
                                    } else if (col == 9) {
                                        cmp = (int)ea.isProtected - (int)eb.isProtected;
                                    } else if (col == 10) {
                                        cmp = (int)ea.isSystemComponent - (int)eb.isSystemComponent;
                                    }
                                    return asc ? (cmp < 0) : (cmp > 0);
                                });
                        }

                        for (int vi = 0; vi < (int)filteredIndices.size(); vi++) {
                            int idx = filteredIndices[vi];
                            auto& e = g_uninstallEntries[idx];

                            ImGui::PushID(idx);
                            ImGui::TableNextRow(ImGuiTableRowFlags_None, 22.0f);

                            if (ImGui::TableSetColumnIndex(0)) {
                                ImVec2 cellMin = ImGui::GetCursorScreenPos();
                                bool isSelected = (g_selectedUninstallIdx == idx);
                                bool isChecked = (idx < (int)g_rowSelected.size() && g_rowSelected[idx]);
                                float colW = ImGui::GetColumnWidth(0);

                                ImGui::SetCursorScreenPos(cellMin);
                                if (ImGui::Selectable("##row_sel", isSelected, ImGuiSelectableFlags_AllowDoubleClick | ImGuiSelectableFlags_SpanAllColumns, ImVec2(colW, 20.0f))) {
                                    if (io.KeyCtrl) {
                                        if (idx < (int)g_rowSelected.size()) g_rowSelected[idx] = !g_rowSelected[idx];
                                    } else {
                                        g_selectedUninstallIdx = idx;
                                    }
                                }
                                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                                    g_ctxMenuIdx = idx;
                                }

                                ImDrawList* rowDL = ImGui::GetWindowDrawList();
                                float checkX = cellMin.x + 3.0f;
                                float checkY = cellMin.y + 2.0f;
                                float checkSize = 12.0f;
                                ImVec2 checkMin(checkX, checkY);
                                ImVec2 checkMax(checkX + checkSize, checkY + checkSize);
                    ImU32 checkBg = isChecked ? Vec4ToU32(CLR_ACCENT) : Vec4ToU32(CLR_ELEM_BG);
                    ImU32 checkBorder = isChecked ? Vec4ToU32(CLR_ACCENT) : Vec4ToU32(CLR_STROKE);
                                rowDL->AddRectFilled(checkMin, checkMax, checkBg, 2.0f);
                                rowDL->AddRect(checkMin, checkMax, checkBorder, 2.0f, 0, 1.0f);
                                if (isChecked) {
                                    ImVec2 p1(checkX + 2.5f, checkY + 6.0f);
                                    ImVec2 p2(checkX + 5.0f, checkY + 8.5f);
                                    ImVec2 p3(checkX + 9.5f, checkY + 3.5f);
                                    rowDL->AddLine(p1, p2, IM_COL32(255, 255, 255, 230), 1.5f);
                                    rowDL->AddLine(p2, p3, IM_COL32(255, 255, 255, 230), 1.5f);
                                }
                                bool checkHov = io.MousePos.x >= checkMin.x && io.MousePos.x <= checkMax.x &&
                                                io.MousePos.y >= checkMin.y && io.MousePos.y <= checkMax.y;
                                if (checkHov && io.MouseClicked[0]) {
                                    if (idx < (int)g_rowSelected.size()) g_rowSelected[idx] = !g_rowSelected[idx];
                                }

                                ImVec2 iconPos(cellMin.x + 18.0f, cellMin.y + 2.0f);
                                ID3D11ShaderResourceView* iconSRV = nullptr;
                                {
                                    std::lock_guard<std::mutex> lock(g_iconMutex);
                                    auto it = g_iconCache.find(e.displayName);
                                    if (it != g_iconCache.end() && it->second)
                                        iconSRV = it->second;
                                }

                                if (iconSRV) {
                                    rowDL->AddImage((ImTextureID)iconSRV, iconPos, ImVec2(iconPos.x + 16.0f, iconPos.y + 16.0f));
                                } else if (g_defaultIconSRV) {
                                    rowDL->AddImage((ImTextureID)g_defaultIconSRV, iconPos, ImVec2(iconPos.x + 16.0f, iconPos.y + 16.0f));
                                } else {
                                    ImVec2 dp(iconPos.x + 1.0f, iconPos.y + 1.0f);
                                    rowDL->AddRectFilled(dp, ImVec2(dp.x + 14.0f, dp.y + 14.0f),
                                        Vec4ToU32(CLR_STROKE), 3.0f);
                                }

                                std::string nameUtf8;
                                {
                                    int sz = WideCharToMultiByte(CP_UTF8, 0, e.displayName.c_str(), (int)e.displayName.size(), NULL, 0, NULL, NULL);
                                    nameUtf8.resize(sz);
                                    WideCharToMultiByte(CP_UTF8, 0, e.displayName.c_str(), (int)e.displayName.size(), &nameUtf8[0], sz, NULL, NULL);
                                }
                                ImGui::SetCursorScreenPos(ImVec2(cellMin.x + 38.0f, cellMin.y + 2.0f));
                                if (e.isSystemComponent) {
                                    ImGui::TextColored(CLR_ACCENT, "%s", nameUtf8.c_str());
                                } else {
                                    ImGui::TextUnformatted(nameUtf8.c_str());
                                }
                                {
                                    ImVec2 txtEnd = ImGui::GetItemRectMax();
                                    ImVec2 lineStart(cellMin.x + 38.0f, txtEnd.y + 1.0f);
                                    float lineW = txtEnd.x - lineStart.x;
                                    if (lineW > 4.0f) {
                                        ImVec4 statusClr(0.0f, 0.0f, 0.0f, 0.0f);
                                        bool gotColor = false;
                                        if (e.certStatus == BlackHole::CertStatus::Verified) {
                                            statusClr = ImVec4(0.20f, 0.90f, 0.40f, 1.0f); gotColor = true;
                                        } else if (e.certStatus == BlackHole::CertStatus::Unverified) {
                                            statusClr = ImVec4(1.00f, 0.65f, 0.10f, 1.0f); gotColor = true;
                                        } else if (e.isOrphaned) {
                                            statusClr = ImVec4(0.95f, 0.20f, 0.25f, 1.0f); gotColor = true;
                                        } else if (BlackHole::IsStoreApp(e)) {
                                            statusClr = ImVec4(0.25f, 0.55f, 1.00f, 1.0f); gotColor = true;
                                        } else if (e.isUpdate) {
                                            statusClr = ImVec4(0.75f, 0.40f, 1.00f, 1.0f); gotColor = true;
                                        } else if (e.uninstallString.empty() && e.quietUninstallString.empty()) {
                                            statusClr = ImVec4(0.50f, 0.50f, 0.55f, 1.0f); gotColor = true;
                                        } else {
                                            statusClr = ImVec4(0.30f, 0.30f, 0.38f, 1.0f); gotColor = true;
                                        }
                                        if (gotColor) {
                                            ImU32 lineCol = IM_COL32((int)(statusClr.x * 255), (int)(statusClr.y * 255), (int)(statusClr.z * 255), 160);
                                            rowDL->AddLine(lineStart, ImVec2(lineStart.x + lineW, lineStart.y), lineCol, 2.0f);
                                        }
                                    }
                                }
                            }

                            if (col1Visible && ImGui::TableSetColumnIndex(1)) {
                                std::string pubUtf8;
                                if (!e.publisher.empty()) {
                                    int psz = WideCharToMultiByte(CP_UTF8, 0, e.publisher.c_str(), (int)e.publisher.size(), NULL, 0, NULL, NULL);
                                    pubUtf8.resize(psz);
                                    WideCharToMultiByte(CP_UTF8, 0, e.publisher.c_str(), (int)e.publisher.size(), &pubUtf8[0], psz, NULL, NULL);
                                } else {
                                    pubUtf8 = "-";
                                }
                                ImGui::TextColored(CLR_TEXT_DIM, "%s", pubUtf8.c_str());
                            }

                            if (col2Visible && ImGui::TableSetColumnIndex(2)) {
                                float kb = (float)e.estimatedSize;
                                char sizeBuf[32];
                                if (kb >= 1048576.0f)
                                    snprintf(sizeBuf, sizeof(sizeBuf), "%.1f GB", kb / 1048576.0f);
                                else if (kb >= 1024.0f)
                                    snprintf(sizeBuf, sizeof(sizeBuf), "%.0f MB", kb / 1024.0f);
                                else if (kb > 0)
                                    snprintf(sizeBuf, sizeof(sizeBuf), "%.0f KB", kb);
                                else
                                    snprintf(sizeBuf, sizeof(sizeBuf), "-");
                                ImGui::TextColored(CLR_TEXT_DIM, "%s", sizeBuf);
                            }

                            if (col3Visible && ImGui::TableSetColumnIndex(3)) {
                                std::string dateUtf8;
                                if (!e.installDate.empty() && e.installDate.size() == 8) {
                                    int dsz = WideCharToMultiByte(CP_UTF8, 0, e.installDate.c_str(), (int)e.installDate.size(), NULL, 0, NULL, NULL);
                                    dateUtf8.resize(dsz);
                                    WideCharToMultiByte(CP_UTF8, 0, e.installDate.c_str(), (int)e.installDate.size(), &dateUtf8[0], dsz, NULL, NULL);
                                    if (dateUtf8.size() == 8) {
                                        std::string yr = dateUtf8.substr(0, 4);
                                        std::string mo = dateUtf8.substr(4, 2);
                                        std::string dy = dateUtf8.substr(6, 2);
                                        dateUtf8 = mo + "/" + dy + "/" + yr;
                                    }
                                } else {
                                    dateUtf8 = "-";
                                }
                                ImGui::TextColored(CLR_TEXT_DIM, "%s", dateUtf8.c_str());
                            }

                            if (col4Visible && ImGui::TableSetColumnIndex(4)) {
                                const char* certLabel = "-";
                                ImVec4 certClr = CLR_TEXT_DIM;
                                if (e.certStatus == BlackHole::CertStatus::Verified) {
                                    certLabel = "OK";
                                    certClr = ImVec4(0.35f, 0.75f, 0.35f, 1.0f);
                                } else if (e.certStatus == BlackHole::CertStatus::Unverified) {
                                    certLabel = "WARN";
                                    certClr = ImVec4(0.85f, 0.55f, 0.25f, 1.0f);
                                }
                                ImGui::TextColored(certClr, "%s", certLabel);
                            }
                            if (col5Visible && ImGui::TableSetColumnIndex(5)) {
                                const char* archLabel = "-";
                                if (e.bitness == BlackHole::Bitness::X64) archLabel = "x64";
                                else if (e.bitness == BlackHole::Bitness::X86) archLabel = "x86";
                                else if (e.bitness == BlackHole::Bitness::ARM64) archLabel = "ARM64";
                                ImGui::TextColored(CLR_TEXT_DIM, "%s", archLabel);
                            }
                            if (col6Visible && ImGui::TableSetColumnIndex(6)) {
                                std::string verUtf8;
                                if (!e.displayVersion.empty()) {
                                    int vsz = WideCharToMultiByte(CP_UTF8, 0, e.displayVersion.c_str(), (int)e.displayVersion.size(), NULL, 0, NULL, NULL);
                                    verUtf8.resize(vsz);
                                    WideCharToMultiByte(CP_UTF8, 0, e.displayVersion.c_str(), (int)e.displayVersion.size(), &verUtf8[0], vsz, NULL, NULL);
                                } else {
                                    verUtf8 = "-";
                                }
                                ImGui::TextColored(CLR_TEXT_DIM, "%s", verUtf8.c_str());
                            }
                            if (col7Visible && ImGui::TableSetColumnIndex(7)) {
                                const char* kindLabel = "Standard";
                                switch (e.installerType) {
                                    case BlackHole::InstallerType::Msi: kindLabel = "MSI"; break;
                                    case BlackHole::InstallerType::InnoSetup: kindLabel = "InnoSetup"; break;
                                    case BlackHole::InstallerType::Nsis: kindLabel = "NSIS"; break;
                                    case BlackHole::InstallerType::InstallShield: kindLabel = "InstallShield"; break;
                                    case BlackHole::InstallerType::PowerShell: kindLabel = "PowerShell"; break;
                                    case BlackHole::InstallerType::SdbInst: kindLabel = "SdbInst"; break;
                                    case BlackHole::InstallerType::StoreApp: kindLabel = "Store"; break;
                                    case BlackHole::InstallerType::Chocolatey: kindLabel = "Chocolatey"; break;
                                    case BlackHole::InstallerType::Scoop: kindLabel = "Scoop"; break;
                                    case BlackHole::InstallerType::WindowsFeature: kindLabel = "Feature"; break;
                                    default: kindLabel = "Unknown"; break;
                                }
                                ImGui::TextColored(CLR_TEXT_DIM, "%s", kindLabel);
                            }
                            if (col8Visible && ImGui::TableSetColumnIndex(8)) {
                                std::string locUtf8;
                                if (!e.installPath.empty()) {
                                    int lsz = WideCharToMultiByte(CP_UTF8, 0, e.installPath.c_str(), (int)e.installPath.size(), NULL, 0, NULL, NULL);
                                    locUtf8.resize(lsz);
                                    WideCharToMultiByte(CP_UTF8, 0, e.installPath.c_str(), (int)e.installPath.size(), &locUtf8[0], lsz, NULL, NULL);
                                    if (locUtf8.size() > 30) locUtf8 = "..." + locUtf8.substr(locUtf8.size() - 27);
                                } else {
                                    locUtf8 = "-";
                                }
                                ImGui::TextColored(CLR_TEXT_DIM, "%s", locUtf8.c_str());
                            }
                            if (col9Visible && ImGui::TableSetColumnIndex(9)) {
                                if (e.isProtected) {
                                    ImGui::TextColored(ImVec4(0.85f, 0.55f, 0.25f, 1.0f), "Yes");
                                } else {
                                    ImGui::TextColored(CLR_TEXT_DIM, "-");
                                }
                            }
                            if (col10Visible && ImGui::TableSetColumnIndex(10)) {
                                if (e.isSystemComponent) {
                                    ImGui::TextColored(ImVec4(0.85f, 0.55f, 0.25f, 1.0f), "Yes");
                                } else {
                                    ImGui::TextColored(CLR_TEXT_DIM, "-");
                                }
                            }

                            ImGui::PopID();
                        }

                        ImGui::EndTable();
                    }

                    ImGui::PopStyleColor(8);
                    ImGui::GetStyle() = styleBackup;

                    {
                        int shown = (int)filteredIndices.size();
                        int total = (int)g_uninstallEntries.size();
                        bool filtersActive = !g_filterShowMicrosoft || !g_filterShowPortable ||
                                             !g_filterShowStore || !g_filterShowSystem ||
                                             !g_filterShowUpdates || !g_filterShowProtected ||
                                             !g_filterShowOrphans || !g_filterShowChocolatey ||
                                             !g_filterShowScoop || !g_filterShowTweaks ||
                                             !g_filterShowUnregistered ||
                                              !g_uninstallFilter.empty();

                    }

                    {
                        static bool ctxMenuWasOpen = false;
                        bool popupIsOpen = ImGui::IsPopupOpen("##uninstall_ctx");
                        if (ctxMenuWasOpen && !popupIsOpen && g_ctxMenuIdx >= 0) {
                            g_ctxMenuIdx = -1;
                        }
                        ctxMenuWasOpen = popupIsOpen;

                        if (g_ctxMenuIdx >= 0 && g_ctxMenuIdx < (int)g_uninstallEntries.size() && !popupIsOpen) {
                            ImGui::OpenPopup("##uninstall_ctx");
                        }
                    }
                    if (ImGui::BeginPopup("##uninstall_ctx")) {
                        if (g_ctxMenuIdx >= 0 && g_ctxMenuIdx < (int)g_uninstallEntries.size()) {
                            auto& selEntry = g_uninstallEntries[g_ctxMenuIdx];

                            std::string selNameUtf8;
                            {
                                int sz = WideCharToMultiByte(CP_UTF8, 0, selEntry.displayName.c_str(), (int)selEntry.displayName.size(), NULL, 0, NULL, NULL);
                                selNameUtf8.resize(sz);
                                WideCharToMultiByte(CP_UTF8, 0, selEntry.displayName.c_str(), (int)selEntry.displayName.size(), &selNameUtf8[0], sz, NULL, NULL);
                            }

                            ImGui::TextColored(ImVec4(0.55f, 0.51f, 1.0f, 1.0f), "%s", selNameUtf8.c_str());
                            ImGui::Separator();

                            if (ImGui::MenuItem("Uninstall...")) {
                                int selCount = 0;
                                for (auto s : g_rowSelected) if (s) selCount++;

                                if (selCount > 1) {
                                    std::vector<BlackHole::UninstallEntry> selectedEntries;
                                    for (int si = 0; si < (int)g_rowSelected.size(); si++) {
                                        if (g_rowSelected[si] && si < (int)g_uninstallEntries.size()) {
                                            selectedEntries.push_back(g_uninstallEntries[si]);
                                        }
                                    }
                                    BlackHole::ScanDepth depthCopy = g_scanDepth;
                                    g_rowSelected.assign(g_rowSelected.size(), false);
                                    g_ctxMenuIdx = -1;
                                    g_selectedUninstallIdx = -1;
                                    ImGui::CloseCurrentPopup();
                                    g_scanComplete.store(false);
                                    LaunchBigStackThread([selectedEntries, depthCopy]() {
                                        try {
                                        std::vector<BlackHole::LeftoverItem> allLeftovers;
                                        for (size_t i = 0; i < selectedEntries.size(); i++) {
                                            auto& se = selectedEntries[i];
                                            std::wstring cmd = !se.quietUninstallString.empty() ? se.quietUninstallString : se.uninstallString;
                                            bool uninstallerRan = false;
                                            if (!cmd.empty()) {
                                                if (se.isMsiInstaller) {
                                                    if (cmd.find(L"MsiExec") == std::wstring::npos &&
                                                        cmd.find(L"msiexec") == std::wstring::npos) {
                                                        cmd = L"msiexec.exe /x " + cmd;
                                                    }
                                                }
                                                if (!cmd.empty() && cmd[0] != L'"' && cmd.find(L' ') != std::wstring::npos) {
                                                    cmd = L"\"" + cmd + L"\"";
                                                }
                                                STARTUPINFOW si2 = {};
                                                si2.cb = sizeof(si2);
                                                PROCESS_INFORMATION pi = {};
                                                std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
                                                cmdBuf.push_back(0);
                                                if (CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si2, &pi)) {
                                                    WaitForSingleObject(pi.hProcess, 60000);
                                                    DWORD exitCode = 0;
                                                    GetExitCodeProcess(pi.hProcess, &exitCode);
                                                    CloseHandle(pi.hProcess);
                                                    CloseHandle(pi.hThread);
                                                    uninstallerRan = (exitCode == 0);
                                                } else {
                                                    std::wstring exePath, exeArgs;
                                                    std::wstring c = cmd;
                                                    if (c.size() >= 2 && c[0] == L'"') {
                                                        auto end = c.find(L'"', 1);
                                                        if (end != std::wstring::npos) { exePath = c.substr(1, end - 1); exeArgs = c.substr(end + 1); }
                                                    } else {
                                                        auto sp = c.find(L' ');
                                                        if (sp != std::wstring::npos) { exePath = c.substr(0, sp); exeArgs = c.substr(sp); } else { exePath = c; }
                                                    }
                                                    DWORD attrs = GetFileAttributesW(exePath.c_str());
                                                    if (attrs != INVALID_FILE_ATTRIBUTES) {
                                                        ShellExecuteW(NULL, L"open", exePath.c_str(), exeArgs.empty() ? NULL : exeArgs.c_str(), NULL, SW_SHOWNORMAL);
                                                        WaitForSingleObject(GetCurrentProcess(), 15000);
                                                        uninstallerRan = true;
                                                    }
                                                }
                                                if (uninstallerRan) std::this_thread::sleep_for(std::chrono::seconds(3));
                                            }
                                            if (!uninstallerRan) {
                                                PushNotification(L"No uninstaller found, scanning leftovers", se.displayName, false);
                                                BlackHole::Uninstaller uScan;
                                                auto leftovers = uScan.ScanLeftovers(se, BlackHole::ScanDepth::Advanced);
                                                for (auto& item : leftovers) item.checked = true;
                                                allLeftovers.insert(allLeftovers.end(), leftovers.begin(), leftovers.end());
                                                uScan.RemoveRegistryEntry(se);
                                            } else {
                                                BlackHole::Uninstaller u;
                                                auto leftovers = u.ScanLeftovers(se, depthCopy);
                                                allLeftovers.insert(allLeftovers.end(), leftovers.begin(), leftovers.end());
                                            }
                                        }
                                        for (auto& item : allLeftovers) item.checked = true;
                                        if (!allLeftovers.empty()) {
                                            {
                                                std::lock_guard<std::mutex> lock(g_forceRemovalMutex);
                                                g_leftoverItems = allLeftovers;
                                                g_batchPurgeNames.clear();
                                                for (auto& se : selectedEntries) {
                                                    g_batchPurgeNames.push_back(se.displayName);
                                                }
                                            }
                                            g_showLeftoverPopup.store(true);
                                        } else {
                                            PushNotification(L"Batch uninstall complete", std::to_wstring(selectedEntries.size()) + L" programs processed", false);
                                        }
                                        if (allLeftovers.empty()) {
                                        BlackHole::Uninstaller uRefresh;
                                        auto freshEntries = uRefresh.ScanInstalled();
                                        auto freshOrphans = uRefresh.ScanDirectoryOrphans();
                                        freshEntries.insert(freshEntries.end(), freshOrphans.begin(), freshOrphans.end());
                                        uRefresh.EnrichEntriesBackground(freshEntries);
                                        { std::lock_guard<std::mutex> lock(g_scanResultMutex); g_scanResultPending = std::move(freshEntries); }
                                        g_initialScanStarted = true;
                                        }
                                        } catch (...) {
                                            PushNotification(L"Batch uninstall failed", L"An error occurred", false);
                                        }
                                        g_scanComplete.store(true);
                                        g_iconThreadGeneration.store(0);
                                    });
                                } else {
                                    g_standardUninstallEntry = selEntry;
                                    g_standardUninstallIdx = g_ctxMenuIdx;
                                    g_pendingStandardUninstall = true;
                                    g_ctxMenuIdx = -1;
                                    g_selectedUninstallIdx = -1;
                                    ImGui::CloseCurrentPopup();
                                }
                            }

                            if (ImGui::MenuItem("Uninstall quietly")) {
                                if (!selEntry.uninstallString.empty()) {
                                    std::wstring cmd = selEntry.uninstallString;

                                    switch (selEntry.installerType) {
                                    case BlackHole::InstallerType::Msi:
                                        if (cmd.find(L"/qn") == std::wstring::npos) {
                                            if (cmd.find(L"/x") != std::wstring::npos)
                                                cmd += L" /qn /norestart";
                                            else
                                                cmd += L" /qn /norestart";
                                        }
                                        break;
                                    case BlackHole::InstallerType::InnoSetup:
                                        if (cmd.find(L"/VERYSILENT") == std::wstring::npos)
                                            cmd += L" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-";
                                        break;
                                    case BlackHole::InstallerType::Nsis:
                                        if (cmd.find(L"/S") == std::wstring::npos)
                                            cmd += L" /S";
                                        break;
                                    case BlackHole::InstallerType::InstallShield:
                                        if (cmd.find(L"/s") == std::wstring::npos &&
                                            cmd.find(L"/S") == std::wstring::npos) {
                                            size_t quotePos = cmd.find(L'"');
                                            if (quotePos != std::wstring::npos)
                                                cmd += L" /s /v\"/qn\"";
                                            else
                                                cmd += L" /s /v\"/qn\"";
                                        }
                                        break;
                                    default: {
                                        std::wstring cmdLower = cmd;
                                        std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::towlower);
                                        bool hasSilent = cmdLower.find(L"/s") != std::wstring::npos ||
                                                         cmdLower.find(L"/silent") != std::wstring::npos ||
                                                         cmdLower.find(L"/quiet") != std::wstring::npos ||
                                                         cmdLower.find(L"/verysilent") != std::wstring::npos;
                                        if (!hasSilent) {
                                            if (cmdLower.find(L"msiexec") != std::wstring::npos)
                                                cmd += L" /qn /norestart";
                                            else
                                                cmd += L" /S";
                                        }
                                        break;
                                        }
                                    }

                                    LaunchBigStackThread([cmd, entry = selEntry, depthCopy = g_scanDepth]() {
                                        try {
                                        bool success = false;
                                        std::wstring fixedCmd = cmd;
                                        if (!fixedCmd.empty() && fixedCmd[0] != L'"' && fixedCmd.find(L' ') != std::wstring::npos) {
                                            fixedCmd = L"\"" + fixedCmd + L"\"";
                                        }
                                        STARTUPINFOW si = { sizeof(si) };
                                        PROCESS_INFORMATION pi = {};
                                        std::vector<wchar_t> cmdBuf(fixedCmd.begin(), fixedCmd.end());
                                        cmdBuf.push_back(0);
                                        if (CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                                            WaitForSingleObject(pi.hProcess, 60000);
                                            DWORD exitCode = 0;
                                            GetExitCodeProcess(pi.hProcess, &exitCode);
                                            CloseHandle(pi.hProcess);
                                            CloseHandle(pi.hThread);
                                            success = (exitCode == 0);
                                        }
                                        std::this_thread::sleep_for(std::chrono::seconds(2));
                                        BlackHole::Uninstaller u;
                                        auto leftovers = u.ScanLeftovers(entry, depthCopy);
                                        for (auto& item : leftovers) item.checked = true;
                                        if (!success) {
                                            PushNotification(L"Uninstaller failed, reviewing leftovers", entry.displayName, false);
                                            u.RemoveRegistryEntry(entry);
                                        }
                                        if (!leftovers.empty()) {
                                            {
                                                std::lock_guard<std::mutex> lock(g_forceRemovalMutex);
                                                g_leftoverItems = leftovers;
                                            }
                                            g_showLeftoverPopup.store(true);
                                        } else if (success) {
                                            PushNotification(L"Quiet uninstall complete", entry.displayName, false);
                                        }
                                        } catch (...) {}
                                    });
                                }
                                g_ctxMenuIdx = -1;
                                g_selectedUninstallIdx = -1;
                                ImGui::CloseCurrentPopup();
                            }

                            if (selEntry.uninstallString.empty() && selEntry.quietUninstallString.empty()) {
                                if (ImGui::MenuItem("Force Remove")) {
                                    int idx = g_ctxMenuIdx;
                                    if (idx >= 0 && idx < (int)g_uninstallEntries.size()) {
                                        auto* data = new ForceRemoveData{g_uninstallEntries[idx], g_scanDepth};
                                        g_popupEraseIdx = idx;
                                        g_ctxMenuIdx = -1;
                                        g_selectedUninstallIdx = -1;
                                        ImGui::CloseCurrentPopup();
                                        g_scanComplete.store(false);
                                        HANDLE hThread = (HANDLE)_beginthreadex(nullptr, 4 * 1024 * 1024, ForceRemoveThread, data, 0, nullptr);
                                        if (hThread) CloseHandle(hThread);
                                    }
                                }
                            }

                            ImGui::Separator();
                            ImGui::TextColored(ImVec4(0.55f, 0.51f, 1.0f, 1.0f), "Scan Depth:");
                            if (ImGui::RadioButton("Safe", g_scanDepth == BlackHole::ScanDepth::Safe))
                                g_scanDepth = BlackHole::ScanDepth::Safe;
                            if (ImGui::RadioButton("Moderate", g_scanDepth == BlackHole::ScanDepth::Moderate))
                                g_scanDepth = BlackHole::ScanDepth::Moderate;
                            if (ImGui::RadioButton("Advanced", g_scanDepth == BlackHole::ScanDepth::Advanced))
                                g_scanDepth = BlackHole::ScanDepth::Advanced;
                            ImGui::Separator();

                            if (ImGui::MenuItem("Open Installation Folder")) {
                                BlackHole::Uninstaller u;
                                std::wstring resolvedPath = u.ResolveInstallPath(selEntry);
                                if (!resolvedPath.empty()) {
                                    ShellExecuteW(NULL, L"open", resolvedPath.c_str(), NULL, NULL, SW_SHOWNORMAL);
                                }
                                g_ctxMenuIdx = -1;
                                ImGui::CloseCurrentPopup();
                            }

                            if (ImGui::MenuItem("View Properties")) {
                                g_propertiesIdx = g_ctxMenuIdx;
                                g_showPropertiesModal = true;
                                g_ctxMenuIdx = -1;
                                ImGui::CloseCurrentPopup();
                            }

                            if (ImGui::MenuItem("Open Registry Entry")) {
                                if (!selEntry.registryKey.empty()) {
                                    std::wstring regPath = selEntry.registryKey;
                                    size_t slashPos = regPath.find(L'\\');
                                    std::wstring hivePrefix;
                                    std::wstring subKey;
                                    if (slashPos != std::wstring::npos) {
                                        hivePrefix = regPath.substr(0, slashPos);
                                        subKey = regPath.substr(slashPos + 1);
                                    } else {
                                        subKey = regPath;
                                    }

                                    std::wstring lastKey;
                                    if (hivePrefix == L"HKLM" || hivePrefix == L"HKEY_LOCAL_MACHINE")
                                        lastKey = L"HKEY_LOCAL_MACHINE\\" + subKey;
                                    else if (hivePrefix == L"HKCU" || hivePrefix == L"HKEY_CURRENT_USER")
                                        lastKey = L"HKEY_CURRENT_USER\\" + subKey;
                                    else
                                        lastKey = regPath;

                                    HKEY hApplets;
                                    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                                        L"Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit",
                                        0, KEY_SET_VALUE, &hApplets) == ERROR_SUCCESS) {
                                        RegSetValueExW(hApplets, L"LastKey", 0, REG_SZ,
                                            (const BYTE*)lastKey.c_str(),
                                            (DWORD)((lastKey.size() + 1) * sizeof(wchar_t)));
                                        RegCloseKey(hApplets);
                                    }

                                    HKEY hWant;
                                    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                                        L"Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit",
                                        0, KEY_SET_VALUE, &hWant) == ERROR_SUCCESS) {
                                        DWORD wantVal = 1;
                                        RegSetValueExW(hWant, L"WantRegedit32", 0, REG_DWORD,
                                            (const BYTE*)&wantVal, sizeof(DWORD));
                                        RegCloseKey(hWant);
                                    }

                                    ShellExecuteW(NULL, L"open", L"regedit.exe", NULL, NULL, SW_SHOWNORMAL);
                                } else {
                                    ShellExecuteW(NULL, L"open", L"regedit.exe", NULL, NULL, SW_SHOWNORMAL);
                                }
                                g_ctxMenuIdx = -1;
                                ImGui::CloseCurrentPopup();
                            }

                            if (ImGui::BeginMenu("Search Online")) {
                                std::wstring encoded = UrlEncode(selEntry.displayName);

                                if (ImGui::MenuItem("Google")) {
                                    std::wstring url = L"https://www.google.com/search?q=" + encoded;
                                    ShellExecuteW(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
                                    g_ctxMenuIdx = -1;
                                    ImGui::CloseCurrentPopup();
                                }
                                if (ImGui::MenuItem("AlternativeTo")) {
                                    std::wstring url = L"https://alternativeto.net/browse/search/?q=" + encoded;
                                    ShellExecuteW(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
                                    g_ctxMenuIdx = -1;
                                    ImGui::CloseCurrentPopup();
                                }
                                if (ImGui::MenuItem("GitHub")) {
                                    std::wstring url = L"https://github.com/search?q=" + encoded + L"&type=repositories";
                                    ShellExecuteW(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
                                    g_ctxMenuIdx = -1;
                                    ImGui::CloseCurrentPopup();
                                }
                                if (ImGui::MenuItem("SourceForge")) {
                                    std::wstring url = L"https://sourceforge.net/directory/?q=" + encoded;
                                    ShellExecuteW(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
                                    g_ctxMenuIdx = -1;
                                    ImGui::CloseCurrentPopup();
                                }
                                if (ImGui::MenuItem("FileHippo")) {
                                    std::wstring url = L"https://filehippo.com/search/?q=" + encoded;
                                    ShellExecuteW(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
                                    g_ctxMenuIdx = -1;
                                    ImGui::CloseCurrentPopup();
                                }
                                ImGui::EndMenu();
                            }

                            if (ImGui::MenuItem("Copy Details to Clipboard")) {
                                std::wstring details = L"Name: " + selEntry.displayName + L"\r\n";
                                details += L"Version: " + selEntry.displayVersion + L"\r\n";
                                details += L"Publisher: " + selEntry.publisher + L"\r\n";
                                details += L"Install Path: " + selEntry.installPath + L"\r\n";
                                details += L"Uninstall: " + selEntry.uninstallString + L"\r\n";
                                details += L"Registry: " + selEntry.registryKey;

                                if (OpenClipboard(NULL)) {
                                    EmptyClipboard();
                                    size_t len = details.size();
                                    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (len + 1) * sizeof(wchar_t));
                                    if (hMem) {
                                        wchar_t* pMem = (wchar_t*)GlobalLock(hMem);
                                        memcpy(pMem, details.c_str(), len * sizeof(wchar_t));
                                        pMem[len] = 0;
                                        GlobalUnlock(hMem);
                                        SetClipboardData(CF_UNICODETEXT, hMem);
                                    }
                                    CloseClipboard();
                                    PushNotification(L"Copied to clipboard", selEntry.displayName, false);
                                }
                                g_ctxMenuIdx = -1;
                                ImGui::CloseCurrentPopup();
                            }

                            ImGui::Separator();

                            if (ImGui::MenuItem("Remove Entry")) {
                                BlackHole::Uninstaller u;
                                u.RemoveRegistryEntry(selEntry);
                                PushNotification(L"Registry entry removed", selEntry.displayName, false);
                                g_iconThreadRunning.store(false);
                                g_sizeCalcDone.store(true);
                                g_iconThreadGeneration.store(0);
                                g_uninstallEntries.erase(g_uninstallEntries.begin() + g_ctxMenuIdx);
                                g_filteredIndicesDirty = true;
                                g_rowSelected.assign(g_uninstallEntries.size(), false);
                                g_ctxMenuIdx = -1;
                                g_selectedUninstallIdx = -1;
                                ImGui::CloseCurrentPopup();
                            }
                        }
                        ImGui::EndPopup();
                    }

                    if (g_showPropertiesModal && g_propertiesIdx >= 0 && g_propertiesIdx < (int)g_uninstallEntries.size()) {
                        ImGui::OpenPopup("App Properties");
                        g_showPropertiesModal = false;
                    }
                    if (ImGui::BeginPopupModal("App Properties", NULL, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
                        if (g_propertiesIdx >= 0 && g_propertiesIdx < (int)g_uninstallEntries.size()) {
                            auto& pe = g_uninstallEntries[g_propertiesIdx];

                            auto w2s = [](const std::wstring& ws) -> std::string {
                                if (ws.empty()) return "-";
                                int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), NULL, 0, NULL, NULL);
                                std::string s(sz, 0);
                                WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &s[0], sz, NULL, NULL);
                                return s;
                            };

                            ImGui::SeparatorText("General");
                            ImGui::Text("Name:     %s", w2s(pe.displayName).c_str());
                            ImGui::Text("Version:  %s", w2s(pe.displayVersion).c_str());
                            ImGui::Text("Publisher:%s", w2s(pe.publisher).c_str());
                            ImGui::Text("Size:     %.1f MB", (float)pe.estimatedSize / 1024.0f);
                            ImGui::Text("Date:     %s", w2s(pe.installDate).c_str());

                            ImGui::SeparatorText("Location & Uninstall");
                            ImGui::Text("Install Path:       %s", w2s(pe.installPath).c_str());
                            ImGui::Text("Install Source:     %s", w2s(pe.installSource).c_str());
                            ImGui::Text("Uninstall String:   %s", w2s(pe.uninstallString).c_str());
                            ImGui::Text("Quiet Uninstall:    %s", w2s(pe.quietUninstallString).c_str());
                            ImGui::Text("Modify Path:        %s", w2s(pe.modifyPath).c_str());

                            ImGui::SeparatorText("Registry");
                            ImGui::Text("Registry Key: %s", w2s(pe.registryKey).c_str());
                            ImGui::Text("About URL:    %s", w2s(pe.aboutUrl).c_str());

                            ImGui::SeparatorText("Security & Architecture");
                            const char* certStr = "Not Found";
                            ImVec4 certClr = CLR_TEXT_DIM;
                            if (pe.certStatus == BlackHole::CertStatus::Verified) { certStr = "Verified"; certClr = ImVec4(0.35f, 0.75f, 0.35f, 1.0f); }
                            else if (pe.certStatus == BlackHole::CertStatus::Unverified) { certStr = "Unverified"; certClr = ImVec4(0.85f, 0.55f, 0.25f, 1.0f); }
                            ImGui::TextColored(certClr, "Certificate: %s", certStr);

                            const char* archStr = "Unknown";
                            if (pe.bitness == BlackHole::Bitness::X64) archStr = "x64";
                            else if (pe.bitness == BlackHole::Bitness::X86) archStr = "x86";
                            else if (pe.bitness == BlackHole::Bitness::ARM64) archStr = "ARM64";
                            ImGui::Text("Architecture: %s", archStr);

                            ImGui::Text("System Component: %s", pe.isSystemComponent ? "Yes" : "No");
                            ImGui::Text("MSI Installer:    %s", pe.isMsiInstaller ? "Yes" : "No");
                            ImGui::Text("Protected:        %s", pe.isProtected ? "Yes" : "No");
                            ImGui::Text("Update:           %s", pe.isUpdate ? "Yes" : "No");
                            ImGui::Text("Orphaned:         %s", pe.isOrphaned ? "Yes" : "No");

                            if (!pe.sortedExecutables.empty()) {
                                ImGui::SeparatorText("Executables");
                                for (auto& exe : pe.sortedExecutables) {
                                    ImGui::BulletText("%s", w2s(exe).c_str());
                                }
                            }
                        }
                        if (ImGui::Button("Close", ImVec2(120, 0)))
                            ImGui::CloseCurrentPopup();
                        ImGui::EndPopup();
                    }

                    if (g_pendingStandardUninstall && g_standardUninstallIdx >= 0 && g_standardUninstallIdx < (int)g_uninstallEntries.size() && !g_standardUninstallRunning.load()) {
                        DebugLog("STEP: pendingStandardUninstall triggered");
                        g_pendingStandardUninstall = false;
                        BlackHole::UninstallEntry entryCopy = g_standardUninstallEntry;
                        DebugLog(("STEP: entry copied: " + WideToUtf8(entryCopy.displayName)).c_str());

                        if (!entryCopy.uninstallString.empty()) {
                            DebugLog(("STEP: uninstallString=" + WideToUtf8(entryCopy.uninstallString)).c_str());
                            g_standardUninstallRunning.store(true);
                            int idxCopy = g_standardUninstallIdx;
                            if (g_standardUninstallThreadHandle) { CloseHandle(g_standardUninstallThreadHandle); g_standardUninstallThreadHandle = NULL; }
                            DebugLog("STEP: launching thread");
                            auto* suData = new StandardUninstallData{entryCopy, idxCopy, g_scanDepth};
                            g_standardUninstallThreadHandle = (HANDLE)_beginthreadex(nullptr, 4 * 1024 * 1024, StandardUninstallThread, suData, 0, nullptr);
                        } else {
                            PushNotification(L"No uninstall command found", entryCopy.displayName, true);
                        }
                    }

                } else if (g_selectedTab == 3) {
                    float sX = cPos.x + 20.0f;
                    float sY = innerY + 10.0f;
                    float cardW = cSize.x - 40.0f;
                    ImU32 cardBg = Vec4ToU32(CLR_ELEM_BG);
                    ImU32 cardBorder = Vec4ToU32(CLR_STROKE);
                    ImU32 headerCol = Vec4ToU32(CLR_TEXT);
                    ImU32 labelCol = Vec4ToU32(CLR_TEXT);
                    ImU32 dimCol = Vec4ToU32(CLR_TEXT_DIM);

                    // Settings scroll: handle mouse wheel
                    float settingsContentH = 620.0f;
                    float settingsVisibleH = cSize.y - 20.0f;
                    if (settingsContentH > settingsVisibleH) {
                        ImVec2 settingsAreaMin(cPos.x, innerY);
                        ImVec2 settingsAreaMax(cPos.x + cSize.x, innerY + cSize.y);
                        if (ImGui::IsMouseHoveringRect(settingsAreaMin, settingsAreaMax)) {
                            g_settingsScrollY -= io.MouseWheel * 40.0f;
                            if (g_settingsScrollY < 0.0f) g_settingsScrollY = 0.0f;
                            float maxScroll = settingsContentH - settingsVisibleH;
                            if (maxScroll < 0.0f) maxScroll = 0.0f;
                            if (g_settingsScrollY > maxScroll) g_settingsScrollY = maxScroll;
                        }
                    } else {
                        g_settingsScrollY = 0.0f;
                    }

                    // Clip settings content area
                    cdl->PushClipRect(ImVec2(cPos.x, innerY), ImVec2(cPos.x + cSize.x, innerY + cSize.y), true);

                    float y = sY - g_settingsScrollY;

                    auto drawSectionHeader = [&](float x, float y, const char* title) {
                        cdl->AddText(ImVec2(x + 14, y + 10), headerCol, title);
                        return y + 32.0f;
                    };

                    auto drawToggle = [&](float togX, float y, bool on) -> ImVec2 {
                        ImVec2 togMin(togX, y);
                        ImVec2 togMax(togX + 52, y + 22);
                        bool togHov = ImGui::IsMouseHoveringRect(togMin, togMax);
                        ImU32 togBg = on ?
                            (togHov ? IM_COL32(8, 40, 24, 255) : IM_COL32(6, 32, 20, 255)) :
                            (togHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_SIDEBAR_BG));
                        if (on && !g_darkMode)
                            togBg = togHov ? IM_COL32(180, 240, 200, 255) : IM_COL32(160, 220, 180, 255);
                        cdl->AddRectFilled(togMin, togMax, togBg, 10.0f);
                        cdl->AddRect(togMin, togMax, cardBorder, 10.0f, 0, 1.0f);
                        float circleX = on ? (togMax.x - 12.0f) : (togMin.x + 12.0f);
                        ImU32 circCol = on ? IM_COL32(60, 220, 120, 255) : dimCol;
                        cdl->AddCircleFilled(ImVec2(circleX, (togMin.y + togMax.y) / 2.0f), 7.0f, circCol, 16);
                        return togMax;
                    };

                    {
                        float cardH = 80.0f;
                        cdl->AddRectFilled(ImVec2(sX, y), ImVec2(sX + cardW, y + cardH), cardBg, 6.0f);
                        cdl->AddRect(ImVec2(sX, y), ImVec2(sX + cardW, y + cardH), cardBorder, 6.0f, 0, 1.0f);
                        float curY = drawSectionHeader(sX, y, "Context Menu");

                        cdl->AddText(ImVec2(sX + 14, curY + 6), labelCol, "Black Hole submenu");

                        ImVec2 bhInstMin(sX + 145, curY);
                        ImVec2 bhInstMax(sX + 145 + 70, curY + 28);
                        bool bhInstHov = ImGui::IsMouseHoveringRect(bhInstMin, bhInstMax);
                        cdl->AddRectFilled(bhInstMin, bhInstMax, bhInstHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_SIDEBAR_BG), 4.0f);
                        cdl->AddRect(bhInstMin, bhInstMax, cardBorder, 4.0f, 0, 1.0f);
                        ImVec2 bhInstT = ImGui::CalcTextSize("Install");
                        cdl->AddText(ImVec2((bhInstMin.x + bhInstMax.x - bhInstT.x) / 2, (bhInstMin.y + bhInstMax.y - bhInstT.y) / 2),
                            labelCol, "Install");

                        ImVec2 bhUninstMin(sX + 221, curY);
                        ImVec2 bhUninstMax(sX + 221 + 70, curY + 28);
                        bool bhUninstHov = ImGui::IsMouseHoveringRect(bhUninstMin, bhUninstMax);
                        cdl->AddRectFilled(bhUninstMin, bhUninstMax, bhUninstHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_SIDEBAR_BG), 4.0f);
                        cdl->AddRect(bhUninstMin, bhUninstMax, cardBorder, 4.0f, 0, 1.0f);
                        ImVec2 bhUninstT = ImGui::CalcTextSize("Uninstall");
                        cdl->AddText(ImVec2((bhUninstMin.x + bhUninstMax.x - bhUninstT.x) / 2, (bhUninstMin.y + bhUninstMax.y - bhUninstT.y) / 2),
                            labelCol, "Uninstall");

                        bool bhInstalled = g_installStatus.load();
                        cdl->AddText(ImVec2(sX + 297, curY + 6),
                            bhInstalled ? IM_COL32(60, 180, 80, 255) : IM_COL32(180, 60, 60, 255),
                            bhInstalled ? "INSTALLED" : "NOT INSTALLED");

                        ImVec2 bhHelpMin(sX + 395, curY + 6);
                        ImVec2 bhHelpMax(sX + 409, curY + 22);
                        bool bhHelpHov = ImGui::IsMouseHoveringRect(bhHelpMin, bhHelpMax);
                        cdl->AddText(ImVec2(bhHelpMin.x, bhHelpMin.y),
                            bhHelpHov ? headerCol : dimCol, "(?)");
                        if (bhHelpHov) {
                            ImGui::BeginTooltip();
                            ImGui::PushTextWrapPos(350.0f);
                            ImGui::TextColored(ImVec4(0.9f, 0.8f, 0.2f, 1.0f), "BLACK HOLE CONTEXT MENU");
                            ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.92f, 1.0f),
                                "Adds a \"Black Hole\" submenu to the right-click context menu with: "
                                "Force Delete, Force Delete & Scan, and Analyze & Inspect. "
                                "Requires BlackHoleShell.dll in the same folder as the exe.");
                            ImGui::PopTextWrapPos();
                            ImGui::EndTooltip();
                        }

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            if (m.x >= bhInstMin.x && m.x <= bhInstMax.x && m.y >= bhInstMin.y && m.y <= bhInstMax.y) {
                                bool ok = InstallContextMenu();
                                g_installStatus.store(ok);
                                PushNotification(ok ? L"INSTALLED" : L"FAILED",
                                    L"Black Hole context menu", !ok);
                            }
                            if (m.x >= bhUninstMin.x && m.x <= bhUninstMax.x && m.y >= bhUninstMin.y && m.y <= bhUninstMax.y) {
                                bool ok = UninstallContextMenu();
                                g_installStatus.store(!ok);
                                PushNotification(ok ? L"UNINSTALLED" : L"FAILED",
                                    L"Black Hole context menu removed", false);
                            }
                        }

                        y += cardH + 10.0f;
                    }

                    {
                        float cardH = 110.0f;
                        cdl->AddRectFilled(ImVec2(sX, y), ImVec2(sX + cardW, y + cardH), cardBg, 6.0f);
                        cdl->AddRect(ImVec2(sX, y), ImVec2(sX + cardW, y + cardH), cardBorder, 6.0f, 0, 1.0f);
                        float curY = drawSectionHeader(sX, y, "Safety");

                        cdl->AddText(ImVec2(sX + 14, curY + 2), labelCol, "Override Safety:");

                        float safeTogX = sX + 140;
                        ImVec2 overTogEnd = drawToggle(safeTogX, curY, g_overrideActive.load());
                        cdl->AddText(ImVec2(overTogEnd.x + 12, curY + 2),
                            g_overrideActive.load() ? IM_COL32(60, 220, 120, 255) : dimCol,
                            g_overrideActive.load() ? "SAFE [ON]" : "SAFE [OFF]");

                        ImVec2 safeLabelSz = ImGui::CalcTextSize(g_overrideActive.load() ? "SAFE [ON]" : "SAFE [OFF]");
                        float helpX = overTogEnd.x + 12 + safeLabelSz.x + 10;
                        ImVec2 helpMin(helpX, curY + 2);
                        ImVec2 helpMax(helpX + 14, curY + 18);
                        bool helpHov = ImGui::IsMouseHoveringRect(helpMin, helpMax);
                        ImU32 helpCol = helpHov ? headerCol : dimCol;
                        cdl->AddText(ImVec2(helpX, curY + 2), helpCol, "(?)");
                        if (helpHov) {
                            ImGui::BeginTooltip();
                            ImGui::PushTextWrapPos(350.0f);
                            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "DANGER MODE");
                            ImGui::SameLine();
                            ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.92f, 1.0f), ": Bypasses the safety blacklist to allow deletion of critical Windows system files.");
                            ImGui::Spacing();
                            ImGui::TextColored(ImVec4(0.85f, 0.85f, 0.88f, 1.0f),
                                "The developers accept ABSOLUTELY ZERO LIABILITY for reckless or uneducated usage. "
                                "If you delete a critical system component and cause an OS crash, boot loop, or "
                                "Blue Screen of Death (BSOD), you are entirely on your own. "
                                "You assume 100%% responsibility for your actions.");
                            ImGui::PopTextWrapPos();
                            ImGui::EndTooltip();
                        }

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            if (m.x >= safeTogX && m.x <= safeTogX + 52 && m.y >= curY && m.y <= curY + 22) {
                                if (!g_overrideActive.load()) {
                                    const char* expected = "I assume full liability";
                                    if (strcmp(g_overrideInput, expected) == 0) {
                                        g_overrideActive.store(true);
                                        g_phraseWrong = false;
                                        BlackHole::GetLogger().LogOverride(true, L"I assume full liability");
                                    } else {
                                        g_phraseWrong = true;
                                        g_phraseWrongTimer = 2.0f;
                                    }
                                } else {
                                    g_overrideActive.store(false);
                                    BlackHole::GetLogger().LogOverride(false);
                                }
                            }
                        }

                        float phraseY = curY + 34.0f;
                        cdl->AddText(ImVec2(sX + 14, phraseY), labelCol, "Phrase:");

                        ImVec2 pbMin(sX + 75, phraseY - 4);
                        ImVec2 pbMax(sX + 75 + 320, phraseY + 18);
                        ImU32 phraseBorder = cardBorder;
                        if (g_phraseWrong && g_phraseWrongTimer > 0.0f)
                            phraseBorder = IM_COL32(180, 50, 50, 255);
                        cdl->AddRectFilled(pbMin, pbMax, Vec4ToU32(CLR_SIDEBAR_BG), 4.0f);
                        cdl->AddRect(pbMin, pbMax, phraseBorder, 4.0f, 0, 1.0f);

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            g_phraseFocused = (m.x >= pbMin.x && m.x <= pbMax.x && m.y >= pbMin.y && m.y <= pbMax.y);
                            if (!g_phraseFocused) g_phraseWrong = false;
                        }

                        std::string pi(g_overrideInput);
                        if (!pi.empty()) {
                            ImVec4 txtCol = (g_phraseWrong && g_phraseWrongTimer > 0.0f)
                                ? ImVec4(0.85f, 0.3f, 0.3f, 1.0f) : ImVec4(0.92f, 0.92f, 0.94f, 1.0f);
                            cdl->AddText(ImVec2(pbMin.x + 8, pbMin.y + 3), Vec4ToU32(txtCol), pi.c_str());
                        } else {
                            cdl->AddText(ImVec2(pbMin.x + 8, pbMin.y + 3), dimCol, "I assume full liability");
                        }
                        if (g_phraseFocused) {
                            ImVec2 txtSz = ImGui::CalcTextSize(pi.c_str());
                            float cursorX = pbMin.x + 8 + txtSz.x;
                            if (fmodf((float)ImGui::GetTime(), 1.0f) < 0.5f)
                                cdl->AddLine(ImVec2(cursorX, pbMin.y + 3), ImVec2(cursorX, pbMin.y + 17), headerCol, 1.0f);
                        }
                        if (g_phraseWrongTimer > 0.0f) {
                            ImVec2 esz = ImGui::CalcTextSize("Wrong phrase");
                            cdl->AddText(ImVec2(pbMax.x + 8, pbMin.y + 3), IM_COL32(180, 50, 50, 255), "Wrong phrase");
                        }
                        y += cardH + 10.0f;
                    }

                    {
                        float cardH = 68.0f;
                        cdl->AddRectFilled(ImVec2(sX, y), ImVec2(sX + cardW, y + cardH), cardBg, 6.0f);
                        cdl->AddRect(ImVec2(sX, y), ImVec2(sX + cardW, y + cardH), cardBorder, 6.0f, 0, 1.0f);
                        float curY = drawSectionHeader(sX, y, "Deletion");

                        cdl->AddText(ImVec2(sX + 14, curY + 2), labelCol, "Send to Recycle Bin:");

                        float rcTogX = sX + 140;
                        ImVec2 rcTogEnd = drawToggle(rcTogX, curY, g_sendToRecycleBin);
                        cdl->AddText(ImVec2(rcTogEnd.x + 12, curY + 2),
                            g_sendToRecycleBin ? IM_COL32(60, 220, 120, 255) : dimCol,
                            g_sendToRecycleBin ? "TRASH [ON]" : "TRASH [OFF]");

                        ImVec2 rcLabelSz = ImGui::CalcTextSize(g_sendToRecycleBin ? "TRASH [ON]" : "TRASH [OFF]");
                        float rcHelpX = rcTogEnd.x + 12 + rcLabelSz.x + 10;
                        ImVec2 rcHelpMin(rcHelpX, curY + 2);
                        ImVec2 rcHelpMax(rcHelpX + 14, curY + 18);
                        bool rcHelpHov = ImGui::IsMouseHoveringRect(rcHelpMin, rcHelpMax);
                        ImU32 rcHelpCol = rcHelpHov ? headerCol : dimCol;
                        cdl->AddText(ImVec2(rcHelpX, curY + 2), rcHelpCol, "(?)");
                        if (rcHelpHov) {
                            ImGui::BeginTooltip();
                            ImGui::PushTextWrapPos(350.0f);
                            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "RECYCLE BIN MODE");
                            ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.92f, 1.0f),
                                ": Instead of permanently shredding files, move them to the Recycle Bin folder.");
                            ImGui::Spacing();
                            ImGui::TextColored(ImVec4(0.85f, 0.85f, 0.88f, 1.0f),
                                "When enabled, deleted files can be restored via the Undo button in the Logs tab. "
                                "Files are stored in the BlackHole Trash folder until permanently purged.");
                            ImGui::PopTextWrapPos();
                            ImGui::EndTooltip();
                        }

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            if (m.x >= rcTogX && m.x <= rcTogX + 52 && m.y >= curY && m.y <= curY + 22) {
                                g_sendToRecycleBin = !g_sendToRecycleBin;
                                SaveConfig();
                            }
                        }
                        y += cardH + 10.0f;
                    }

                    {
                        float cardH = 212.0f;
                        cdl->AddRectFilled(ImVec2(sX, y), ImVec2(sX + cardW, y + cardH), cardBg, 6.0f);
                        cdl->AddRect(ImVec2(sX, y), ImVec2(sX + cardW, y + cardH), cardBorder, 6.0f, 0, 1.0f);
                        float curY = drawSectionHeader(sX, y, "Appearance");

                        cdl->AddText(ImVec2(sX + 14, curY + 2), labelCol, "Sidebar Glow:");
                        float sgTogX = sX + 140;
                        ImVec2 sgTogEnd = drawToggle(sgTogX, curY, g_sidebarGlowEnabled);
                        cdl->AddText(ImVec2(sgTogEnd.x + 12, curY + 2),
                            g_sidebarGlowEnabled ? IM_COL32(60, 220, 120, 255) : dimCol,
                            g_sidebarGlowEnabled ? "ON" : "OFF");

                        if (g_sidebarGlowEnabled) {
                            float cpX = sgTogEnd.x + 60;
                            ImGui::SetCursorPos(ImVec2(cpX - cPos.x, curY - cPos.y + 2));
                            ImVec4 curCol(g_sidebarGlowColor[0], g_sidebarGlowColor[1], g_sidebarGlowColor[2], 1.0f);
                            ImGui::PushStyleColor(ImGuiCol_Button, curCol);
                            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(g_sidebarGlowColor[0]*1.2f, g_sidebarGlowColor[1]*1.2f, g_sidebarGlowColor[2]*1.2f, 1.0f));
                            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
                            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14, 4));
                            char sgBtnId[32];
                            snprintf(sgBtnId, sizeof(sgBtnId), "##sgColor##%d", (int)curY);
                            bool sgSwatchClicked = ImGui::ColorButton(sgBtnId, ImVec4(g_sidebarGlowColor[0], g_sidebarGlowColor[1], g_sidebarGlowColor[2], 1.0f),
                                ImGuiColorEditFlags_NoPicker | ImGuiColorEditFlags_NoTooltip, ImVec2(24, 18));
                            ImGui::PopStyleVar(2);
                            ImGui::PopStyleColor(2);

                            static bool sgOpen = false;
                            if (sgSwatchClicked) sgOpen = !sgOpen;
                            if (sgOpen) {
                                ImVec2 panelPos(wPos.x + cpX + 30, wPos.y + curY);
                                ImGui::SetNextWindowPos(panelPos, ImGuiCond_FirstUseEver);
                                ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
                                ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 14.0f);
                                ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
                                ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.08f, 0.08f, 0.10f, 0.96f));
                                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.18f, 0.18f, 0.22f, 1.0f));
                                ImGui::Begin("##sgPicker", &sgOpen, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoNav);

                                float panelW = 220;
                                float svW = panelW - 20, svH = 180;
                                float hueH = 12;
                                float padX = 10;

                                float curHue = 0.0f, curSat = 0.0f, curVal = 0.0f;
                                {
                                    float mx = ImMax(g_sidebarGlowColor[0], ImMax(g_sidebarGlowColor[1], g_sidebarGlowColor[2]));
                                    float mn = ImMin(g_sidebarGlowColor[0], ImMin(g_sidebarGlowColor[1], g_sidebarGlowColor[2]));
                                    float d = mx - mn;
                                    curVal = mx;
                                    if (mx > 0.0f) curSat = d / mx;
                                    if (d > 0.0f) {
                                        if (mx == g_sidebarGlowColor[0]) curHue = (g_sidebarGlowColor[1] - g_sidebarGlowColor[2]) / d + (g_sidebarGlowColor[1] < g_sidebarGlowColor[2] ? 6.0f : 0.0f);
                                        else if (mx == g_sidebarGlowColor[1]) curHue = (g_sidebarGlowColor[2] - g_sidebarGlowColor[0]) / d + 2.0f;
                                        else curHue = (g_sidebarGlowColor[0] - g_sidebarGlowColor[1]) / d + 4.0f;
                                        curHue /= 6.0f;
                                    }
                                }

                                ImGui::SetCursorPosX(padX);
                                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6);
                                ImVec2 svStart = ImGui::GetCursorScreenPos();
                                ImDrawList* pdl = ImGui::GetWindowDrawList();
                                ImVec2 svEnd(svStart.x + svW, svStart.y + svH);
                                pdl->AddRectFilled(svStart, svEnd, IM_COL32(80, 80, 80, 255), 8.0f);
                                for (int y = 0; y < (int)svH; y++) {
                                    for (int x = 0; x < (int)svW; x++) {
                                        float s = (float)x / svW;
                                        float v = 1.0f - (float)y / svH;
                                        float r, g, b;
                                        ImGui::ColorConvertHSVtoRGB(curHue, s, v, r, g, b);
                                        pdl->AddRectFilled(ImVec2(svStart.x + x, svStart.y + y),
                                            ImVec2(svStart.x + x + 1, svStart.y + y + 1), ImColor(r, g, b));
                                    }
                                }
                                {
                                    float cx = svStart.x + curSat * svW;
                                    float cy = svStart.y + (1.0f - curVal) * svH;
                                    pdl->AddCircle(ImVec2(cx, cy), 6.0f, IM_COL32(255, 255, 255, 255), 0, 2.0f);
                                    pdl->AddCircle(ImVec2(cx, cy), 4.5f, IM_COL32(0, 0, 0, 0), 0, 2.0f);
                                }
                                ImGui::InvisibleButton("##svArea", ImVec2(svW, svH));
                                if (ImGui::IsItemActive()) {
                                    ImVec2 m = ImGui::GetIO().MousePos;
                                    float s = ImClamp((m.x - svStart.x) / svW, 0.0f, 1.0f);
                                    float v = 1.0f - ImClamp((m.y - svStart.y) / svH, 0.0f, 1.0f);
                                    ImGui::ColorConvertHSVtoRGB(curHue, s, v, g_sidebarGlowColor[0], g_sidebarGlowColor[1], g_sidebarGlowColor[2]);
                                    SaveConfig();
                                }

                                ImGui::SetCursorPosX(padX);
                                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6);
                                ImVec2 hueStart = ImGui::GetCursorScreenPos();
                                for (int x = 0; x < (int)svW; x++) {
                                    float h = (float)x / svW;
                                    float r, g, b;
                                    ImGui::ColorConvertHSVtoRGB(h, 1.0f, 1.0f, r, g, b);
                                    pdl->AddRectFilled(ImVec2(hueStart.x + x, hueStart.y),
                                        ImVec2(hueStart.x + x + 1, hueStart.y + hueH), ImColor(r, g, b));
                                }
                                {
                                    float hx = hueStart.x + curHue * svW;
                                    pdl->AddCircleFilled(ImVec2(hx, hueStart.y + hueH * 0.5f), 5.0f, IM_COL32(255, 255, 255, 255));
                                    pdl->AddCircle(ImVec2(hx, hueStart.y + hueH * 0.5f), 5.0f, IM_COL32(100, 100, 110, 255), 0, 1.5f);
                                }
                                ImGui::SetCursorPosX(padX);
                                ImGui::InvisibleButton("##hueBar", ImVec2(svW, hueH + 4));
                                if (ImGui::IsItemActive()) {
                                    ImVec2 m = ImGui::GetIO().MousePos;
                                    float h = ImClamp((m.x - hueStart.x) / svW, 0.0f, 0.999f);
                                    ImGui::ColorConvertHSVtoRGB(h, curSat, curVal, g_sidebarGlowColor[0], g_sidebarGlowColor[1], g_sidebarGlowColor[2]);
                                    SaveConfig();
                                }

                                ImGui::SetCursorPosX(padX);
                                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
                                ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
                                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 5));
                                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.14f, 0.14f, 0.17f, 1.0f));
                                ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.18f, 0.18f, 0.22f, 1.0f));
                                ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0.22f, 0.22f, 0.26f, 1.0f));
                                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.82f, 0.82f, 0.85f, 1.0f));
                                ImGui::Text("Hex");
                                ImGui::SameLine(padX + 30);
                                ImGui::PushItemWidth(svW - 50);
                                char hexBuf[16];
                                int ri = (int)(g_sidebarGlowColor[0] * 255.0f + 0.5f);
                                int gi = (int)(g_sidebarGlowColor[1] * 255.0f + 0.5f);
                                int bi = (int)(g_sidebarGlowColor[2] * 255.0f + 0.5f);
                                snprintf(hexBuf, sizeof(hexBuf), "%02X%02X%02X", ri, gi, bi);
                                char hexInput[16];
                                snprintf(hexInput, sizeof(hexInput), "#%s", hexBuf);
                                if (ImGui::InputText("##hexInput", hexInput, sizeof(hexInput), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase)) {
                                    if (hexInput[0] == '#' && strlen(hexInput) == 7) {
                                        unsigned int hex = 0;
                                        if (sscanf(hexInput + 1, "%X", &hex) == 1) {
                                            g_sidebarGlowColor[0] = ((hex >> 16) & 0xFF) / 255.0f;
                                            g_sidebarGlowColor[1] = ((hex >> 8) & 0xFF) / 255.0f;
                                            g_sidebarGlowColor[2] = (hex & 0xFF) / 255.0f;
                                            SaveConfig();
                                        }
                                    }
                                }
                                ImGui::PopItemWidth();
                                ImGui::SameLine();
                                ImVec4 previewCol(g_sidebarGlowColor[0], g_sidebarGlowColor[1], g_sidebarGlowColor[2], 1.0f);
                                ImGui::ColorButton("##previewSwatch", previewCol, 0, ImVec2(20, 20));
                                ImGui::PopStyleColor(4);
                                ImGui::PopStyleVar(2);

                                ImGui::Dummy(ImVec2(panelW, 1));
                                ImGui::End();
                                ImGui::PopStyleColor(2);
                                ImGui::PopStyleVar(3);
                            }
                        }

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            if (m.x >= sgTogX && m.x <= sgTogX + 52 && m.y >= curY && m.y <= curY + 22) {
                                g_sidebarGlowEnabled = !g_sidebarGlowEnabled;
                                SaveConfig();
                            }
                        }

                        curY += 32.0f;
                        cdl->AddText(ImVec2(sX + 14, curY + 2), labelCol, "Glow Line:");
                        float lgTogX = sX + 140;
                        ImVec2 lgTogEnd = drawToggle(lgTogX, curY, g_lineGlowEnabled);
                        cdl->AddText(ImVec2(lgTogEnd.x + 12, curY + 2),
                            g_lineGlowEnabled ? IM_COL32(60, 220, 120, 255) : dimCol,
                            g_lineGlowEnabled ? "ON" : "OFF");

                        if (g_lineGlowEnabled) {
                            float cpX = lgTogEnd.x + 60;
                            ImGui::SetCursorPos(ImVec2(cpX - cPos.x, curY - cPos.y + 2));
                            ImVec4 curCol(g_lineGlowColor[0], g_lineGlowColor[1], g_lineGlowColor[2], 1.0f);
                            ImGui::PushStyleColor(ImGuiCol_Button, curCol);
                            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(g_lineGlowColor[0]*1.2f, g_lineGlowColor[1]*1.2f, g_lineGlowColor[2]*1.2f, 1.0f));
                            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
                            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14, 4));
                            char lgBtnId2[32];
                            snprintf(lgBtnId2, sizeof(lgBtnId2), "##lgColor2##%d", (int)curY);
                            bool lgSwatchClicked = ImGui::ColorButton(lgBtnId2, ImVec4(g_lineGlowColor[0], g_lineGlowColor[1], g_lineGlowColor[2], 1.0f),
                                ImGuiColorEditFlags_NoPicker | ImGuiColorEditFlags_NoTooltip, ImVec2(24, 18));
                            ImGui::PopStyleVar(2);
                            ImGui::PopStyleColor(2);

                            static bool lgOpen = false;
                            if (lgSwatchClicked) lgOpen = !lgOpen;
                            if (lgOpen) {
                                ImVec2 panelPos(wPos.x + cpX + 30, wPos.y + curY);
                                ImGui::SetNextWindowPos(panelPos, ImGuiCond_FirstUseEver);
                                ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
                                ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 14.0f);
                                ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
                                ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.08f, 0.08f, 0.10f, 0.96f));
                                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.18f, 0.18f, 0.22f, 1.0f));
                                ImGui::Begin("##lgPicker", &lgOpen, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoNav);

                                float panelW = 220;
                                float svW2 = panelW - 20, svH2 = 180;
                                float hueH2 = 12;
                                float padX = 10;

                                float curHue2 = 0.0f, curSat2 = 0.0f, curVal2 = 0.0f;
                                {
                                    float mx = ImMax(g_lineGlowColor[0], ImMax(g_lineGlowColor[1], g_lineGlowColor[2]));
                                    float mn = ImMin(g_lineGlowColor[0], ImMin(g_lineGlowColor[1], g_lineGlowColor[2]));
                                    float d = mx - mn;
                                    curVal2 = mx;
                                    if (mx > 0.0f) curSat2 = d / mx;
                                    if (d > 0.0f) {
                                        if (mx == g_lineGlowColor[0]) curHue2 = (g_lineGlowColor[1] - g_lineGlowColor[2]) / d + (g_lineGlowColor[1] < g_lineGlowColor[2] ? 6.0f : 0.0f);
                                        else if (mx == g_lineGlowColor[1]) curHue2 = (g_lineGlowColor[2] - g_lineGlowColor[0]) / d + 2.0f;
                                        else curHue2 = (g_lineGlowColor[0] - g_lineGlowColor[1]) / d + 4.0f;
                                        curHue2 /= 6.0f;
                                    }
                                }

                                ImGui::SetCursorPosX(padX);
                                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6);
                                ImVec2 svStart2 = ImGui::GetCursorScreenPos();
                                ImDrawList* pdl = ImGui::GetWindowDrawList();
                                ImVec2 svEnd2(svStart2.x + svW2, svStart2.y + svH2);
                                pdl->AddRectFilled(svStart2, svEnd2, IM_COL32(80, 80, 80, 255), 8.0f);
                                for (int y = 0; y < (int)svH2; y++) {
                                    for (int x = 0; x < (int)svW2; x++) {
                                        float s = (float)x / svW2;
                                        float v = 1.0f - (float)y / svH2;
                                        float r, g, b;
                                        ImGui::ColorConvertHSVtoRGB(curHue2, s, v, r, g, b);
                                        pdl->AddRectFilled(ImVec2(svStart2.x + x, svStart2.y + y),
                                            ImVec2(svStart2.x + x + 1, svStart2.y + y + 1), ImColor(r, g, b));
                                    }
                                }
                                {
                                    float cx = svStart2.x + curSat2 * svW2;
                                    float cy = svStart2.y + (1.0f - curVal2) * svH2;
                                    pdl->AddCircle(ImVec2(cx, cy), 6.0f, IM_COL32(255, 255, 255, 255), 0, 2.0f);
                                    pdl->AddCircle(ImVec2(cx, cy), 4.5f, IM_COL32(0, 0, 0, 0), 0, 2.0f);
                                }
                                ImGui::InvisibleButton("##svAreaLg", ImVec2(svW2, svH2));
                                if (ImGui::IsItemActive()) {
                                    ImVec2 m = ImGui::GetIO().MousePos;
                                    float s = ImClamp((m.x - svStart2.x) / svW2, 0.0f, 1.0f);
                                    float v = 1.0f - ImClamp((m.y - svStart2.y) / svH2, 0.0f, 1.0f);
                                    ImGui::ColorConvertHSVtoRGB(curHue2, s, v, g_lineGlowColor[0], g_lineGlowColor[1], g_lineGlowColor[2]);
                                    SaveConfig();
                                }

                                ImGui::SetCursorPosX(padX);
                                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6);
                                ImVec2 hueStart2 = ImGui::GetCursorScreenPos();
                                for (int x = 0; x < (int)svW2; x++) {
                                    float h = (float)x / svW2;
                                    float r, g, b;
                                    ImGui::ColorConvertHSVtoRGB(h, 1.0f, 1.0f, r, g, b);
                                    pdl->AddRectFilled(ImVec2(hueStart2.x + x, hueStart2.y),
                                        ImVec2(hueStart2.x + x + 1, hueStart2.y + hueH2), ImColor(r, g, b));
                                }
                                {
                                    float hx = hueStart2.x + curHue2 * svW2;
                                    pdl->AddCircleFilled(ImVec2(hx, hueStart2.y + hueH2 * 0.5f), 5.0f, IM_COL32(255, 255, 255, 255));
                                    pdl->AddCircle(ImVec2(hx, hueStart2.y + hueH2 * 0.5f), 5.0f, IM_COL32(100, 100, 110, 255), 0, 1.5f);
                                }
                                ImGui::SetCursorPosX(padX);
                                ImGui::InvisibleButton("##hueBarLg", ImVec2(svW2, hueH2 + 4));
                                if (ImGui::IsItemActive()) {
                                    ImVec2 m = ImGui::GetIO().MousePos;
                                    float h = ImClamp((m.x - hueStart2.x) / svW2, 0.0f, 0.999f);
                                    ImGui::ColorConvertHSVtoRGB(h, curSat2, curVal2, g_lineGlowColor[0], g_lineGlowColor[1], g_lineGlowColor[2]);
                                    SaveConfig();
                                }

                                ImGui::SetCursorPosX(padX);
                                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
                                ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
                                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 5));
                                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.14f, 0.14f, 0.17f, 1.0f));
                                ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.18f, 0.18f, 0.22f, 1.0f));
                                ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0.22f, 0.22f, 0.26f, 1.0f));
                                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.82f, 0.82f, 0.85f, 1.0f));
                                ImGui::Text("Hex");
                                ImGui::SameLine(padX + 30);
                                ImGui::PushItemWidth(svW2 - 50);
                                char hexBuf2[16];
                                int ri2 = (int)(g_lineGlowColor[0] * 255.0f + 0.5f);
                                int gi2 = (int)(g_lineGlowColor[1] * 255.0f + 0.5f);
                                int bi2 = (int)(g_lineGlowColor[2] * 255.0f + 0.5f);
                                snprintf(hexBuf2, sizeof(hexBuf2), "%02X%02X%02X", ri2, gi2, bi2);
                                char hexInput2[16];
                                snprintf(hexInput2, sizeof(hexInput2), "#%s", hexBuf2);
                                if (ImGui::InputText("##hexInputLg", hexInput2, sizeof(hexInput2), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase)) {
                                    if (hexInput2[0] == '#' && strlen(hexInput2) == 7) {
                                        unsigned int hex = 0;
                                        if (sscanf(hexInput2 + 1, "%X", &hex) == 1) {
                                            g_lineGlowColor[0] = ((hex >> 16) & 0xFF) / 255.0f;
                                            g_lineGlowColor[1] = ((hex >> 8) & 0xFF) / 255.0f;
                                            g_lineGlowColor[2] = (hex & 0xFF) / 255.0f;
                                            SaveConfig();
                                        }
                                    }
                                }
                                ImGui::PopItemWidth();
                                ImGui::SameLine();
                                ImVec4 previewCol2(g_lineGlowColor[0], g_lineGlowColor[1], g_lineGlowColor[2], 1.0f);
                                ImGui::ColorButton("##previewSwatchLg", previewCol2, 0, ImVec2(20, 20));
                                ImGui::PopStyleColor(4);
                                ImGui::PopStyleVar(2);

                                ImGui::Dummy(ImVec2(panelW, 1));
                                ImGui::End();
                                ImGui::PopStyleColor(2);
                                ImGui::PopStyleVar(3);
                            }
                        }

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            if (m.x >= lgTogX && m.x <= lgTogX + 52 && m.y >= curY && m.y <= curY + 22) {
                                g_lineGlowEnabled = !g_lineGlowEnabled;
                                SaveConfig();
                            }
                        }

                        curY += 32.0f;
                        cdl->AddText(ImVec2(sX + 14, curY + 2), labelCol, "Hide Sidebar:");
                        float hsTogX = sX + 140;
                        ImVec2 hsTogEnd = drawToggle(hsTogX, curY, g_hideSidebar);
                        cdl->AddText(ImVec2(hsTogEnd.x + 12, curY + 2),
                            g_hideSidebar ? IM_COL32(60, 220, 120, 255) : dimCol,
                            g_hideSidebar ? "ON" : "OFF");

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            if (m.x >= hsTogX && m.x <= hsTogX + 52 && m.y >= curY && m.y <= curY + 22) {
                                g_hideSidebar = !g_hideSidebar;
                                SaveConfig();
                            }
                        }

                        curY += 32.0f;
                        cdl->AddText(ImVec2(sX + 14, curY + 2), labelCol, "Transparent:");
                        float trTogX = sX + 140;
                        ImVec2 trTogEnd = drawToggle(trTogX, curY, g_windowTransparent);
                        cdl->AddText(ImVec2(trTogEnd.x + 12, curY + 2),
                            g_windowTransparent ? IM_COL32(60, 220, 120, 255) : dimCol,
                            g_windowTransparent ? "ON" : "OFF");

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            if (m.x >= trTogX && m.x <= trTogX + 52 && m.y >= curY && m.y <= curY + 22) {
                                g_windowTransparent = !g_windowTransparent;
                                ApplyWindowTransparency();
                                SaveConfig();
                            }
                        }

                        if (g_windowTransparent) {
                            float sliderX = sX + 235;
                            float sliderW = 150.0f;
                            float sliderY = curY + 10.0f;
                            float lineY = sliderY;
                            float lineH = 5.0f;
                            float grabR = 6.0f;

                            float t = (g_windowAlpha - 0.15f) / (1.0f - 0.15f);

                            ImVec2 lineMin(sliderX, lineY);
                            ImVec2 lineMax(sliderX + sliderW, lineY + lineH);
                            cdl->AddRectFilled(lineMin, lineMax, Vec4ToU32(CLR_STROKE), 1.0f);

                            float fillW = sliderW * t;
                            cdl->AddRectFilled(lineMin, ImVec2(lineMin.x + fillW, lineY + lineH),
                                Vec4ToU32(CLR_ACCENT), 1.0f);

                            float grabX = sliderX + fillW;
                            float grabY = lineY + lineH * 0.5f;

                            bool isHovering = io.MousePos.x >= sliderX - grabR && io.MousePos.x <= sliderX + sliderW + grabR
                                && io.MousePos.y >= lineY - grabR && io.MousePos.y <= lineY + lineH + grabR;

                            static bool sliderDragging = false;
                            if (isHovering && io.MouseClicked[0])
                                sliderDragging = true;
                            if (!io.MouseDown[0])
                                sliderDragging = false;

                            if (sliderDragging) {
                                float mx = io.MousePos.x;
                                float newT = (mx - sliderX) / sliderW;
                                if (newT < 0.0f) newT = 0.0f;
                                if (newT > 1.0f) newT = 1.0f;
                                float newAlpha = 0.15f + newT * (1.0f - 0.15f);
                                if (newAlpha != g_windowAlpha) {
                                    g_windowAlpha = newAlpha;
                                    g_applyTransparencyNextFrame = true;
                                    SaveConfig();
                                }
                            }

                            ImU32 grabCol = (isHovering || sliderDragging)
                                ? Vec4ToU32(ImVec4(0.85f, 0.80f, 1.0f, 1.0f))
                                : Vec4ToU32(CLR_ACCENT);
                            cdl->AddCircleFilled(ImVec2(grabX, grabY), grabR, Vec4ToU32(CLR_STROKE), 16);
                            cdl->AddCircleFilled(ImVec2(grabX, grabY), grabR - 2.0f, grabCol, 16);

                            char alphaBuf[16];
                            snprintf(alphaBuf, sizeof(alphaBuf), "%.0f%%", g_windowAlpha * 100.0f);
                            cdl->AddText(ImVec2(sliderX + sliderW + 6.0f, curY + 2), dimCol, alphaBuf);
                        }

                        curY += 32.0f;
                        cdl->AddText(ImVec2(sX + 14, curY + 2), labelCol, "Resizable:");
                        float rsTogX = sX + 140;
                        ImVec2 rsTogEnd = drawToggle(rsTogX, curY, g_resizableWindow);
                        cdl->AddText(ImVec2(rsTogEnd.x + 12, curY + 2),
                            g_resizableWindow ? IM_COL32(60, 220, 120, 255) : dimCol,
                            g_resizableWindow ? "ON" : "OFF");

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            if (m.x >= rsTogX && m.x <= rsTogX + 52 && m.y >= curY && m.y <= curY + 22) {
                                g_resizableWindow = !g_resizableWindow;
                                ApplyResizableStyle();
                                SaveConfig();
                            }
                        }

                        y += cardH + 10.0f;
                    }

                    {
                        float cardH = 70.0f;
                        cdl->AddRectFilled(ImVec2(sX, y), ImVec2(sX + cardW, y + cardH), cardBg, 6.0f);
                        cdl->AddRect(ImVec2(sX, y), ImVec2(sX + cardW, y + cardH), cardBorder, 6.0f, 0, 1.0f);
                        float curY = drawSectionHeader(sX, y, "Monitoring");

                        cdl->AddText(ImVec2(sX + 14, curY + 2), labelCol, "Install Monitor:");
                        float imTogX = sX + 140;
                        ImVec2 imTogEnd = drawToggle(imTogX, curY, g_installMonitorEnabled);

                        const char* imStatusText = g_installMonitorEnabled ? "ACTIVE" : "INACTIVE";
                        ImU32 imStatusCol = g_installMonitorEnabled
                            ? IM_COL32(60, 220, 120, 255) : dimCol;
                        ImVec2 imStatusSz = ImGui::CalcTextSize(imStatusText);
                        cdl->AddText(ImVec2(imTogEnd.x + 12, curY + 2), imStatusCol, imStatusText);

                        float imHelpX = imTogEnd.x + 12.0f + imStatusSz.x + 8.0f;
                        ImVec2 imHelpMin(imHelpX, curY + 2);
                        ImVec2 imHelpMax(imHelpX + 14, curY + 18);
                        bool imHelpHov = ImGui::IsMouseHoveringRect(imHelpMin, imHelpMax);
                        ImU32 imHelpCol = imHelpHov ? headerCol : dimCol;
                        cdl->AddText(ImVec2(imHelpX, curY + 2), imHelpCol, "(?)");
                        if (imHelpHov) {
                            ImGui::BeginTooltip();
                            ImGui::PushTextWrapPos(350.0f);
                            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "INSTALLATION MONITOR");
                            ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.92f, 1.0f),
                                "Monitors new installations in real-time. When an installer is detected, "
                                "tracks all files and registry keys it creates.");
                            ImGui::Spacing();
                            ImGui::TextColored(ImVec4(0.85f, 0.85f, 0.88f, 1.0f),
                                "Logs are saved to %LOCALAPPDATA%\\BlackHole\\InstallLogs\\ so you can "
                                "review and purge remnants later.");
                            ImGui::PopTextWrapPos();
                            ImGui::EndTooltip();
                        }

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            if (m.x >= imTogX && m.x <= imTogX + 52 && m.y >= curY && m.y <= curY + 22) {
                                g_installMonitorEnabled = !g_installMonitorEnabled;
                                if (g_installMonitorEnabled)
                                    BlackHole::GetInstallMonitor().StartMonitoring();
                                else
                                    std::thread([]() { BlackHole::GetInstallMonitor().StopMonitoring(); }).detach();
                                SaveConfig();
                            }
                        }

                        y += cardH + 10.0f;
                    }

                    // Draw scrollbar indicator if content overflows
                    {
                        float settingsContentH = 620.0f;
                        float settingsVisibleH = cSize.y - 20.0f;
                        if (settingsContentH > settingsVisibleH) {
                            float sbX = cPos.x + cSize.x - 6.0f;
                            float sbH = settingsVisibleH;
                            float sbY = innerY;
                            float thumbH = sbH * (sbH / settingsContentH);
                            if (thumbH < 20.0f) thumbH = 20.0f;
                            float maxScroll = settingsContentH - settingsVisibleH;
                            float thumbY = sbY + (g_settingsScrollY / maxScroll) * (sbH - thumbH);
                            cdl->AddRectFilled(ImVec2(sbX, sbY), ImVec2(sbX + 4, sbY + sbH),
                                g_darkMode ? IM_COL32(255, 255, 255, 20) : IM_COL32(0, 0, 0, 15), 2.0f);
                            cdl->AddRectFilled(ImVec2(sbX, thumbY), ImVec2(sbX + 4, thumbY + thumbH),
                                g_darkMode ? IM_COL32(255, 255, 255, 80) : IM_COL32(0, 0, 0, 40), 2.0f);
                        }
                    }

                    cdl->PopClipRect();

                    {
                        float btnW = 170.0f;
                        float btnH = 26.0f;
                        float gap = 10.0f;
                        float pad = 12.0f;
                        float linksY = cPos.y + cSize.y - btnH - pad;
                        float fbX = cPos.x + cSize.x - pad - btnW;
                        float ubX = fbX - gap - btnW;

                        {
                            ImVec2 ubMin(ubX, linksY);
                            ImVec2 ubMax(ubX + btnW, linksY + btnH);
                            bool ubHov = ImGui::IsMouseHoveringRect(ubMin, ubMax);
                            ImU32 ubBg = ubHov
                                ? IM_COL32(50, 140, 200, 60)
                                : IM_COL32(50, 140, 200, 25);
                            ImU32 ubBorder = IM_COL32(50, 140, 200, ubHov ? 160 : 80);
                            cdl->AddRectFilled(ubMin, ubMax, ubBg, 4.0f);
                            cdl->AddRect(ubMin, ubMax, ubBorder, 4.0f, 0, 1.0f);
                            const char* ubLabel = "Check for Updates";
                            ImVec2 ubT = ImGui::CalcTextSize(ubLabel);
                            cdl->AddText(ImVec2((ubMin.x + ubMax.x - ubT.x) / 2, (ubMin.y + ubMax.y - ubT.y) / 2),
                                IM_COL32(50, 140, 200, 255), ubLabel);
                            if (ubHov && io.MouseClicked[0])
                                std::thread(CheckForUpdates, g_hMainWindow).detach();
                        }

                        {
                            ImVec2 fbMin(fbX, linksY);
                            ImVec2 fbMax(fbX + btnW, linksY + btnH);
                            bool fbHov = ImGui::IsMouseHoveringRect(fbMin, fbMax);
                            ImU32 fbBg = fbHov
                                ? IM_COL32(200, 130, 50, 60)
                                : IM_COL32(200, 130, 50, 25);
                            ImU32 fbBorder = IM_COL32(200, 130, 50, fbHov ? 160 : 80);
                            cdl->AddRectFilled(fbMin, fbMax, fbBg, 4.0f);
                            cdl->AddRect(fbMin, fbMax, fbBorder, 4.0f, 0, 1.0f);
                            const char* fbLabel = "Feedback / Report";
                            ImVec2 fbT = ImGui::CalcTextSize(fbLabel);
                            cdl->AddText(ImVec2((fbMin.x + fbMax.x - fbT.x) / 2, (fbMin.y + fbMax.y - fbT.y) / 2),
                                IM_COL32(200, 130, 50, 255), fbLabel);
                            if (fbHov && io.MouseClicked[0])
                                ShellExecuteW(NULL, L"open", L"https://github.com/axs-offcl/Black-Hole/issues/new", NULL, NULL, SW_SHOWNORMAL);
                        }
                    }
                }
            }
            ImGui::EndChild();
            ImGui::PopStyleVar(2);
        }

        g_mainWinPos = ImGui::GetWindowPos();
        g_mainWinSize = ImGui::GetWindowSize();
        ImGui::End();
        ImGui::PopStyleVar(2);

        if (g_showLeftoverPopup.load()) {
            {
                std::lock_guard<std::mutex> lock(g_forceRemovalMutex);
                g_leftoverSnapshot = g_leftoverItems;
                g_leftoverSearchFilter[0] = '\0';
            }
            ImGui::OpenPopup("Leftovers Found##popup");
            g_showLeftoverPopup.store(false);
        }

        ImVec2 popupSize(640, 500);
        float centerWinX = g_mainWinPos.x + g_mainWinSize.x / 2.0f;
        float centerWinY = g_mainWinPos.y + g_mainWinSize.y / 2.0f;
        ImVec2 popupPos(centerWinX - popupSize.x / 2.0f,
                        centerWinY - popupSize.y / 2.0f);
        ImGui::SetNextWindowPos(popupPos, ImGuiCond_Always);
        ImGui::SetNextWindowSizeConstraints(ImVec2(500, 350), ImVec2(1200, 900));
        ImGui::SetNextWindowSize(popupSize, ImGuiCond_FirstUseEver);

        if (ImGui::BeginPopupModal("Leftovers Found##popup", NULL,
            ImGuiWindowFlags_NoScrollbar)) {

            ImVec2 wPos = ImGui::GetWindowPos();
            ImVec2 wSize = ImGui::GetWindowSize();
            ImDrawList* mdl = ImGui::GetWindowDrawList();
            mdl->AddRectFilled(wPos, ImVec2(wPos.x + wSize.x, wPos.y + wSize.y),
                Vec4ToU32(CLR_CHILD_BG), 8.0f);

            if (g_leftoverSnapshot.empty()) {
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.55f, 1.0f), "No leftovers found.");
                ImGui::Separator();
                if (ImGui::Button("OK", ImVec2(120, 0))) {
                    if (g_popupEraseIdx >= 0 && g_popupEraseIdx < (int)g_uninstallEntries.size()) {
                        BlackHole::Uninstaller u;
                        u.RemoveRegistryEntry(g_uninstallEntries[g_popupEraseIdx]);
                        g_iconThreadRunning.store(false);
                        g_sizeCalcDone.store(true);
                        g_iconThreadGeneration.store(0);
                        g_uninstallEntries.erase(g_uninstallEntries.begin() + g_popupEraseIdx);
                        g_filteredIndicesDirty = true;
                        g_rowSelected.assign(g_uninstallEntries.size(), false);
                    } else if (!g_batchPurgeNames.empty()) {
                        BlackHole::Uninstaller u;
                        for (auto& name : g_batchPurgeNames) {
                            for (int i = (int)g_uninstallEntries.size() - 1; i >= 0; i--) {
                                if (g_uninstallEntries[i].displayName == name) {
                                    u.RemoveRegistryEntry(g_uninstallEntries[i]);
                                    g_uninstallEntries.erase(g_uninstallEntries.begin() + i);
                                    break;
                                }
                            }
                        }
                        g_batchPurgeNames.clear();
                        g_iconThreadRunning.store(false);
                        g_sizeCalcDone.store(true);
                        g_iconThreadGeneration.store(0);
                        g_filteredIndicesDirty = true;
                        g_rowSelected.assign(g_uninstallEntries.size(), false);
                    }
                    g_popupEraseIdx = -1;
                    ImGui::CloseCurrentPopup();
                }
            } else {
                int safeCount = 0, maybeCount = 0, riskyCount = 0;
                for (auto& item : g_leftoverSnapshot) {
                    if (item.confidence == BlackHole::LeftoverConfidence::Safe) safeCount++;
                    else if (item.confidence == BlackHole::LeftoverConfidence::Moderate) maybeCount++;
                    else riskyCount++;
                }
                int totalCount = (int)g_leftoverSnapshot.size();

                // Summary bar — header left, dots far right
                {
                    char header[128];
                    snprintf(header, sizeof(header), "%d remnants detected:", totalCount);
                    ImGui::TextColored(ImVec4(0.55f, 0.51f, 1.0f, 1.0f), "%s", header);
                }

                // Calculate dots total width, then draw at far right
                {
                    float dotR = 4.0f;
                    float dotsWidth = 0.0f;
                    // Measure
                    auto measureDot = [&](int count, const char* label) {
                        if (count == 0) return;
                        char buf[32];
                        snprintf(buf, sizeof(buf), "%d %s", count, label);
                        ImVec2 sz = ImGui::CalcTextSize(buf);
                        dotsWidth += dotR * 2 + 4 + sz.x + 14;
                    };
                    measureDot(safeCount, "Safe");
                    measureDot(maybeCount, "Maybe");
                    measureDot(riskyCount, "Risky");
                    if (dotsWidth > 0) dotsWidth -= 14; // remove last gap

                    float avail = ImGui::GetContentRegionAvail().x;
                    ImGui::SameLine(avail - dotsWidth);

                    ImDrawList* dlSummary = ImGui::GetWindowDrawList();
                    ImVec2 dotPos = ImGui::GetCursorScreenPos();
                    dotPos.y += ImGui::GetTextLineHeight() / 2.0f;

                    auto drawDot = [&](ImVec4 col, int count, const char* label) {
                        if (count == 0) return;
                        dlSummary->AddCircleFilled(dotPos, dotR, ImGui::GetColorU32(col), 10);
                        dotPos.x += dotR * 2 + 4;
                        char buf[32];
                        snprintf(buf, sizeof(buf), "%d %s", count, label);
                        ImVec2 txtSz = ImGui::CalcTextSize(buf);
                        dlSummary->AddText(ImVec2(dotPos.x, dotPos.y - txtSz.y / 2),
                            ImGui::GetColorU32(ImVec4(0.7f, 0.7f, 0.75f, 1.0f)), buf);
                        dotPos.x += txtSz.x + 14;
                    };
                    drawDot(ImVec4(0.4f, 0.85f, 0.5f, 1.0f), safeCount, "Safe");
                    drawDot(ImVec4(0.9f, 0.8f, 0.3f, 1.0f), maybeCount, "Maybe");
                    drawDot(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), riskyCount, "Risky");
                }

                ImGui::Separator();

                // Search/filter box
                ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 4));
                ImGui::PushStyleColor(ImGuiCol_FrameBg, Vec4ToU32(CLR_SIDEBAR_BG));
                ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, Vec4ToU32(CLR_ELEM_BG_HOVER));
                ImGui::PushStyleColor(ImGuiCol_Border, Vec4ToU32(CLR_STROKE));
                ImGui::PushItemWidth(-1);
                ImGui::InputTextWithHint("##leftover_filter", "Filter by path...",
                    g_leftoverSearchFilter, sizeof(g_leftoverSearchFilter));
                ImGui::PopItemWidth();
                ImGui::PopStyleColor(3);
                ImGui::PopStyleVar(2);

                ImGui::BeginChild("##leftover_list", ImVec2(0, -56), false,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBackground);

                ImVec4 safeCol(0.4f, 0.85f, 0.5f, 1.0f);
                ImVec4 maybeCol(0.9f, 0.8f, 0.3f, 1.0f);
                ImVec4 riskyCol(0.9f, 0.3f, 0.3f, 1.0f);

                auto drawCategory = [&](const char* label, ImVec4 color, int count,
                                        BlackHole::LeftoverConfidence conf) {
                    if (count == 0) return;

                    ImVec2 catStart = ImGui::GetCursorScreenPos();
                    float avail = ImGui::GetContentRegionAvail().x;

                    char hdr[128];
                    snprintf(hdr, sizeof(hdr), "  %s (%d)", label, count);

                    ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_DefaultOpen |
                        ImGuiTreeNodeFlags_OpenOnArrow;

                    bool nodeOpen = ImGui::TreeNodeEx((void*)(intptr_t)conf, flags, "%s", hdr);

                    ImVec2 catEnd = ImGui::GetCursorScreenPos();
                    ImDrawList* dl = ImGui::GetWindowDrawList();

                    // Colored left border (3px thick stripe)
                    dl->AddRectFilled(ImVec2(catStart.x, catStart.y + 2.0f),
                        ImVec2(catStart.x + 3.0f, catEnd.y - 2.0f),
                        ImGui::GetColorU32(color), 1.5f);

                    // Subtle background strip
                    dl->AddRectFilled(ImVec2(catStart.x + 4.0f, catStart.y + 1.0f),
                        ImVec2(catStart.x + avail, catEnd.y - 1.0f),
                        ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, 0.06f)), 3.0f);

                    ImGui::SameLine(avail - 120);
                    char selBtn[32], unsBtn[32];
                    snprintf(selBtn, sizeof(selBtn), "All##%d", (int)conf);
                    snprintf(unsBtn, sizeof(unsBtn), "None##%d", (int)conf);
                    if (ImGui::SmallButton(selBtn)) {
                        for (auto& item : g_leftoverSnapshot)
                            if (item.confidence == conf) item.checked = true;
                    }
                    ImGui::SameLine(0, 8);
                    if (ImGui::SmallButton(unsBtn)) {
                        for (auto& item : g_leftoverSnapshot)
                            if (item.confidence == conf) item.checked = false;
                    }

                    if (nodeOpen) {
                        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 3.0f);
                        for (int i = 0; i < (int)g_leftoverSnapshot.size(); i++) {
                            auto& item = g_leftoverSnapshot[i];
                            if (item.confidence != conf) continue;

                            // Full path (for tooltip)
                            std::string fullPathUtf8;
                            {
                                int sz = WideCharToMultiByte(CP_UTF8, 0, item.path.c_str(), (int)item.path.size(),
                                    NULL, 0, NULL, NULL);
                                fullPathUtf8.resize(sz);
                                WideCharToMultiByte(CP_UTF8, 0, item.path.c_str(), (int)item.path.size(),
                                    &fullPathUtf8[0], sz, NULL, NULL);
                            }

                            // Apply search filter
                            if (g_leftoverSearchFilter[0] != '\0') {
                                std::string filterLower = g_leftoverSearchFilter;
                                std::string pathLower = fullPathUtf8;
                                std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::tolower);
                                std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);
                                if (pathLower.find(filterLower) == std::string::npos) continue;
                            }

                            // Truncated path for display
                            std::string displayPath = fullPathUtf8;
                            if (displayPath.size() > 62) displayPath = "..." + displayPath.substr(displayPath.size() - 59);

                            // Type labels
                            const char* typeLabel = "";
                            ImVec4 typeColor;
                            if (item.type == BlackHole::LeftoverItem::File) {
                                typeLabel = "[F]";
                                typeColor = ImVec4(0.9f, 0.7f, 0.3f, 1.0f);
                            } else if (item.type == BlackHole::LeftoverItem::Directory) {
                                typeLabel = "[D]";
                                typeColor = ImVec4(0.4f, 0.8f, 0.5f, 1.0f);
                            } else {
                                typeLabel = "[R]";
                                typeColor = ImVec4(0.6f, 0.5f, 1.0f, 1.0f);
                            }

                            ImGui::PushID(i);
                            ImGui::Indent(20.0f);

                            // Measure row background first
                            ImVec2 rowBgStart = ImGui::GetCursorScreenPos();
                            float rowH = ImGui::GetTextLineHeight() + 4.0f;

                            // Checkbox (16x16)
                            ImVec2 cbPos = ImGui::GetCursorScreenPos();
                            ImVec2 cbSize(16, 16);
                            ImDrawList* dl = ImGui::GetWindowDrawList();

                            // Draw row background behind everything
                            bool rowHovered = ImGui::IsMouseHoveringRect(
                                ImVec2(rowBgStart.x - 4, rowBgStart.y - 2),
                                ImVec2(rowBgStart.x + avail - 40, rowBgStart.y + rowH));
                            ImU32 rowBg = rowHovered
                                ? ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, 0.10f))
                                : ImGui::GetColorU32(ImVec4(0, 0, 0, 0.08f));
                            dl->AddRectFilled(
                                ImVec2(rowBgStart.x - 4, rowBgStart.y - 2),
                                ImVec2(rowBgStart.x + avail - 40, rowBgStart.y + rowH),
                                rowBg, 2.0f);

                            // Checkbox
                            dl->AddRectFilled(cbPos, ImVec2(cbPos.x + cbSize.x, cbPos.y + cbSize.y),
                                ImGui::GetColorU32(CLR_ELEM_BG), 3.0f);
                            dl->AddRect(cbPos, ImVec2(cbPos.x + cbSize.x, cbPos.y + cbSize.y),
                                ImGui::GetColorU32(ImVec4(0.4f, 0.4f, 0.45f, 1.0f)), 3.0f);
                            if (item.checked) {
                                ImVec2 pad(3, 3);
                                dl->AddRectFilled(
                                    ImVec2(cbPos.x + pad.x, cbPos.y + pad.y),
                                    ImVec2(cbPos.x + cbSize.x - pad.x, cbPos.y + cbSize.y - pad.y),
                                    ImGui::GetColorU32(ImVec4(0.557f, 0.518f, 1.0f, 1.0f)), 2.0f);
                            }
                            ImGui::Dummy(cbSize);
                            if (ImGui::IsItemClicked()) item.checked = !item.checked;

                            // Type label + path on same line
                            ImGui::SameLine();
                            ImGui::TextColored(typeColor, "%s", typeLabel);
                            ImGui::SameLine();
                            ImGui::TextColored(ImVec4(0.85f, 0.85f, 0.88f, 1.0f), "%s", displayPath.c_str());

                            // Full path tooltip on hover
                            if (rowHovered) {
                                ImGui::BeginTooltip();
                                ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.75f, 1.0f), "Full Path:");
                                ImGui::PushTextWrapPos(600.0f);
                                ImGui::Text("%s", fullPathUtf8.c_str());
                                ImGui::PopTextWrapPos();
                                ImGui::EndTooltip();
                            }

                            // Right-click context menu
                            char popupId[32];
                            snprintf(popupId, sizeof(popupId), "ctx##%d", i);
                            if (ImGui::BeginPopupContextItem(popupId, ImGuiPopupFlags_MouseButtonRight)) {
                                // Open in Explorer (files + dirs)
                                if (item.type != BlackHole::LeftoverItem::RegistryKey) {
                                    if (ImGui::Selectable("Open in Explorer")) {
                                        std::wstring params = L"/select,\"" + item.path + L"\"";
                                        ShellExecuteW(NULL, L"open", L"explorer.exe", params.c_str(), NULL, SW_SHOWNORMAL);
                                    }
                                    if (item.type == BlackHole::LeftoverItem::File) {
                                        if (ImGui::Selectable("Open Containing Folder")) {
                                            size_t lastSlash = item.path.find_last_of(L'\\');
                                            if (lastSlash != std::wstring::npos) {
                                                std::wstring folder = item.path.substr(0, lastSlash);
                                                ShellExecuteW(NULL, L"open", L"explorer.exe", folder.c_str(), NULL, SW_SHOWNORMAL);
                                            }
                                        }
                                    }
                                }
                                // Open in RegEdit (registry keys)
                                if (item.type == BlackHole::LeftoverItem::RegistryKey) {
                                    if (ImGui::Selectable("Open in RegEdit")) {
                                        // Parse HKLM\SOFTWARE\... or HKCU\... format
                                        std::wstring regPath = item.path;
                                        HKEY rootKey = HKEY_LOCAL_MACHINE;
                                        size_t firstSlash = regPath.find(L'\\');
                                        if (firstSlash != std::wstring::npos) {
                                            std::wstring root = regPath.substr(0, firstSlash);
                                            regPath = regPath.substr(firstSlash + 1);
                                            if (root == L"HKCU" || root == L"HKEY_CURRENT_USER")
                                                rootKey = HKEY_CURRENT_USER;
                                        }
                                        // Launch regedit and navigate to key
                                        HKEY openKey = NULL;
                                        if (RegOpenKeyExW(rootKey, regPath.c_str(), 0, KEY_READ, &openKey) == ERROR_SUCCESS) {
                                            RegCloseKey(openKey);
                                            std::wstring cmd = L"regedit.exe /m \"" + item.path + L"\"";
                                            // Fallback: just open regedit at root
                                            ShellExecuteW(NULL, L"open", L"regedit.exe", NULL, NULL, SW_SHOWNORMAL);
                                        } else {
                                            ShellExecuteW(NULL, L"open", L"regedit.exe", NULL, NULL, SW_SHOWNORMAL);
                                        }
                                    }
                                    if (ImGui::Selectable("Copy Key Name")) {
                                        if (OpenClipboard(NULL)) {
                                            EmptyClipboard();
                                            size_t wLen = item.path.size();
                                            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (wLen + 1) * sizeof(wchar_t));
                                            if (hMem) {
                                                wchar_t* pMem = (wchar_t*)GlobalLock(hMem);
                                                memcpy(pMem, item.path.c_str(), wLen * sizeof(wchar_t));
                                                pMem[wLen] = 0;
                                                GlobalUnlock(hMem);
                                                SetClipboardData(CF_UNICODETEXT, hMem);
                                            }
                                            CloseClipboard();
                                        }
                                    }
                                }
                                // Copy path (all types)
                                ImGui::Separator();
                                if (ImGui::Selectable("Copy Full Path")) {
                                    if (OpenClipboard(NULL)) {
                                        EmptyClipboard();
                                        size_t wLen = item.path.size();
                                        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (wLen + 1) * sizeof(wchar_t));
                                        if (hMem) {
                                            wchar_t* pMem = (wchar_t*)GlobalLock(hMem);
                                            memcpy(pMem, item.path.c_str(), wLen * sizeof(wchar_t));
                                            pMem[wLen] = 0;
                                            GlobalUnlock(hMem);
                                            SetClipboardData(CF_UNICODETEXT, hMem);
                                        }
                                        CloseClipboard();
                                    }
                                }
                                ImGui::EndPopup();
                            }

                            ImGui::Unindent(20.0f);
                            ImGui::PopID();
                        }
                        ImGui::PopStyleVar();
                        ImGui::TreePop();
                    }
                };

                drawCategory("Safe", safeCol, safeCount, BlackHole::LeftoverConfidence::Safe);
                drawCategory("Maybe", maybeCol, maybeCount, BlackHole::LeftoverConfidence::Moderate);
                drawCategory("Risky", riskyCol, riskyCount, BlackHole::LeftoverConfidence::Risky);

                ImGui::EndChild();

                // ── Buttons anchored to bottom of popup window ──
                int checkedCount = 0;
                for (auto& item : g_leftoverSnapshot)
                    if (item.checked) checkedCount++;

                float btnH = 24.0f;
                float btnRound = 12.0f;
                float pillGap = 6.0f;
                ImDrawList* dlBtn = ImGui::GetWindowDrawList();
                ImVec2 wPos = ImGui::GetWindowPos();
                ImVec2 wSize = ImGui::GetWindowSize();
                float btnY = wPos.y + wSize.y - btnH - 12.0f;

                // --- Purge pill (left side) ---
                char btnLabel[64];
                snprintf(btnLabel, sizeof(btnLabel), "Purge (%d)", checkedCount);
                {
                    ImVec2 txtSz = ImGui::CalcTextSize(btnLabel);
                    float pillW = txtSz.x + 24.0f;
                    ImVec2 pMin(wPos.x + 12.0f, btnY);
                    ImVec2 pMax(pMin.x + pillW, pMin.y + btnH);
                    bool hov = ImGui::IsMouseHoveringRect(pMin, pMax);
                    bool active = checkedCount > 0;

                    ImU32 bg = active
                        ? (hov ? IM_COL32(30, 28, 60, 255) : IM_COL32(22, 20, 48, 255))
                        : (hov ? IM_COL32(35, 35, 42, 255) : IM_COL32(25, 25, 32, 255));
                    ImU32 border = active
                        ? IM_COL32(100, 90, 220, hov ? 220 : 140)
                        : IM_COL32(60, 60, 70, hov ? 160 : 80);
                    dlBtn->AddRectFilled(pMin, pMax, bg, btnRound);
                    dlBtn->AddRect(pMin, pMax, border, btnRound, 0, 1.0f);

                    float dotX = pMin.x + 8.0f;
                    float dotY = pMin.y + btnH / 2.0f;
                    ImU32 dotCol = active ? IM_COL32(100, 90, 220, 255) : IM_COL32(80, 80, 90, 255);
                    dlBtn->AddCircleFilled(ImVec2(dotX, dotY), 3.5f, dotCol, 10);

                    ImU32 txtCol = active ? IM_COL32(200, 195, 255, 255) : IM_COL32(100, 100, 110, 255);
                    dlBtn->AddText(ImVec2(dotX + 6.0f, dotY - txtSz.y / 2), txtCol, btnLabel);

                    if (hov && io.MouseClicked[0] && checkedCount > 0) {
                        BlackHole::Uninstaller u;
                        bool purgeResult = u.PurgeLeftovers(g_leftoverSnapshot, g_createRestorePoint);
                        int deletedCount = 0, rebootCount = 0, failedCount = 0;
                        for (auto& item : g_leftoverSnapshot) {
                            if (!item.checked) continue;
                            if (item.type == BlackHole::LeftoverItem::RegistryKey) {
                                deletedCount++;
                            } else {
                                DWORD attrs = GetFileAttributesW(item.path.c_str());
                                if (attrs == INVALID_FILE_ATTRIBUTES)
                                    deletedCount++;
                                else
                                    rebootCount++;
                            }
                        }
                        if (rebootCount > 0) {
                            PushNotification(L"Reboot Required",
                                (std::to_wstring(rebootCount) + L" items scheduled for deletion on reboot").c_str(), false);
                        } else {
                            PushNotification(L"Leftovers purged",
                                (std::to_wstring(deletedCount) + L" items removed").c_str(), false);
                        }
                        g_leftoverSnapshot.clear();
                        if (g_popupEraseIdx >= 0 && g_popupEraseIdx < (int)g_uninstallEntries.size()) {
                            u.RemoveRegistryEntry(g_uninstallEntries[g_popupEraseIdx]);
                            g_iconThreadRunning.store(false);
                            g_sizeCalcDone.store(true);
                            g_iconThreadGeneration.store(0);
                            g_uninstallEntries.erase(g_uninstallEntries.begin() + g_popupEraseIdx);
                            g_filteredIndicesDirty = true;
                            g_rowSelected.assign(g_uninstallEntries.size(), false);
                        } else if (!g_batchPurgeNames.empty()) {
                            for (auto& name : g_batchPurgeNames) {
                                for (int i = (int)g_uninstallEntries.size() - 1; i >= 0; i--) {
                                    if (g_uninstallEntries[i].displayName == name) {
                                        u.RemoveRegistryEntry(g_uninstallEntries[i]);
                                        g_uninstallEntries.erase(g_uninstallEntries.begin() + i);
                                        break;
                                    }
                                }
                            }
                            g_batchPurgeNames.clear();
                            g_iconThreadRunning.store(false);
                            g_sizeCalcDone.store(true);
                            g_iconThreadGeneration.store(0);
                            g_filteredIndicesDirty = true;
                            g_rowSelected.assign(g_uninstallEntries.size(), false);
                        }
                        g_popupEraseIdx = -1;
                        ImGui::CloseCurrentPopup();
                    }
                }

                // --- Right group: RP pill + Cancel pill ---
                {
                    const char* rpLabel = g_createRestorePoint ? "RP ON" : "RP OFF";
                    ImVec2 rpTxtSz = ImGui::CalcTextSize(rpLabel);
                    float rpPillW = rpTxtSz.x + 20.0f;
                    const char* cancelLabel = "Cancel";
                    ImVec2 cancelTxtSz = ImGui::CalcTextSize(cancelLabel);
                    float cancelPillW = cancelTxtSz.x + 24.0f;
                    float rightGroupW = rpPillW + pillGap + cancelPillW;
                    float rpX = wPos.x + wSize.x - 12.0f - rightGroupW;

                    // RP pill
                    {
                        ImVec2 pMin(rpX, btnY);
                        ImVec2 pMax(pMin.x + rpPillW, pMin.y + btnH);
                        bool hov = ImGui::IsMouseHoveringRect(pMin, pMax);

                        ImU32 bg = g_createRestorePoint
                            ? (hov ? IM_COL32(12, 50, 30, 255) : IM_COL32(8, 38, 22, 255))
                            : (hov ? IM_COL32(40, 40, 50, 255) : IM_COL32(25, 25, 32, 255));
                        ImU32 border = g_createRestorePoint
                            ? IM_COL32(40, 180, 100, hov ? 200 : 120)
                            : IM_COL32(80, 80, 90, hov ? 160 : 80);
                        dlBtn->AddRectFilled(pMin, pMax, bg, btnRound);
                        dlBtn->AddRect(pMin, pMax, border, btnRound, 0, 1.0f);

                        float dotX = pMin.x + 8.0f;
                        float dotY = pMin.y + btnH / 2.0f;
                        ImU32 dotCol = g_createRestorePoint ? IM_COL32(60, 220, 120, 255) : IM_COL32(120, 120, 130, 255);
                        dlBtn->AddCircleFilled(ImVec2(dotX, dotY), 3.5f, dotCol, 10);

                        ImU32 txtCol = g_createRestorePoint ? IM_COL32(60, 220, 120, 255) : IM_COL32(140, 140, 150, 255);
                        dlBtn->AddText(ImVec2(dotX + 6.0f, dotY - rpTxtSz.y / 2), txtCol, rpLabel);

                        if (hov && io.MouseClicked[0]) {
                            g_createRestorePoint = !g_createRestorePoint;
                        }
                        if (hov) {
                            ImGui::BeginTooltip();
                            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "System Restore Point");
                            ImGui::TextWrapped("%s",
                                g_createRestorePoint
                                    ? "ON - Will create a restore point before purge (~2-5s)"
                                    : "OFF - Skip restore point for faster purge");
                            ImGui::EndTooltip();
                        }
                    }

                    // Cancel pill
                    {
                        float cancelX = rpX + rpPillW + pillGap;
                        ImVec2 pMin(cancelX, btnY);
                        ImVec2 pMax(pMin.x + cancelPillW, pMin.y + btnH);
                        bool hov = ImGui::IsMouseHoveringRect(pMin, pMax);

                        ImU32 bg = hov ? IM_COL32(50, 25, 25, 255) : IM_COL32(35, 18, 18, 255);
                        ImU32 border = IM_COL32(160, 60, 60, hov ? 200 : 120);
                        dlBtn->AddRectFilled(pMin, pMax, bg, btnRound);
                        dlBtn->AddRect(pMin, pMax, border, btnRound, 0, 1.0f);

                        float dotX = pMin.x + 8.0f;
                        float dotY = pMin.y + btnH / 2.0f;
                        dlBtn->AddCircleFilled(ImVec2(dotX, dotY), 3.5f, IM_COL32(200, 70, 70, 255), 10);

                        ImU32 txtCol = hov ? IM_COL32(255, 200, 200, 255) : IM_COL32(200, 140, 140, 255);
                        dlBtn->AddText(ImVec2(dotX + 6.0f, dotY - cancelTxtSz.y / 2), txtCol, cancelLabel);

                        if (hov && io.MouseClicked[0]) {
                            g_leftoverSnapshot.clear();
                            g_batchPurgeNames.clear();
                            g_popupEraseIdx = -1;
                            ImGui::CloseCurrentPopup();
                        }
                    }
                }
            }

            ImGui::EndPopup();
        }

        {
            std::lock_guard<std::mutex> lock(g_processKillMutex);
            if (!g_pendingLockedProcesses.empty()) {
                g_lockedProcesses = std::move(g_pendingLockedProcesses);
                g_showProcessKillDialog = true;
            }
        }

        if (g_showProcessKillDialog) {
            ImGui::OpenPopup("Processes Using Files##prockill");
            ImVec2 dlgSize(500, 350);
            ImVec2 dlgPos(g_mainWinPos.x + g_mainWinSize.x / 2 - dlgSize.x / 2,
                          g_mainWinPos.y + g_mainWinSize.y / 2 - dlgSize.y / 2);
            ImGui::SetNextWindowPos(dlgPos, ImGuiCond_Always);
            ImGui::SetNextWindowSize(dlgSize, ImGuiCond_Always);
            g_showProcessKillDialog = false;
        }
        if (ImGui::BeginPopupModal("Processes Using Files##prockill", NULL,
            ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar)) {

            ImVec2 wP = ImGui::GetWindowPos();
            ImVec2 wS = ImGui::GetWindowSize();
            ImDrawList* pdl = ImGui::GetWindowDrawList();
            pdl->AddRectFilled(wP, ImVec2(wP.x + wS.x, wP.y + wS.y), Vec4ToU32(CLR_ELEM_BG), 8.0f);

            pdl->AddText(ImVec2(wP.x + 16, wP.y + 12), Vec4ToU32(CLR_TEXT),
                "The following processes are using leftover files:");

            float listY = wP.y + 36;
            float listH = wS.y - 110;
            ImGui::SetCursorScreenPos(ImVec2(wP.x + 16, listY));
            ImGui::BeginChild("##procList", ImVec2(wS.x - 32, listH), true,
                ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoScrollbar);
            for (size_t i = 0; i < g_lockedProcesses.size(); i++) {
                auto& proc = g_lockedProcesses[i];
                char label[256];
                snprintf(label, sizeof(label), "%ls (PID: %lu)", proc.name.c_str(), proc.pid);
                ImGui::Selectable(label, false, ImGuiSelectableFlags_AllowDoubleClick, ImVec2(-1, 20));
            }
            ImGui::EndChild();

            float btnY = wP.y + wS.y - 44;
            float btnW = 80.0f;
            float btnH = 28.0f;
            float totalBtnsW = btnW * 4 + 30.0f;
            float btnStartX = wP.x + (wS.x - totalBtnsW) / 2.0f;

            auto drawBtn = [&](const char* text, float x, float y, ImVec4 normalCol, ImVec4 hoverCol) {
                ImVec2 bMin(x, y);
                ImVec2 bMax(x + btnW, y + btnH);
                bool hov = ImGui::IsMouseHoveringRect(bMin, bMax);
                pdl->AddRectFilled(bMin, bMax, hov ? Vec4ToU32(hoverCol) : Vec4ToU32(normalCol), 4.0f);
                pdl->AddRect(bMin, bMax, IM_COL32(80, 80, 100, 150), 4.0f, 0, 1.0f);
                ImVec2 txtSz = ImGui::CalcTextSize(text);
                pdl->AddText(ImVec2(x + (btnW - txtSz.x) / 2, y + (btnH - txtSz.y) / 2),
                    IM_COL32(255, 255, 255, 255), text);
                return hov && io.MouseClicked[0];
            };

            if (drawBtn("Kill", btnStartX, btnY, ImVec4(0.5f, 0.15f, 0.15f, 1.0f), ImVec4(0.7f, 0.2f, 0.2f, 1.0f))) {
                int sel = -1;
                for (int i = 0; i < (int)g_lockedProcesses.size(); i++) {
                    ImVec2 itemMin(wP.x + 16, listY + 2 + i * 20);
                    ImVec2 itemMax(wP.x + wS.x - 16, itemMin.y + 20);
                    if (ImGui::IsMouseHoveringRect(itemMin, itemMax) && ImGui::IsMouseClicked(0)) {
                        sel = i;
                    }
                }
                if (sel >= 0 && sel < (int)g_lockedProcesses.size()) {
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, g_lockedProcesses[sel].pid);
                    if (hProc) { TerminateProcess(hProc, 1); CloseHandle(hProc); }
                    g_lockedProcesses.erase(g_lockedProcesses.begin() + sel);
                }
            }
            if (drawBtn("Kill All", btnStartX + btnW + 10, btnY, ImVec4(0.5f, 0.15f, 0.15f, 1.0f), ImVec4(0.7f, 0.2f, 0.2f, 1.0f))) {
                for (auto& proc : g_lockedProcesses) {
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, proc.pid);
                    if (hProc) { TerminateProcess(hProc, 1); CloseHandle(hProc); }
                }
                g_lockedProcesses.clear();
            }
            if (drawBtn("Ignore", btnStartX + (btnW + 10) * 2, btnY, ImVec4(0.2f, 0.35f, 0.5f, 1.0f), ImVec4(0.25f, 0.45f, 0.65f, 1.0f))) {
                g_lockedProcesses.clear();
                ImGui::CloseCurrentPopup();
            }
            if (drawBtn("Cancel", btnStartX + (btnW + 10) * 3, btnY, ImVec4(0.3f, 0.3f, 0.35f, 1.0f), ImVec4(0.4f, 0.4f, 0.45f, 1.0f))) {
                g_lockedProcesses.clear();
                g_leftoverSnapshot.clear();
                ImGui::CloseCurrentPopup();
            }

            ImGui::EndPopup();
        }

        {
            ImDrawList* ddl = ImGui::GetForegroundDrawList();
            float dockW = DOCK_W;
            float dockLeft = g_mainWinPos.x + g_mainWinSize.x - dockW;
            float dockTop = g_mainWinPos.y;
            float dockBot = g_mainWinPos.y + g_mainWinSize.y;

            if (!g_hideDock) {
                float dockPulse = 0.4f + (sinf(ImGui::GetTime() * 1.5f) + 1.0f) * 0.3f;

                ImU32 dockBg = Vec4ToU32(CLR_SIDEBAR_BG);
                ddl->AddRectFilled(ImVec2(dockLeft, dockTop), ImVec2(dockLeft + dockW, dockBot), dockBg, 0.0f);

                struct DockNav { const char* label; ImU32 color; };
                static const DockNav navItems[] = {
                    { "Uninstall", IM_COL32(110, 170, 255, 255)},
                    { "Delete",    IM_COL32(255, 95, 95, 255)  },
                    { "Logs",      IM_COL32(255, 170, 90, 255) },
                    { "Settings",  IM_COL32(90, 215, 240, 255) },
                };
                const int navCount = 4;

                float topPad = 50.0f;
                float botPad = 50.0f;
                float areaH = (dockBot - dockTop) - topPad - botPad;
                float btnH = areaH / navCount;

                for (int i = 0; i < navCount; i++) {
                    float btnTop = dockTop + topPad + i * btnH;
                    float btnBot = btnTop + btnH;
                    bool isActive = (g_selectedTab == i);
                    bool isHov = io.MousePos.x >= dockLeft && io.MousePos.x <= dockLeft + dockW &&
                                 io.MousePos.y >= btnTop && io.MousePos.y <= btnBot;

                    ImU32 bg = isActive ? IM_COL32(
                        (int)(g_sidebarGlowColor[0] * 255),
                        (int)(g_sidebarGlowColor[1] * 255),
                        (int)(g_sidebarGlowColor[2] * 255), 25)
                                : isHov ? IM_COL32(255, 255, 255, 8)
                                : IM_COL32(0, 0, 0, 0);
                    ddl->AddRectFilled(ImVec2(dockLeft, btnTop), ImVec2(dockLeft + dockW, btnBot), bg, 0.0f);

                    ImU32 lineCol = isActive ? IM_COL32(142, 132, 255, 255) : IM_COL32(0, 0, 0, 0);
                    float lineW = 2.5f;
                    float lineX = dockLeft;
                    float lineTop = btnTop + 8.0f;
                    float lineBot = btnBot - 8.0f;

                    if (isActive && g_lineGlowEnabled) {
                        int glowR = (int)(g_lineGlowColor[0] * 255);
                        int glowG = (int)(g_lineGlowColor[1] * 255);
                        int glowB = (int)(g_lineGlowColor[2] * 255);
                        int glowA = (int)(dockPulse * 60);
                        for (int g = 3; g >= 1; g--) {
                            float spread = (float)g * 1.5f;
                            ImU32 glowCol = IM_COL32(glowR, glowG, glowB, glowA / (g + 1));
                            ddl->AddRectFilled(ImVec2(lineX - spread, lineTop), ImVec2(lineX + lineW + spread, lineBot), glowCol, 1.0f);
                        }
                        ImU32 lineGlow = IM_COL32(glowR, glowG, glowB, (int)(dockPulse * 255));
                        ddl->AddRectFilled(ImVec2(lineX, lineTop), ImVec2(lineX + lineW, lineBot), lineGlow, 1.0f);
                    } else {
                        ddl->AddRectFilled(ImVec2(lineX, lineTop), ImVec2(lineX + lineW, lineBot), lineCol, 1.0f);
                    }

                    float iconCX = dockLeft + dockW / 2.0f;
                    float iconCY = btnTop + btnH / 2.0f;
                    ImU32 iconCol = isActive ? IM_COL32(142, 132, 255, 255)
                                   : isHov ? IM_COL32(200, 200, 210, 255)
                                   : IM_COL32(110, 110, 125, 255);

                    // Lucide icon font characters
                    static const char* iconChars[] = {
                        "\xEE\x84\x8E",  // log-out (U+E10E)
                        "\xEE\x86\x8E",  // trash-2 (U+E18E)
                        "\xEE\x83\x8C",  // file-text (U+E0CC)
                        "\xEE\x85\x94",  // settings (U+E154)
                    };

                    if (g_fontIcon) {
                        ImGui::PushFont(g_fontIcon);
                        ImVec2 iconSize = g_fontIcon->CalcTextSizeA(g_fontIcon->LegacySize, FLT_MAX, 0.0f, iconChars[i]);
                        ImVec2 iconPos(iconCX - iconSize.x / 2.0f, iconCY - iconSize.y / 2.0f);
                        ddl->AddText(g_fontIcon, g_fontIcon->LegacySize, iconPos, iconCol, iconChars[i]);
                        ImGui::PopFont();
                    }

                    if (isHov && !isActive) {
                        ImVec2 ts = ImGui::CalcTextSize(navItems[i].label);
                        float ttX = dockLeft - 8.0f - ts.x;
                        float ttY = iconCY - ts.y / 2.0f;
                        ddl->AddRectFilled(ImVec2(ttX - 6.0f, ttY - 3.0f),
                            ImVec2(ttX + ts.x + 6.0f, ttY + ts.y + 3.0f),
                            Vec4ToU32(CLR_POPUP_BG), 6.0f);
                        ddl->AddRect(ImVec2(ttX - 6.0f, ttY - 3.0f),
                            ImVec2(ttX + ts.x + 6.0f, ttY + ts.y + 3.0f),
                            Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                        ddl->AddText(ImVec2(ttX, ttY), IM_COL32(200, 200, 210, 255), navItems[i].label);
                    }

                    if (io.MouseClicked[0] && isHov) {
                        if (g_selectedTab != i) {
                            g_selectedTab = i;
                            if (i == 2) LoadLogs();
                        }
                    }
                }
            }

            float toggleW = TOGGLE_BTN_W;
            float toggleH = TOGGLE_BTN_H;
            float toggleX = dockLeft + dockW;
            float toggleCY = g_mainWinPos.y + g_mainWinSize.y / 2.0f;
            float toggleY = toggleCY - toggleH / 2.0f;

            bool toggleHov = io.MousePos.x >= toggleX && io.MousePos.x <= toggleX + toggleW &&
                             io.MousePos.y >= toggleY && io.MousePos.y <= toggleY + toggleH;

            if (io.MouseClicked[0] && toggleHov) {
                g_hideDock = !g_hideDock;
                SaveConfig();
            }

            float toggleCX = toggleX + toggleW / 2.0f;
            float toggleCY2 = toggleY + toggleH / 2.0f;
            float chevR = 6.0f;

            if (toggleHov) {
                ImU32 glowBg = IM_COL32(90, 90, 120, 60);
                ddl->AddRectFilled(ImVec2(toggleX + 2, toggleY + 2),
                    ImVec2(toggleX + toggleW - 2, toggleY + toggleH - 2), glowBg, 8.0f);
            }

            ImU32 chevCol = toggleHov ? IM_COL32(180, 180, 200, 255) : IM_COL32(100, 100, 120, 255);
            float angle = g_hideDock ? 0.0f : 3.14159f;
            float cosA = cosf(angle), sinA = sinf(angle);
            auto rotPt = [&](float x, float y) {
                float rx = (x - toggleCX) * cosA - (y - toggleCY2) * sinA + toggleCX;
                float ry = (x - toggleCX) * sinA + (y - toggleCY2) * cosA + toggleCY2;
                return ImVec2(rx, ry);
            };
            ddl->AddLine(rotPt(toggleCX - chevR * 0.5f, toggleCY2 - chevR * 0.6f),
                         rotPt(toggleCX + chevR * 0.5f, toggleCY2), chevCol, 2.0f);
            ddl->AddLine(rotPt(toggleCX + chevR * 0.5f, toggleCY2),
                         rotPt(toggleCX - chevR * 0.5f, toggleCY2 + chevR * 0.6f), chevCol, 2.0f);
        }

        if (g_batchLeftoverScanning.load()) {
            int progress = g_batchLeftoverProgress.load();
            int total = g_batchLeftoverTotal.load();
            ImGui::SetNextWindowPos(ImVec2(g_mainWinPos.x + g_mainWinSize.x / 2.0f - 160, g_mainWinPos.y + 60));
            ImGui::SetNextWindowSize(ImVec2(320, 50));
            ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);
            ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.08f, 0.08f, 0.12f, 0.95f));
            ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.35f, 0.31f, 0.90f, 0.6f));
            if (ImGui::Begin("##batchScanProgress", nullptr,
                ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoNav)) {
                ImDrawList* bdl = ImGui::GetWindowDrawList();
                ImVec2 bPos = ImGui::GetWindowPos();
                ImVec2 bSize = ImGui::GetWindowSize();

                char progressText[128];
                snprintf(progressText, sizeof(progressText), "Scanning leftovers: %d / %d programs", progress, total);
                bdl->AddText(ImVec2(bPos.x + 12, bPos.y + 8), IM_COL32(200, 195, 255, 255), progressText);

                ImVec2 barMin(bPos.x + 12, bPos.y + bSize.y - 12);
                ImVec2 barMax(bPos.x + bSize.x - 12, bPos.y + bSize.y - 6);
                bdl->AddRectFilled(barMin, barMax, IM_COL32(30, 30, 40, 255), 3.0f);
                float pct = total > 0 ? (float)progress / (float)total : 0.0f;
                ImVec2 fillMax(barMin.x + (barMax.x - barMin.x) * pct, barMax.y);
                bdl->AddRectFilled(barMin, fillMax, IM_COL32(90, 80, 220, 255), 3.0f);
            }
            ImGui::End();
            ImGui::PopStyleColor(2);
            ImGui::PopStyleVar();
        }

        {
            std::lock_guard<std::mutex> lock(g_notifMutex);
            float notifW = 310.0f, notifH = 60.0f, gap = 8.0f;
            ImVec2 displaySize = ImGui::GetIO().DisplaySize;
            float startX = displaySize.x - DOCK_W - notifW - 20.0f;
            float startY = 10.0f;

            for (int i = (int)g_notifications.size() - 1; i >= 0; i--) {
                auto& n = g_notifications[i];
                if (n.active) n.timer += dt;
                if (n.timer > 7.0f) n.active = false;
                float newAlpha = n.alpha + (3.0f * dt * (n.active ? 1.0f : -1.0f));
                n.alpha = (newAlpha < 0.0f) ? 0.0f : ((newAlpha > 1.0f) ? 1.0f : newAlpha);

                if (n.alpha <= 0.01f && !n.active) {
                    g_notifications.erase(g_notifications.begin() + i);
                    continue;
                }

                float curY = startY + i * (notifH + gap);
                float easeT = 1.0f - powf(2.0f, -6.0f * (n.active ? n.alpha : (1.0f - n.alpha)));
                float curX = displaySize.x + 10.0f + (startX - displaySize.x - 10.0f) * easeT;

                ImGui::SetNextWindowPos(ImVec2(curX, curY));
                ImGui::SetNextWindowSize(ImVec2(notifW, notifH));
                ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
                ImGui::PushStyleVar(ImGuiStyleVar_Alpha, n.alpha);

                std::string nId = "##notif_" + std::to_string(i);
                ImGui::Begin(nId.c_str(), nullptr,
                    ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoBackground |
                    ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                    ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoInputs);

                ImDrawList* ndl = ImGui::GetWindowDrawList();
                ImVec2 nPos = ImGui::GetWindowPos();
                ImVec2 nSize = ImGui::GetWindowSize();

                ndl->AddRectFilled(nPos, ImVec2(nPos.x + nSize.x, nPos.y + nSize.y),
                    Vec4ToU32(CLR_POPUP_BG), 8.0f);
                ndl->AddRect(nPos, ImVec2(nPos.x + nSize.x, nPos.y + nSize.y),
                    g_darkMode
                        ? (n.isError ? IM_COL32(50, 16, 16, 255) : IM_COL32(16, 40, 24, 255))
                        : (n.isError ? IM_COL32(220, 120, 120, 255) : IM_COL32(120, 220, 150, 255)),
                    8.0f, 0, 1.0f);
                ndl->AddRectFilled(ImVec2(nPos.x, nPos.y), ImVec2(nPos.x + 3, nPos.y + nSize.y),
                    n.isError ? IM_COL32(180, 50, 50, 255) : IM_COL32(50, 180, 80, 255), 2.0f);

                ndl->AddText(ImVec2(nPos.x + 14, nPos.y + 10), Vec4ToU32(CLR_TEXT), n.titleUtf8.c_str());
                ndl->AddText(ImVec2(nPos.x + 14, nPos.y + 30), Vec4ToU32(CLR_TEXT_DIM), n.detailUtf8.c_str());

                float pct = n.timer / 7.0f;
                ImVec2 barMin(nPos.x + 12, nPos.y + nSize.y - 8);
                ImVec2 barMax(nPos.x + nSize.x - 12, nPos.y + nSize.y - 4);
                ndl->AddRectFilled(barMin, barMax, Vec4ToU32(CLR_ELEM_BG), 4.0f);
                ImVec2 fillMax(barMin.x + (barMax.x - barMin.x) * (1.0f - pct), barMax.y);
                ndl->AddRectFilled(barMin, fillMax,
                    n.isError ? IM_COL32(180, 50, 50, 255) : IM_COL32(50, 180, 80, 255), 4.0f);

                ImGui::End();
                ImGui::PopStyleVar(2);
            }
        }

        ImGui::Render();
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        const float clear[4] = { CLR_MAIN_BG.x, CLR_MAIN_BG.y, CLR_MAIN_BG.z, 1.0f };
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
        if (g_hToggleWnd) {
            UpdateTogglePosition();
        }
        if (g_applyTransparencyNextFrame) {
            g_applyTransparencyNextFrame = false;
            ApplyWindowTransparency();
        }
        Sleep(1);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(g_hMainWindow);
    UnregisterClassW(g_wc.lpszClassName, hInstance);
    return 0;
}
