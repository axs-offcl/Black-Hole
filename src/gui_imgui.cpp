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
#include <commctrl.h>
#include <ShObjIdl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commdlg.h>
#include <fstream>
#include <winhttp.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <psapi.h>

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

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static bool g_SwapChainOccluded = false;
static UINT g_ResizeWidth = 0, g_ResizeHeight = 0;

static HINSTANCE g_hInstance = nullptr;
static HWND g_hMainWindow = nullptr;
static WNDCLASSEXW g_wc = {};
static NOTIFYICONDATAW g_nid = {};

static std::atomic<bool> g_running{true};
static std::atomic<bool> g_overrideActive{false};
static std::atomic<bool> g_installStatus{false};
static bool g_forceDeleteInstalled = false;
static bool g_analyzeInspectInstalled = false;
static bool g_needsRedraw = true;
static DWORD g_lastFrameTime = 0;

static char g_overrideInput[256] = "";
static bool g_phraseFocused = false;
static bool g_phraseWrong = false;
static float g_phraseWrongTimer = 0.0f;
static std::wstring g_selectedFile = L"";
static BlackHole::ImpactAnalysis g_impactAnalysis;
static std::atomic<bool> g_analysisRunning{false};
static bool g_showLockDetails = false;
static bool g_showRegistryDetails = false;
static bool g_showServiceDetails = false;
static bool g_showDependentDetails = false;
static bool g_showRelatedDetails = false;
static bool g_showLeftoverDetails = false;
static std::vector<bool> g_leftoverChecked;
static bool g_showLeftoverCleanConfirm = false;
static std::vector<bool> g_lockedByChecked;
static std::vector<bool> g_dependentAppsChecked;
static std::vector<bool> g_registryRefsChecked;
static std::vector<bool> g_serviceRefsChecked;
static std::vector<bool> g_relatedFilesChecked;

static ImFont* g_fontDefault = nullptr;
static ImFont* g_fontSidebar = nullptr;
static ImFont* g_fontPill = nullptr;

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
static bool g_autoAnalyzeOnStart = false;
static bool g_showDeleteConfirm = false;
static float g_analysisAnimTime = 0.0f;
static const wchar_t* BH_VERSION = L"2.0";

static std::vector<BlackHole::UninstallEntry> g_uninstallEntries;
static std::vector<BlackHole::LeftoverItem> g_leftoverItems;
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
static std::atomic<bool> g_scanComplete{false};
static std::atomic<bool> g_initialScanStarted{false};
static std::mutex g_scanResultMutex;
static std::vector<BlackHole::UninstallEntry> g_scanResultPending;
static std::atomic<int> g_scanPhase{0};
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
static std::atomic<bool> g_showLeftoverPopup{false};
static char g_leftoverSearchFilter[128] = {};
static BlackHole::ScanDepth g_scanDepth = BlackHole::ScanDepth::Safe;
static std::mutex g_forceRemovalMutex;
static bool g_pendingStandardUninstall = false;
static BlackHole::UninstallEntry g_standardUninstallEntry;
static int g_standardUninstallIdx = -1;
static std::atomic<bool> g_standardUninstallRunning{false};
static HANDLE g_standardUninstallThreadHandle = NULL;
static int g_popupEraseIdx = -1;
static int g_selectedUninstallIdx = -1;
static int g_ctxMenuIdx = -1;

struct ProcessInfo {
    DWORD pid;
    std::wstring name;
    std::wstring exePath;
};
static std::vector<ProcessInfo> g_lockedProcesses;
static bool g_showProcessKillDialog = false;
static std::mutex g_processKillMutex;
static std::vector<ProcessInfo> g_pendingLockedProcesses;
static int g_uninstallSortCol = 0;
static bool g_uninstallSortAsc = true;
static bool g_sendToRecycleBin = false;
static bool g_createRestorePoint = true;
static float g_settingsScrollY = 0.0f;

enum class ViewPreset { Basic, Advanced, Everything };
static ViewPreset g_viewPreset = ViewPreset::Advanced;
static bool g_showPropertiesModal = false;
static int g_propertiesIdx = -1;
static bool g_sidebarGlowEnabled = true;
static bool g_lineGlowEnabled = true;
static bool g_hideSidebar = false;
static bool g_hideDock = false;

static bool g_colVisible[11] = { true, true, true, true, true, true, true, true, true, true, true };
static const char* g_colNames[] = { "Program Name", "Publisher", "Size", "Installed On", "Cert", "Arch", "Version", "Kind", "Location", "Protected", "Sys Component" };
static bool g_showColumnChooser = false;
static bool g_showFilterChooser = false;
static std::vector<bool> g_rowSelected;
static bool g_showDeleteSelectedConfirm = false;

static HWND g_hToggleWnd = NULL;
static const wchar_t* TOGGLE_CLASS = L"BlackHoleToggle";
static const float TOGGLE_BTN_W = 16.0f;
static const float TOGGLE_BTN_H = 60.0f;
static bool g_windowTransparent = false;
static float g_windowAlpha = 0.85f;
static bool g_applyTransparencyNextFrame = false;
static bool g_resizableWindow = false;
static bool g_isMaximized = false;
static ImVec2 g_mainWinPos;
static ImVec2 g_mainWinSize;
static std::vector<int> g_filteredIndicesCache;
static bool g_filteredIndicesDirty = true;
static std::string g_lastFilterText;
static float g_sidebarGlowColor[3] = { 128.0f / 255.0f, 0.0f / 255.0f, 230.0f / 255.0f };
static float g_lineGlowColor[3] = { 128.0f / 255.0f, 0.0f / 255.0f, 230.0f / 255.0f };

static std::unordered_map<std::wstring, ID3D11ShaderResourceView*> g_iconCache;
static std::mutex g_iconMutex;
static std::atomic<bool> g_iconThreadRunning{false};
static std::atomic<int> g_iconThreadGeneration{0};
static ID3D11ShaderResourceView* g_defaultIconSRV = nullptr;
static const size_t MAX_ICON_CACHE_ENTRIES = 2000;

static std::atomic<int> g_texCreated(0);
static std::atomic<int> g_texReleased(0);

struct PendingIcon { std::wstring key; HICON hIcon; };
static std::vector<PendingIcon> g_pendingIcons;
static std::mutex g_pendingIconMutex;

struct PendingCachedIcon { std::wstring key; std::vector<BYTE> pixels; };
static std::vector<PendingCachedIcon> g_pendingCachedIcons;
static std::mutex g_pendingCachedIconMutex;

static bool gDragging = false;
static POINT gDragOffset = {};
static bool g_darkMode = true;

static const float SIDEBAR_W = 80.0f;
static const float TITLE_BAR_H = 36.0f;
static const float TOOLBAR_H = 0.0f;
static const float DOCK_W = 44.0f;
static const float DOCK_BTN_H = 36.0f;
static const float DOCK_BTN_GAP = 2.0f;
static const float CONTENT_W = 960.0f;
static const float DOCK_GAP = 4.0f;
static const float DOCK_PAD = 6.0f;

static bool g_dockExpanded = false;
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
        CLR_STROKE     = ImVec4(0.055f, 0.055f, 0.063f, 1.0f);
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

static int g_rotationStartIdx = 0;

static ImVec2 RotateCenter(ImDrawList* dl) {
    ImVec2 l(FLT_MAX, FLT_MAX), u(-FLT_MAX, -FLT_MAX);
    for (int i = g_rotationStartIdx; i < dl->VtxBuffer.Size; i++) {
        l.x = ImMin(l.x, dl->VtxBuffer[i].pos.x);
        l.y = ImMin(l.y, dl->VtxBuffer[i].pos.y);
        u.x = ImMax(u.x, dl->VtxBuffer[i].pos.x);
        u.y = ImMax(u.y, dl->VtxBuffer[i].pos.y);
    }
    return ImVec2((l.x + u.x) / 2.0f, (l.y + u.y) / 2.0f);
}

static void RotateStart() {
    g_rotationStartIdx = ImGui::GetWindowDrawList()->VtxBuffer.Size;
}

static void RotateEnd(float rad) {
    ImVec2 center = RotateCenter(ImGui::GetWindowDrawList());
    float s = sinf(rad), c = cosf(rad);
    ImVec2 offset = ImRotate(center, s, c);
    offset.x -= center.x;
    offset.y -= center.y;
    auto& buf = ImGui::GetWindowDrawList()->VtxBuffer;
    for (int i = g_rotationStartIdx; i < buf.Size; i++) {
        ImVec2 r = ImRotate(buf[i].pos, s, c);
        buf[i].pos.x = r.x - offset.x;
        buf[i].pos.y = r.y - offset.y;
    }
}

static void SetLinearColorAlpha(ImDrawList* dl, int vStart, int vEnd,
    ImVec2 p0, ImVec2 p1, ImU32 col0, ImU32 col1)
{
    ImVec2 gradExtent(p1.x - p0.x, p1.y - p0.y);
    float invLen2 = 1.0f / (gradExtent.x * gradExtent.x + gradExtent.y * gradExtent.y);
    int r0 = (col0 >> IM_COL32_R_SHIFT) & 0xFF;
    int g0 = (col0 >> IM_COL32_G_SHIFT) & 0xFF;
    int b0 = (col0 >> IM_COL32_B_SHIFT) & 0xFF;
    int a0 = (col0 >> IM_COL32_A_SHIFT) & 0xFF;
    int dr = ((col1 >> IM_COL32_R_SHIFT) & 0xFF) - r0;
    int dg = ((col1 >> IM_COL32_G_SHIFT) & 0xFF) - g0;
    int db = ((col1 >> IM_COL32_B_SHIFT) & 0xFF) - b0;
    int da = ((col1 >> IM_COL32_A_SHIFT) & 0xFF) - a0;

    for (int i = vStart; i < vEnd; i++) {
        float dx = dl->VtxBuffer[i].pos.x - p0.x;
        float dy = dl->VtxBuffer[i].pos.y - p0.y;
        float t = ImClamp((dx * gradExtent.x + dy * gradExtent.y) * invLen2, 0.0f, 1.0f);
        int r = (int)(r0 + dr * t);
        int g = (int)(g0 + dg * t);
        int b = (int)(b0 + db * t);
        int a = (int)(a0 + da * t);
        dl->VtxBuffer[i].col = (r) | (g << 8) | (b << 16) | (a << 24);
    }
}

static void RenderTextWithSpacing(const char* text, float spacing, ImVec2 pos1, ImVec2 pos2, ImU32 color, bool centered) {
    ImVec2 pos = pos1;
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

    if (centered) {
        pos.x = (pos1.x + pos2.x) / 2.0f - maxW / 2.0f;
        pos.y = (pos1.y + pos2.y) / 2.0f - totalH / 2.0f;
    }

    while (*text) {
        if (*text != '\n' && *text != ' ') {
            ImGui::SetCursorScreenPos(pos);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(color), "%c", *text);
            pos.y += ImGui::GetTextLineHeight() + spacing;
        }
        text++;
    }
}

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

static std::string GetExeDir() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string s(path);
    size_t pos = s.find_last_of("\\/");
    return (pos != std::string::npos) ? s.substr(0, pos) : s;
}

static std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), NULL, 0);
    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &result[0], size);
    return result;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &result[0], size, NULL, NULL);
    return result;
}

static std::wstring GetConfigPath() {
    PWSTR appDataPath = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appDataPath)))
        return L"";
    std::wstring path(appDataPath);
    CoTaskMemFree(appDataPath);
    path += L"\\BlackHole\\config.ini";
    return path;
}

static void SaveConfig() {
    std::wstring cfgPath = GetConfigPath();
    if (cfgPath.empty()) return;
    std::wstring dir = std::filesystem::path(cfgPath).parent_path().wstring();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    std::ofstream f(WideToUtf8(cfgPath), std::ios::trunc | std::ios::out);
    if (f.is_open()) {
        f << "DarkMode=" << (g_darkMode ? "1" : "0") << "\n";
        f << "SendToRecycleBin=" << (g_sendToRecycleBin ? "1" : "0") << "\n";
        f << "CreateRestorePoint=" << (g_createRestorePoint ? "1" : "0") << "\n";
        f << "SidebarGlowEnabled=" << (g_sidebarGlowEnabled ? "1" : "0") << "\n";
        f << "SidebarGlowR=" << g_sidebarGlowColor[0] << "\n";
        f << "SidebarGlowG=" << g_sidebarGlowColor[1] << "\n";
        f << "SidebarGlowB=" << g_sidebarGlowColor[2] << "\n";
        f << "LineGlowEnabled=" << (g_lineGlowEnabled ? "1" : "0") << "\n";
        f << "LineGlowR=" << g_lineGlowColor[0] << "\n";
        f << "LineGlowG=" << g_lineGlowColor[1] << "\n";
        f << "LineGlowB=" << g_lineGlowColor[2] << "\n";
        f << "HideSidebar=" << (g_hideSidebar ? "1" : "0") << "\n";
        f << "HideDock=" << (g_hideDock ? "1" : "0") << "\n";
        f << "WindowTransparent=" << (g_windowTransparent ? "1" : "0") << "\n";
        f << "WindowAlpha=" << g_windowAlpha << "\n";
        f << "ResizableWindow=" << (g_resizableWindow ? "1" : "0") << "\n";
        f << "DockExpanded=" << (g_dockExpanded ? "1" : "0") << "\n";
        f.close();
    }
}

static void ApplyWindowTransparency();
static void PushNotification(const std::wstring& title, const std::wstring& detail, bool isError);

static void LoadConfig() {
    std::wstring cfgPath = GetConfigPath();
    if (cfgPath.empty()) return;
    std::ifstream f(WideToUtf8(cfgPath));
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.find("DarkMode=1") != std::string::npos)
            g_darkMode = true;
        else if (line.find("DarkMode=0") != std::string::npos)
            g_darkMode = false;

        if (line.find("SendToRecycleBin=1") != std::string::npos)
            g_sendToRecycleBin = true;
        else if (line.find("SendToRecycleBin=0") != std::string::npos)
            g_sendToRecycleBin = false;

        if (line.find("CreateRestorePoint=1") != std::string::npos)
            g_createRestorePoint = true;
        else if (line.find("CreateRestorePoint=0") != std::string::npos)
            g_createRestorePoint = false;

        if (line.find("SidebarGlowEnabled=1") != std::string::npos)
            g_sidebarGlowEnabled = true;
        else if (line.find("SidebarGlowEnabled=0") != std::string::npos)
            g_sidebarGlowEnabled = false;

        if (line.find("SidebarGlowR=") == 0)
            g_sidebarGlowColor[0] = std::stof(line.substr(13));
        else if (line.find("SidebarGlowG=") == 0)
            g_sidebarGlowColor[1] = std::stof(line.substr(13));
        else if (line.find("SidebarGlowB=") == 0)
            g_sidebarGlowColor[2] = std::stof(line.substr(13));

        if (line.find("LineGlowEnabled=1") != std::string::npos)
            g_lineGlowEnabled = true;
        else if (line.find("LineGlowEnabled=0") != std::string::npos)
            g_lineGlowEnabled = false;

        if (line.find("LineGlowR=") == 0)
            g_lineGlowColor[0] = std::stof(line.substr(10));
        else if (line.find("LineGlowG=") == 0)
            g_lineGlowColor[1] = std::stof(line.substr(10));
        else if (line.find("LineGlowB=") == 0)
            g_lineGlowColor[2] = std::stof(line.substr(10));

        if (line.find("HideSidebar=1") != std::string::npos)
            g_hideSidebar = true;
        else if (line.find("HideSidebar=0") != std::string::npos)
            g_hideSidebar = false;
        if (line.find("HideDock=1") != std::string::npos)
            g_hideDock = true;
        else if (line.find("HideDock=0") != std::string::npos)
            g_hideDock = false;

        if (line.find("WindowTransparent=1") != std::string::npos)
            g_windowTransparent = true;
        else if (line.find("WindowTransparent=0") != std::string::npos)
            g_windowTransparent = false;

        if (line.find("WindowAlpha=") == 0) {
            float val = std::stof(line.substr(12));
            if (val >= 0.15f && val <= 1.0f)
                g_windowAlpha = val;
        }

        if (line.find("ResizableWindow=1") != std::string::npos)
            g_resizableWindow = true;
        else if (line.find("ResizableWindow=0") != std::string::npos)
            g_resizableWindow = false;

        if (line.find("DockExpanded=1") != std::string::npos)
            g_dockExpanded = true;
        else if (line.find("DockExpanded=0") != std::string::npos)
            g_dockExpanded = false;
    }
    f.close();
    ApplyWindowTransparency();
}

static void ApplyWindowTransparency() {
    if (!g_hMainWindow) return;
    if (g_windowTransparent) {
        LONG exStyle = GetWindowLongW(g_hMainWindow, GWL_EXSTYLE);
        SetWindowLongW(g_hMainWindow, GWL_EXSTYLE, exStyle | WS_EX_LAYERED);
        SetLayeredWindowAttributes(g_hMainWindow, 0, (BYTE)(g_windowAlpha * 255), LWA_ALPHA);
    } else {
        LONG exStyle = GetWindowLongW(g_hMainWindow, GWL_EXSTYLE);
        SetWindowLongW(g_hMainWindow, GWL_EXSTYLE, exStyle & ~WS_EX_LAYERED);
    }
}

static void UpdateDockRegion();
static void UpdateTogglePosition();

static void ApplyResizableStyle() {
    if (!g_hMainWindow) return;
    LONG style = GetWindowLongW(g_hMainWindow, GWL_STYLE);
    if (g_resizableWindow) {
        style |= WS_THICKFRAME | WS_MAXIMIZEBOX | WS_MINIMIZEBOX;
    } else {
        style &= ~(WS_THICKFRAME | WS_MAXIMIZEBOX | WS_MINIMIZEBOX);
    }
    SetWindowLongW(g_hMainWindow, GWL_STYLE, style);

    int policy = g_resizableWindow ? 2 : 0;
    DwmSetWindowAttribute(g_hMainWindow, 2, &policy, sizeof(policy));

    if (g_resizableWindow) {
        SetWindowRgn(g_hMainWindow, NULL, TRUE);
        SetWindowPos(g_hMainWindow, NULL, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    } else {
        int totalW = (int)CONTENT_W + (int)DOCK_W;
        int totalH = 640;
        SetWindowPos(g_hMainWindow, NULL, 0, 0, totalW, totalH,
            SWP_NOZORDER | SWP_FRAMECHANGED);
        UpdateDockRegion();
    }
    UpdateTogglePosition();
}

static void ToggleDock() {
    g_dockExpanded = !g_dockExpanded;
    SaveConfig();
    UpdateDockRegion();
}

static void UpdateDockRegion() {
    if (!g_hMainWindow || g_resizableWindow) return;
    RECT rc;
    GetClientRect(g_hMainWindow, &rc);
    int winW = rc.right - rc.left;
    int winH = rc.bottom - rc.top;

    HRGN hRgn = CreateRoundRectRgn(0, 0, winW, winH, 24, 24);
    SetWindowRgn(g_hMainWindow, hRgn, TRUE);
}

static void UpdateTogglePosition() {
    if (!g_hToggleWnd || !g_hMainWindow) return;
    RECT rc;
    GetWindowRect(g_hMainWindow, &rc);
    int mainW = rc.right - rc.left;
    int mainH = rc.bottom - rc.top;
    int btnW = (int)TOGGLE_BTN_W;
    int btnH = (int)TOGGLE_BTN_H;
    int btnX = rc.left + mainW - 4;
    int btnY = rc.top + (mainH - btnH) / 2;
    SetWindowPos(g_hToggleWnd, HWND_TOP, btnX, btnY, btnW, btnH,
        SWP_NOACTIVATE | SWP_SHOWWINDOW);
}

static bool g_toggleHovered = false;

static LRESULT CALLBACK ToggleWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rc;
        GetClientRect(hWnd, &rc);
        int w = rc.right - rc.left;
        int h = rc.bottom - rc.top;

        bool hov = g_toggleHovered;

        HBRUSH bgBrush = CreateSolidBrush(hov ? RGB(18, 18, 26) : RGB(8, 8, 12));
        HPEN borderPen = CreatePen(PS_SOLID, 1, hov ? RGB(100, 90, 200) : RGB(24, 24, 32));
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, bgBrush);
        HPEN oldPen = (HPEN)SelectObject(hdc, borderPen);
        RoundRect(hdc, 0, 0, w, h, 4, 4);
        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
        DeleteObject(bgBrush);
        DeleteObject(borderPen);

        int cx = w / 2;
        int cy = h / 2;

        COLORREF colLine = hov ? RGB(142, 132, 255) : RGB(70, 70, 90);
        HPEN linePen = CreatePen(PS_SOLID, 2, colLine);
        HPEN oldLine = (HPEN)SelectObject(hdc, linePen);

        int cw = 4;
        int ch = 10;

        if (g_hideDock) {
            POINT p[3] = { { cx - cw, cy - ch }, { cx, cy }, { cx - cw, cy + ch } };
            Polyline(hdc, p, 3);
        } else {
            POINT p[3] = { { cx + cw, cy - ch }, { cx, cy }, { cx + cw, cy + ch } };
            Polyline(hdc, p, 3);
        }

        SelectObject(hdc, oldLine);
        DeleteObject(linePen);
        EndPaint(hWnd, &ps);
        return 0;
    }
    case WM_LBUTTONDOWN:
        g_hideDock = !g_hideDock;
        SaveConfig();
        InvalidateRect(hWnd, NULL, TRUE);
        return 0;
    case WM_MOUSEMOVE: {
        TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hWnd, 0 };
        TrackMouseEvent(&tme);
        if (!g_toggleHovered) {
            g_toggleHovered = true;
            InvalidateRect(hWnd, NULL, TRUE);
        }
        return 0;
    }
    case WM_MOUSELEAVE:
        g_toggleHovered = false;
        InvalidateRect(hWnd, NULL, TRUE);
        return 0;
    case WM_DESTROY:
        g_hToggleWnd = NULL;
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static void CreateToggleWindow(HINSTANCE hInstance) {
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = ToggleWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = TOGGLE_CLASS;
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    RegisterClassExW(&wc);

    g_hToggleWnd = CreateWindowExW(
        WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
        TOGGLE_CLASS, L"",
        WS_POPUP | WS_VISIBLE,
        0, 0, (int)TOGGLE_BTN_W, (int)TOGGLE_BTN_H,
        g_hMainWindow, NULL, hInstance, NULL);

    if (g_hToggleWnd) {
    }
}

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

static std::wstring UrlEncode(const std::wstring& input) {
    std::wstring result;
    result.reserve(input.size() * 3);
    for (wchar_t c : input) {
        if (c == L' ') result += L"%20";
        else if (c == L'&') result += L"%26";
        else if (c == L'+') result += L"%2B";
        else if (c == L'=') result += L"%3D";
        else if (c == L'?') result += L"%3F";
        else if (c == L'#') result += L"%23";
        else if (c == L'%') result += L"%25";
        else if (c == L'"') result += L"%22";
        else if (c == L'<') result += L"%3C";
        else if (c == L'>') result += L"%3E";
        else if (c == L'|') result += L"%7C";
        else if (c == L'^') result += L"%5E";
        else if (c == L'`') result += L"%60";
        else if (c == L'{') result += L"%7B";
        else if (c == L'}') result += L"%7D";
        else if (c == L'\\') result += L"%5C";
        else if (c >= 32 && c < 127) result += c;
        else {
            wchar_t buf[8];
            swprintf(buf, L"%%%02X", (unsigned int)c);
            result += buf;
        }
    }
    return result;
}

static void DetectLockingProcesses(const std::vector<std::wstring>& filePaths) {
    std::vector<ProcessInfo> localLocked;
    DWORD myPid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == myPid) continue;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (!hProc) continue;
            HMODULE hMods[1024];
            DWORD cbNeeded = 0;
            if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
                int modCount = cbNeeded / sizeof(HMODULE);
                for (int i = 0; i < modCount; i++) {
                    wchar_t modPath[MAX_PATH];
                    if (GetModuleFileNameExW(hProc, hMods[i], modPath, MAX_PATH)) {
                        std::wstring modLower = modPath;
                        std::transform(modLower.begin(), modLower.end(), modLower.begin(), ::towlower);
                        for (auto& fp : filePaths) {
                            std::wstring fpLower = fp;
                            std::transform(fpLower.begin(), fpLower.end(), fpLower.begin(), ::towlower);
                            if (modLower == fpLower) {
                                bool found = false;
                                for (auto& existing : localLocked) {
                                    if (existing.pid == pe.th32ProcessID) { found = true; break; }
                                }
                                if (!found) {
                                    ProcessInfo pi;
                                    pi.pid = pe.th32ProcessID;
                                    pi.name = pe.szExeFile;
                                    pi.exePath = modPath;
                                    localLocked.push_back(pi);
                                }
                                break;
                            }
                        }
                    }
                }
            }
            CloseHandle(hProc);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (!localLocked.empty()) {
        std::lock_guard<std::mutex> lock(g_processKillMutex);
        g_pendingLockedProcesses = std::move(localLocked);
    }
}

static void PushNotification(const std::wstring& title, const std::wstring& detail, bool isError) {
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

static void RegisterShellEntry(const wchar_t* regPath, const wchar_t* menuName, const wchar_t* cmd) {
    HKEY hCmd;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, (std::wstring(regPath) + L"\\command").c_str(),
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hCmd, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hCmd, NULL, 0, REG_SZ, (BYTE*)cmd,
            (DWORD)((wcslen(cmd) + 1) * sizeof(wchar_t)));
        RegCloseKey(hCmd);
    }
    HKEY hMenu;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, regPath,
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hMenu, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hMenu, L"MUIVerb", 0, REG_SZ, (BYTE*)menuName,
            (DWORD)((wcslen(menuName) + 1) * sizeof(wchar_t)));
        RegSetValueExW(hMenu, L"Position", 0, REG_SZ, (BYTE*)L"bottom", 16);
        RegCloseKey(hMenu);
    }
}

static void UnregisterShellEntry(const wchar_t* regPath) {
    RegDeleteTreeW(HKEY_CLASSES_ROOT, regPath);
}

static const wchar_t* kShellPaths[] = {
    L"*\\shell\\BlackHole_ForceDelete",
    L"Directory\\shell\\BlackHole_ForceDelete",
};
static const wchar_t* kAnalyzePaths[] = {
    L"*\\shell\\BlackHole_Analyze",
    L"Directory\\shell\\BlackHole_Analyze",
};

static bool InstallForceDeleteMenu() {
    static const wchar_t* kOldPaths[] = {
        L"Drive\\shell\\BlackHole_ForceDelete",
        L"AllFileSystemObjects\\shell\\BlackHole_ForceDelete",
    };
    for (auto p : kOldPaths) UnregisterShellEntry(p);
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring icon = L"\"C:\\Windows\\System32\\shell32.dll,-32\"";
    std::wstring cmd = L"\"" + std::wstring(exePath) + L"\" --delete \"%1\"";
    for (auto path : kShellPaths) {
        RegisterShellEntry(path, L"Force Delete", cmd.c_str());
        HKEY hIcon;
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, path, 0, KEY_SET_VALUE, &hIcon) == ERROR_SUCCESS) {
            RegSetValueExW(hIcon, L"Icon", 0, REG_SZ, (BYTE*)icon.c_str(),
                (DWORD)((icon.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(hIcon);
        }
    }
    return true;
}

static bool UninstallForceDeleteMenu() {
    for (auto path : kShellPaths) UnregisterShellEntry(path);
    return true;
}

static bool IsForceDeleteMenuInstalled() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"*\\shell\\BlackHole_ForceDelete\\command", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

static bool InstallAnalyzeMenu() {
    static const wchar_t* kOldPaths[] = {
        L"Drive\\shell\\BlackHole_Analyze",
        L"AllFileSystemObjects\\shell\\BlackHole_Analyze",
    };
    for (auto p : kOldPaths) UnregisterShellEntry(p);
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring icon = L"\"C:\\Windows\\System32\\shell32.dll,-22\"";
    std::wstring cmd = L"\"" + std::wstring(exePath) + L"\" --analyze \"%1\"";
    for (auto path : kAnalyzePaths) {
        RegisterShellEntry(path, L"Analyze & Inspect", cmd.c_str());
        HKEY hIcon;
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, path, 0, KEY_SET_VALUE, &hIcon) == ERROR_SUCCESS) {
            RegSetValueExW(hIcon, L"Icon", 0, REG_SZ, (BYTE*)icon.c_str(),
                (DWORD)((icon.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(hIcon);
        }
    }
    return true;
}

static bool UninstallAnalyzeMenu() {
    for (auto path : kAnalyzePaths) UnregisterShellEntry(path);
    return true;
}

static bool IsAnalyzeMenuInstalled() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"*\\shell\\BlackHole_Analyze\\command", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

static bool InstallContextMenu() {
    return InstallForceDeleteMenu();
}

static bool UninstallContextMenu() {
    bool a = UninstallForceDeleteMenu();
    bool b = UninstallAnalyzeMenu();
    return a || b;
}

static bool IsContextMenuInstalled() {
    return IsForceDeleteMenuInstalled() || IsAnalyzeMenuInstalled();
}

static void DrawTrashIcon(ImDrawList* dl, ImVec2 center, float s, ImU32 col) {
    float h = s * 0.5f;
    float w = s * 0.35f;
    ImVec2 tl(center.x - w, center.y - h);
    ImVec2 tr(center.x + w, center.y - h);
    ImVec2 bl(center.x - w * 0.85f, center.y + h);
    ImVec2 br(center.x + w * 0.85f, center.y + h);
    dl->AddLine(tl, tr, col, 1.5f);
    dl->AddLine(tl, bl, col, 1.5f);
    dl->AddLine(tr, br, col, 1.5f);
    dl->AddLine(bl, br, col, 1.5f);
    float lidW = w * 1.2f;
    dl->AddLine(ImVec2(center.x - lidW, center.y - h - 2), ImVec2(center.x + lidW, center.y - h - 2), col, 1.5f);
    float handleW = w * 0.35f;
    dl->AddLine(ImVec2(center.x - handleW, center.y - h - 5), ImVec2(center.x + handleW, center.y - h - 5), col, 1.5f);
    dl->AddLine(ImVec2(center.x - w * 0.35f, center.y - h * 0.3f), ImVec2(center.x - w * 0.35f, center.y + h * 0.6f), col, 1.0f);
    dl->AddLine(ImVec2(center.x, center.y - h * 0.3f), ImVec2(center.x, center.y + h * 0.6f), col, 1.0f);
    dl->AddLine(ImVec2(center.x + w * 0.35f, center.y - h * 0.3f), ImVec2(center.x + w * 0.35f, center.y + h * 0.6f), col, 1.0f);
}

static void DrawSearchIcon(ImDrawList* dl, ImVec2 center, float s, ImU32 col) {
    float r = s * 0.35f;
    ImVec2 c(center.x - s * 0.08f, center.y - s * 0.08f);
    dl->AddCircle(c, r, col, 20, 1.5f);
    float hx = c.x + r * 0.7f;
    float hy = c.y + r * 0.7f;
    dl->AddLine(ImVec2(hx, hy), ImVec2(hx + s * 0.28f, hy + s * 0.28f), col, 2.0f);
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

static std::atomic<bool> g_sizeCalcDone{false};
static std::atomic<bool> g_iconThreadDone{false};

static std::wstring GetIconCacheDir() {
    wchar_t appData[MAX_PATH] = {};
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData);
    std::wstring dir = std::wstring(appData) + L"\\BlackHole\\IconCache";
    CreateDirectoryW((std::wstring(appData) + L"\\BlackHole").c_str(), NULL);
    CreateDirectoryW(dir.c_str(), NULL);
    return dir;
}

static std::wstring GetIconCachePath(const std::wstring& key) {
    DWORD h = 5381;
    for (wchar_t c : key) h = ((h << 5) + h) + (DWORD)c;
    wchar_t hex[16];
    swprintf_s(hex, L"%08x", h);
    return GetIconCacheDir() + L"\\" + hex + L".dat";
}

static bool SaveIconToDiskCache(const std::wstring& key, HICON hIcon) {
    if (!hIcon) return false;
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

    if (!bits) { DeleteObject(hBmp); return false; }

    std::wstring path = GetIconCachePath(key);
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { DeleteObject(hBmp); return false; }

    DWORD magic = 0x48424948;
    DWORD size = 24 * 24 * 4;
    DWORD written = 0;
    WriteFile(hFile, &magic, 4, &written, NULL);
    WriteFile(hFile, bits, size, &written, NULL);
    CloseHandle(hFile);
    DeleteObject(hBmp);
    return true;
}

static bool LoadIconFromDiskCache(const std::wstring& key, std::vector<BYTE>& outPixels) {
    std::wstring path = GetIconCachePath(key);
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD magic = 0;
    DWORD bytesRead = 0;
    ReadFile(hFile, &magic, 4, &bytesRead, NULL);
    if (magic != 0x48424948 || bytesRead != 4) { CloseHandle(hFile); return false; }

    outPixels.resize(24 * 24 * 4);
    ReadFile(hFile, outPixels.data(), (DWORD)outPixels.size(), &bytesRead, NULL);
    CloseHandle(hFile);
    return bytesRead == outPixels.size();
}

static DWORD CalculateFolderSizeKB(const std::wstring& path) {
    if (path.empty()) return 0;
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return 0;

    ULONGLONG totalBytes = 0;
    std::wstring search = path;
    if (search.back() != L'\\') search += L'\\';
    search += L'*';

    WIN32_FIND_DATAW fdata;
    HANDLE hFind = FindFirstFileW(search.c_str(), &fdata);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (g_sizeCalcDone.load()) { FindClose(hFind); return 0; }
        if (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(fdata.cFileName, L".") == 0 || wcscmp(fdata.cFileName, L"..") == 0) continue;
            std::wstring sub = path;
            if (sub.back() != L'\\') sub += L'\\';
            sub += fdata.cFileName;
            DWORD subKB = CalculateFolderSizeKB(sub);
            totalBytes += (ULONGLONG)subKB * 1024;
        } else {
            ULONGLONG fileSize = ((ULONGLONG)fdata.nFileSizeHigh << 32) | fdata.nFileSizeLow;
            totalBytes += fileSize;
        }
    } while (FindNextFileW(hFind, &fdata));
    FindClose(hFind);

    if (totalBytes > (ULONGLONG)4096 * 1024 * 1024) return 0;
    return (DWORD)(totalBytes / 1024);
}

static void LoadIconsBackground(std::vector<BlackHole::UninstallEntry> entries) {
    for (int i = 0; i < (int)entries.size(); i++) {
        if (!g_iconThreadRunning.load()) break;
        auto& e = entries[i];

        std::wstring iconKey = e.displayName;
        {
            std::lock_guard<std::mutex> lock(g_iconMutex);
            if (g_iconCache.count(iconKey)) continue;
        }

        std::vector<BYTE> cachedPixels;
        if (LoadIconFromDiskCache(iconKey, cachedPixels)) {
            {
                std::lock_guard<std::mutex> lock(g_iconMutex);
                if (g_iconCache.count(iconKey)) continue;
            }
            {
                std::lock_guard<std::mutex> lock(g_pendingCachedIconMutex);
                g_pendingCachedIcons.push_back({iconKey, std::move(cachedPixels)});
            }
            continue;
        }

        if (!e.installPath.empty()) {
            DWORD attr = GetFileAttributesW(e.installPath.c_str());
            (void)attr;
        }

        HICON hIcon = BlackHole::ExtractAppIcon(e);

        if (!hIcon) continue;

        SaveIconToDiskCache(iconKey, hIcon);

        {
            std::lock_guard<std::mutex> lock(g_pendingIconMutex);
            g_pendingIcons.push_back({iconKey, hIcon});
        }
    }
    g_iconThreadRunning.store(false);
    g_iconThreadDone.store(true);
    g_sizeCalcDone.store(true);
}

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

static void SelectFile(HWND hwnd) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    bool comInited = SUCCEEDED(hr);

    IFileOpenDialog* pDialog = nullptr;
    hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_ALL, IID_PPV_ARGS(&pDialog));
    if (SUCCEEDED(hr)) {
        DWORD options;
        pDialog->GetOptions(&options);
        pDialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
        pDialog->SetTitle(L"Select File or Folder to Analyze");

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

static void PerformDeletion(const std::wstring& path, HWND hwnd) {
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
            PWSTR ap = nullptr;
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &ap))) {
                std::wstring logPath(ap);
                CoTaskMemFree(ap);
                logPath += L"\\BlackHole\\audit.log";
                SYSTEMTIME st;
                GetLocalTime(&st);
                wchar_t ts[64];
                swprintf_s(ts, L"%04d-%02d-%02d %02d:%02d:%02d.%03d",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
                std::wstring entry = std::wstring(ts) + L" | Recycled | " + path + L"\n";
                SetFileAttributesW(logPath.c_str(), FILE_ATTRIBUTE_NORMAL);
                std::ofstream logF(WideToUtf8(logPath), std::ios::app | std::ios::out);
                if (logF.is_open()) {
                    logF << WideToUtf8(entry);
                    logF.flush();
                    logF.close();
                }
            }
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
    bool success = (result.result == BlackHole::DeletionResult::Success ||
                    result.result == BlackHole::DeletionResult::Scheduled_Reboot);
    if (success) {
        std::wstring title = (result.result == BlackHole::DeletionResult::Success)
            ? L"DELETE SUCCESS" : L"DELETE SCHEDULED";
        PushNotification(title, result.errorMessage, false);
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

static void PerformLeftoverClean(const std::vector<BlackHole::LeftoverRef>& items,
                                 const std::vector<bool>& checked, HWND hwnd) {
    int cleaned = 0, failed = 0;

    for (int i = 0; i < (int)items.size(); i++) {
        if (i >= (int)checked.size() || !checked[i]) continue;
        const auto& item = items[i];

        if (item.typeName == L"Registry") {
            // Path format: "HKLM\key\path -> ValueName"
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
            // Path format: "Service: serviceName"
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
            // File leftover
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

static const char* CRASH_LOG_PATH = nullptr;

static void WriteCrashLogHeader() {
    if (!CRASH_LOG_PATH) return;
    FILE* f = nullptr;
    fopen_s(&f, CRASH_LOG_PATH, "w");
    if (f) {
        fprintf(f, "BlackHole started - crash handler installed\n");
        fclose(f);
    }
}

static void DebugLog(const char* msg) {
    OutputDebugStringA(msg);
    if (!CRASH_LOG_PATH) return;
    FILE* f = nullptr;
    fopen_s(&f, CRASH_LOG_PATH, "a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%02d:%02d:%02d.%03d] %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
        fclose(f);
    }
}

struct ForceRemoveData {
    BlackHole::UninstallEntry entry;
    BlackHole::ScanDepth depth;
};

static unsigned __stdcall ForceRemoveThread(void* param) {
    auto* data = static_cast<ForceRemoveData*>(param);
    try {
        DebugLog("FORCE_REMOVE: thread started");
        PushNotification(L"Scanning leftovers", data->entry.displayName, false);
        BlackHole::Uninstaller u;
        DebugLog("FORCE_REMOVE: Uninstaller created");
        u.RemoveRegistryEntry(data->entry);
        DebugLog("FORCE_REMOVE: Registry removed, scanning leftovers");
        auto leftovers = u.ScanLeftovers(data->entry, data->depth, true);
        DebugLog("FORCE_REMOVE: ScanLeftovers done");
        for (auto& item : leftovers) item.checked = true;
        if (!leftovers.empty()) {
            {
                std::lock_guard<std::mutex> lock(g_forceRemovalMutex);
                g_leftoverItems = leftovers;
            }
            g_showLeftoverPopup.store(true);
        } else {
            PushNotification(L"No leftovers found", data->entry.displayName, false);
        }
        DebugLog("FORCE_REMOVE: rescan starting");
        auto freshEntries = u.ScanInstalled();
        DebugLog("FORCE_REMOVE: ScanInstalled done");
        auto freshOrphans = u.ScanDirectoryOrphans();
        DebugLog("FORCE_REMOVE: ScanDirectoryOrphans done");
        freshEntries.insert(freshEntries.end(), freshOrphans.begin(), freshOrphans.end());
        u.EnrichEntriesBackground(freshEntries);
        DebugLog("FORCE_REMOVE: EnrichEntries done");
        {
            std::lock_guard<std::mutex> lock(g_scanResultMutex);
            g_scanResultPending = std::move(freshEntries);
        }
        g_initialScanStarted = true;
        DebugLog("FORCE_REMOVE: done");
    } catch (...) {
        DebugLog("FORCE_REMOVE: CRASH - exception caught");
        PushNotification(L"Force remove failed", data->entry.displayName, false);
    }
    g_scanComplete.store(true);
    delete data;
    return 0;
}

struct ForceRemovalPipelineData {
    BlackHole::UninstallEntry entry;
    BlackHole::ScanDepth depth;
};

static unsigned __stdcall ForceRemovalPipelineThread(void* param) {
    auto* data = static_cast<ForceRemovalPipelineData*>(param);
        DebugLog("FORCE_THREAD: started");
    try {
        BlackHole::Uninstaller u;
        DebugLog("FORCE_THREAD: BackupRegistryKey");
        if (!data->entry.registryKey.empty())
            u.BackupRegistryKey(data->entry.displayName, data->entry.registryKey);
        DebugLog("FORCE_THREAD: ForceRemovalPipeline");
        auto result = u.ForceRemovalPipeline(data->entry, data->depth, g_createRestorePoint);
        DebugLog("FORCE_THREAD: pipeline done");
        BlackHole::GetLogger().LogUninstall(data->entry.displayName, true);
    } catch (...) {
        DebugLog("FORCE_THREAD: CAUGHT EXCEPTION");
    }
    DebugLog("FORCE_THREAD: done");
    delete data;
    return 0;
}

struct StandardUninstallData {
    BlackHole::UninstallEntry entry;
    int idx;
    BlackHole::ScanDepth depth;
};

static unsigned __stdcall StandardUninstallThread(void* param) {
    auto* data = static_cast<StandardUninstallData*>(param);
    try {
        DebugLog("STD_THREAD: started");
        DebugLog("THREAD: building command");
        std::wstring cmd = data->entry.uninstallString;
        if (data->entry.isMsiInstaller) {
            if (cmd.find(L"MsiExec") == std::wstring::npos &&
                cmd.find(L"msiexec") == std::wstring::npos) {
                cmd = L"msiexec.exe /x " + cmd;
            }
        }
        DebugLog(("THREAD: raw uninstallString=" + WideToUtf8(data->entry.uninstallString)).c_str());
        DebugLog(("THREAD: built cmd=" + WideToUtf8(cmd)).c_str());
        if (!cmd.empty() && cmd[0] != L'"' && cmd.find(L' ') != std::wstring::npos) {
            cmd = L"\"" + cmd + L"\"";
            DebugLog(("THREAD: quoted cmd=" + WideToUtf8(cmd)).c_str());
        }

        std::wstring exePath;
        std::wstring exeArgs;
        {
            std::wstring c = cmd;
            if (c.size() >= 2 && c[0] == L'"') {
                auto end = c.find(L'"', 1);
                if (end != std::wstring::npos) {
                    exePath = c.substr(1, end - 1);
                    exeArgs = c.substr(end + 1);
                }
            } else {
                auto sp = c.find(L' ');
                if (sp != std::wstring::npos) {
                    exePath = c.substr(0, sp);
                    exeArgs = c.substr(sp);
                } else {
                    exePath = c;
                }
            }
        }
        DebugLog(("THREAD: exePath=" + WideToUtf8(exePath)).c_str());
        DWORD attrs = GetFileAttributesW(exePath.c_str());
        DebugLog(("THREAD: GetFileAttributes=" + std::to_string(attrs) +
            " err=" + std::to_string(GetLastError())).c_str());

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
        cmdBuf.push_back(0);
        DebugLog("THREAD: calling CreateProcessW");
        bool processStarted = false;
        if (CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            DebugLog("THREAD: CreateProcessW OK, waiting...");
            WaitForSingleObject(pi.hProcess, 30000);
            DebugLog("THREAD: process done, closing handles");
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            processStarted = true;
        } else {
            DWORD err1 = GetLastError();
            DebugLog(("THREAD: CreateProcessW FAILED, error=" + std::to_string(err1)).c_str());
            DebugLog("THREAD: trying ShellExecuteW with raw uninstallString");
            HINSTANCE hInst = ShellExecuteW(NULL, L"open",
                data->entry.uninstallString.c_str(), NULL, NULL, SW_SHOWNORMAL);
            if ((INT_PTR)hInst > 32) {
                DebugLog("THREAD: ShellExecuteW OK");
                processStarted = true;
            } else {
                DWORD err2 = (DWORD)(INT_PTR)hInst;
                DebugLog(("THREAD: ShellExecuteW also FAILED, code=" + std::to_string(err2)).c_str());
                DebugLog("THREAD: trying ShellExecuteW with cmd string");
                hInst = ShellExecuteW(NULL, L"open", cmd.c_str(), NULL, NULL, SW_SHOWNORMAL);
                if ((INT_PTR)hInst > 32) {
                    DebugLog("THREAD: ShellExecuteW with cmd OK");
                    processStarted = true;
                } else {
                    DebugLog("THREAD: all launch methods failed");
                }
            }
        }

        DebugLog("THREAD: logging uninstall");
        BlackHole::GetLogger().LogUninstall(data->entry.displayName, false);

        if (processStarted) {
            PushNotification(L"Uninstall launched", data->entry.displayName, false);
            DebugLog("THREAD: starting ScanLeftovers");
            BlackHole::Uninstaller u;
            auto leftovers = u.ScanLeftovers(data->entry, data->depth);
            DebugLog("THREAD: ScanLeftovers done");
            {
                std::lock_guard<std::mutex> lock(g_forceRemovalMutex);
                g_leftoverItems = leftovers;
            }
            if (!leftovers.empty()) {
                g_popupEraseIdx = data->idx;
                DebugLog("THREAD: setting popup flag");
                g_showLeftoverPopup.store(true);
            }
            DebugLog("THREAD: rescan starting");
            auto freshEntries = u.ScanInstalled();
            DebugLog("THREAD: ScanInstalled done");
            auto freshOrphans = u.ScanDirectoryOrphans();
            DebugLog("THREAD: ScanDirectoryOrphans done");
            freshEntries.insert(freshEntries.end(), freshOrphans.begin(), freshOrphans.end());
            u.EnrichEntriesBackground(freshEntries);
            DebugLog("THREAD: EnrichEntries done");
            {
                std::lock_guard<std::mutex> lock(g_scanResultMutex);
                g_scanResultPending = std::move(freshEntries);
            }
            g_initialScanStarted = true;
            g_scanComplete.store(true);
            DebugLog("THREAD: done");
        } else {
            DebugLog("THREAD: skipping ScanLeftovers (process failed)");
            PushNotification(L"Could not launch uninstaller", data->entry.displayName, true);
        }
    } catch (...) {
        DebugLog("THREAD: CAUGHT EXCEPTION");
    }
    DebugLog("THREAD: setting running=false");
    g_standardUninstallRunning.store(false);
    delete data;
    return 0;
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

static LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ep) {
    const char* crashLog = CRASH_LOG_PATH ? CRASH_LOG_PATH : "crash_log.txt";
    FILE* f = nullptr;
    fopen_s(&f, crashLog, "w");
    if (!f) return EXCEPTION_EXECUTE_HANDLER;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "=== BLACKHOLE CRASH LOG ===\n");
    fprintf(f, "Date: %04d-%02d-%02d %02d:%02d:%02d\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    DWORD code = ep->ExceptionRecord->ExceptionCode;
    PVOID addr = ep->ExceptionRecord->ExceptionAddress;
    fprintf(f, "\nException Code: 0x%08lX\n", code);
    fprintf(f, "Exception Address: 0x%p\n", addr);
    fprintf(f, "Exception Flags: 0x%lX\n", ep->ExceptionRecord->ExceptionFlags);

    const char* exName = "UNKNOWN";
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:     exName = "ACCESS_VIOLATION"; break;
        case EXCEPTION_STACK_OVERFLOW:       exName = "STACK_OVERFLOW"; break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:   exName = "INT_DIVIDE_BY_ZERO"; break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:   exName = "FLT_DIVIDE_BY_ZERO"; break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:  exName = "ILLEGAL_INSTRUCTION"; break;
        case EXCEPTION_PRIV_INSTRUCTION:     exName = "PRIV_INSTRUCTION"; break;
        case EXCEPTION_IN_PAGE_ERROR:        exName = "IN_PAGE_ERROR"; break;
        case 0xE06D7363:                     exName = "C++_THROW_UNCAUGHT"; break;
    }
    fprintf(f, "Exception Name: %s\n", exName);

    if (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) {
        fprintf(f, "Access Type: %s\n",
            ep->ExceptionRecord->ExceptionInformation[0] == 0 ? "READ" :
            ep->ExceptionRecord->ExceptionInformation[0] == 1 ? "WRITE" : "EXECUTE");
        fprintf(f, "Access Address: 0x%p\n", (void*)ep->ExceptionRecord->ExceptionInformation[1]);
    }

    HMODULE hMod = NULL;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)addr, &hMod);
    char modName[MAX_PATH] = "";
    if (hMod) GetModuleFileNameA(hMod, modName, MAX_PATH);
    fprintf(f, "Module: %s\n", modName);

    CONTEXT* ctx = ep->ContextRecord;
    fprintf(f, "\n=== REGISTER STATE ===\n");
#ifdef _WIN64
    fprintf(f, "RAX: 0x%016llX  RBX: 0x%016llX\n", ctx->Rax, ctx->Rbx);
    fprintf(f, "RCX: 0x%016llX  RDX: 0x%016llX\n", ctx->Rcx, ctx->Rdx);
    fprintf(f, "RSI: 0x%016llX  RDI: 0x%016llX\n", ctx->Rsi, ctx->Rdi);
    fprintf(f, "RSP: 0x%016llX  RBP: 0x%016llX\n", ctx->Rsp, ctx->Rbp);
    fprintf(f, "RIP: 0x%016llX\n", ctx->Rip);
    fprintf(f, "R8:  0x%016llX  R9:  0x%016llX\n", ctx->R8, ctx->R9);
    fprintf(f, "R10: 0x%016llX  R11: 0x%016llX\n", ctx->R10, ctx->R11);
    fprintf(f, "R12: 0x%016llX  R13: 0x%016llX\n", ctx->R12, ctx->R13);
    fprintf(f, "R14: 0x%016llX  R15: 0x%016llX\n", ctx->R14, ctx->R15);
#else
    fprintf(f, "EAX: 0x%08lX  EBX: 0x%08lX\n", ctx->Eax, ctx->Ebx);
    fprintf(f, "ECX: 0x%08lX  EDX: 0x%08lX\n", ctx->Ecx, ctx->Edx);
    fprintf(f, "ESI: 0x%08lX  EDI: 0x%08lX\n", ctx->Esi, ctx->Edi);
    fprintf(f, "ESP: 0x%08lX  EBP: 0x%08lX\n", ctx->Esp, ctx->Ebp);
    fprintf(f, "EIP: 0x%08lX\n", ctx->Eip);
#endif

    fprintf(f, "\n=== STACK TRACE ===\n");
    SymInitialize(GetCurrentProcess(), NULL, TRUE);
    STACKFRAME64 frame = {};
    DWORD machineType;
#ifdef _WIN64
    machineType = IMAGE_FILE_MACHINE_AMD64;
    frame.AddrPC.Offset = ctx->Rip;
    frame.AddrFrame.Offset = ctx->Rbp;
    frame.AddrStack.Offset = ctx->Rsp;
#else
    machineType = IMAGE_FILE_MACHINE_I386;
    frame.AddrPC.Offset = ctx->Eip;
    frame.AddrFrame.Offset = ctx->Ebp;
    frame.AddrStack.Offset = ctx->Esp;
#endif
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Mode = AddrModeFlat;

    for (int i = 0; i < 64; i++) {
        if (!StackWalk64(machineType, GetCurrentProcess(), GetCurrentThread(),
            &frame, ctx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
            break;
        if (frame.AddrPC.Offset == 0) break;

        DWORD64 offset = 0;
        char symBuf[sizeof(SYMBOL_INFO) + MAX_PATH] = {};
        PSYMBOL_INFO sym = (PSYMBOL_INFO)symBuf;
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = MAX_PATH - 1;
        SymFromAddr(GetCurrentProcess(), frame.AddrPC.Offset, &offset, sym);

        DWORD lineDispl = 0;
        char lineBuf[MAX_PATH] = {};
        IMAGEHLP_LINE64 line = {};
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
        BOOL hasLine = SymGetLineFromAddr64(GetCurrentProcess(), frame.AddrPC.Offset, &lineDispl, &line);

        fprintf(f, "  #%02d  0x%p", i, (void*)frame.AddrPC.Offset);
        if (sym->Name[0]) fprintf(f, "  %s+0x%llX", sym->Name, offset);
        if (hasLine) fprintf(f, "  %s:%lu", line.FileName, line.LineNumber);
        fprintf(f, "\n");
    }
    SymCleanup(GetCurrentProcess());

    fprintf(f, "\n=== THREADS ===\n");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = { sizeof(te) };
        if (Thread32First(snap, &te)) {
            do {
                fprintf(f, "  Thread ID: %lu  (0x%lX)\n", te.th32ThreadID, te.th32ThreadID);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    fprintf(f, "\n=== END CRASH LOG ===\n");
    fclose(f);

    MessageBoxA(NULL,
        "Black Hole has crashed. A crash_log.txt has been written to the program directory.\n\n"
        "Please send crash_log.txt to the developer.",
        "Black Hole - CRASH", MB_OK);

    return EXCEPTION_EXECUTE_HANDLER;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
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

    g_hInstance = hInstance;

    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argc >= 3) {
            std::wstring cmd = argv[1];
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
                    bool isDir = std::filesystem::is_directory(filePath);
                    if (isDir) {
                        std::error_code ec;
                        std::uintmax_t count = std::filesystem::remove_all(filePath, ec);
                        if (ec.value() == 0 && count > 0) {
                            logType = BlackHole::LogEventType::DeletionSuccess;
                            errMsg = L"Removed " + std::to_wstring(count) + L" items";
                        } else {
                            logType = BlackHole::LogEventType::DeletionFailed;
                            errMsg = L"Failed (error " + std::to_wstring(ec.value()) + L")";
                            errCode = ec.value();
                        }
                    } else {
                        auto result = deletor.DeleteFileSafely(filePath);
                        logType = (result.result == BlackHole::DeletionResult::Success)
                            ? BlackHole::LogEventType::DeletionSuccess
                            : (result.result == BlackHole::DeletionResult::Scheduled_Reboot)
                                ? BlackHole::LogEventType::DeletionScheduled
                                : BlackHole::LogEventType::DeletionFailed;
                        errMsg = result.errorMessage;
                        errCode = result.errorCode;
                    }
                    }
                } else {
                    logType = BlackHole::LogEventType::DeletionBlocked;
                    errMsg = L"File is in the blacklist";
                }

                bool success = (logType == BlackHole::LogEventType::DeletionSuccess ||
                               logType == BlackHole::LogEventType::DeletionScheduled);
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
                        std::wstring label = trashed ? L"Recycled" : (success ? L"Deleted" : L"Failed");
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

                WNDCLASSEXW wc = {};
                wc.cbSize = sizeof(wc);
                wc.lpfnWndProc = DefWindowProcW;
                wc.hInstance = hInstance;
                wc.lpszClassName = L"BlackHoleToast";
                wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
                RegisterClassExW(&wc);

                int screenW = GetSystemMetrics(SM_CXSCREEN);
                int toastW = 320, toastH = 50;
                int toastX = screenW - toastW - 20;
                int toastY = GetSystemMetrics(SM_CYSCREEN) - toastH - 60;
                HWND hToast = CreateWindowExW(0, wc.lpszClassName, L"",
                    WS_POPUP | WS_VISIBLE, toastX, toastY, toastW, toastH,
                    NULL, NULL, hInstance, NULL);

                HBRUSH bgBrush = CreateSolidBrush(trashed ? RGB(12, 30, 20) : (success ? RGB(16, 40, 24) : RGB(40, 16, 16)));
                SetClassLongPtr(hToast, GCLP_HBRBACKGROUND, (LONG_PTR)bgBrush);

                HDC hdc = GetDC(hToast);
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, trashed ? RGB(60, 200, 140) : (success ? RGB(80, 220, 120) : RGB(220, 80, 80)));
                HFONT hFont = CreateFontW(16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
                SelectObject(hdc, hFont);
                const wchar_t* title = trashed ? L"MOVED TO TRASH" : (success ? L"DELETE SUCCESS" : L"DELETE FAILED");
                TextOutW(hdc, 14, 8, title, (int)wcslen(title));
                SetTextColor(hdc, RGB(140, 140, 150));
                HFONT hFontSmall = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
                SelectObject(hdc, hFontSmall);
                std::wstring shortPath = filePath;
                if (shortPath.size() > 38) shortPath = shortPath.substr(0, 35) + L"...";
                TextOutW(hdc, 14, 28, shortPath.c_str(), (int)shortPath.size());
                ReleaseDC(hToast, hdc);

                MSG msg;
                DWORD startTime = GetTickCount();
                while (GetTickCount() - startTime < 3500) {
                    if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                        TranslateMessage(&msg);
                        DispatchMessage(&msg);
                    }
                    Sleep(16);
                }

                DeleteObject(bgBrush);
                DeleteObject(hFont);
                DeleteObject(hFontSmall);
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
            if (cmd == L"--analyze") {
                g_selectedTab = 1;
                g_selectedFile = filePath;
                g_autoAnalyzeOnStart = true;
            }
        }
        if (argv) LocalFree(argv);
    }

    BlackHole::GetLogger().Initialize();
    LoadConfig();

    {
        static const wchar_t* kStalePaths[] = {
            L"Directory\\shell\\BlackHole_ForceDelete",
            L"Drive\\shell\\BlackHole_ForceDelete",
            L"AllFileSystemObjects\\shell\\BlackHole_ForceDelete",
            L"Directory\\shell\\BlackHole_Analyze",
            L"Drive\\shell\\BlackHole_Analyze",
            L"AllFileSystemObjects\\shell\\BlackHole_Analyze",
        };
        for (auto p : kStalePaths) {
            RegDeleteTreeW(HKEY_CLASSES_ROOT, p);
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

    style.Colors[ImGuiCol_PopupBg]      = ImVec4(0.04f, 0.04f, 0.05f, 1.0f);
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
        }
    }
    if (!g_fontDefault) g_fontDefault = io.Fonts->AddFontDefault();
    if (!g_fontSidebar) g_fontSidebar = g_fontDefault;
    if (!g_fontPill) g_fontPill = g_fontDefault;
    io.FontDefault = g_fontDefault;

    std::thread([]() { LoadLogs(); }).detach();
    g_forceDeleteInstalled = IsForceDeleteMenuInstalled();
    g_analyzeInspectInstalled = IsAnalyzeMenuInstalled();
    g_installStatus.store(g_forceDeleteInstalled || g_analyzeInspectInstalled);
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

            dl->AddRectFilled(wPos, ImVec2(wPos.x + wSize.x, wPos.y + wSize.y),
                Vec4ToU32(CLR_MAIN_BG), 12.0f);

            float sidebarW = g_hideSidebar ? 0.0f : SIDEBAR_W;

            if (!g_hideSidebar) {
                dl->AddRectFilled(ImVec2(wPos.x, wPos.y), ImVec2(wPos.x + SIDEBAR_W, wPos.y + wSize.y),
                    Vec4ToU32(CLR_SIDEBAR_BG), 12.0f);
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
                    float midY = sidebarTop + sidebarH / 2.0f;

                    float textTop = sidebarTop;
                    float textMid = midY - 40.0f;
                    float textBotStart = midY + 40.0f;
                    float textBot = sidebarBot;

                    ImVec4 sideTextColor = g_darkMode
                        ? ImVec4(1.0f, 1.0f, 1.0f, 1.0f)
                        : ImVec4(0.0f, 0.0f, 0.0f, 1.0f);

                    RenderSidebarTextGradient(sidebarText, charSpacing,
                        ImVec2(wPos.x, textTop), ImVec2(wPos.x + SIDEBAR_W, textMid),
                        0.0f, 1.0f, sideTextColor);

                    if (g_lineGlowEnabled) {
                        float lineX = wPos.x + SIDEBAR_W / 2.0f;
                        float linePad = 12.0f;
                        float lineTop = textBotStart + linePad;
                        float lineBot = textBot - linePad;
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

                    float logoW = 60.0f, logoH = 60.0f;
                    float logoX = wPos.x + (SIDEBAR_W - logoW) / 2.0f;
                    float logoY = midY - logoH / 2.0f;
                    dl->AddRectFilled(ImVec2(logoX, logoY), ImVec2(logoX + logoW, logoY + logoH),
                        Vec4ToU32(CLR_ELEM_BG), 8.0f);
                    dl->AddRect(ImVec2(logoX, logoY), ImVec2(logoX + logoW, logoY + logoH),
                        Vec4ToU32(CLR_STROKE), 8.0f, 0, 1.0f);

                    if (g_fontSidebar) ImGui::PushFont(g_fontSidebar);
                    const char* bText = "B";
                    ImVec2 bSize = ImGui::CalcTextSize(bText);
                    dl->AddText(ImVec2(logoX + (logoW - bSize.x) / 2, logoY + (logoH - bSize.y) / 2),
                        Vec4ToU32(CLR_TEXT), bText);
                    if (g_fontSidebar) ImGui::PopFont();
                }
            }

            float titleBarY = wPos.y;
            dl->AddRectFilled(ImVec2(wPos.x + sidebarW, titleBarY),
                ImVec2(wPos.x + contentRightX, titleBarY + TITLE_BAR_H),
                Vec4ToU32(CLR_SIDEBAR_BG));
            dl->AddRectFilled(ImVec2(wPos.x + sidebarW, titleBarY + TITLE_BAR_H - 1),
                ImVec2(wPos.x + contentRightX, titleBarY + TITLE_BAR_H),
                Vec4ToU32(CLR_STROKE));

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
                    if (g_isMaximized) {
                        float s = 4.0f;
                        float off = 2.5f;
                        ImU32 iconCol = IM_COL32(4, 4, 5, 255);
                        // back square (top-right)
                        dl->AddRect(ImVec2(maxX - s + off, btnY - s - off + 1.0f), ImVec2(maxX + s + off, btnY + s - off + 1.0f), iconCol, 0.5f, 0, 1.2f);
                        // front square (bottom-left)
                        dl->AddRect(ImVec2(maxX - s - off, btnY - s + off + 1.0f), ImVec2(maxX + s - off, btnY + s + off + 1.0f), iconCol, 0.5f, 0, 1.2f);
                    }
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
            float contentH = wSize.y - TITLE_BAR_H - TOOLBAR_H - 16.0f;

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
                        ImU32 btnText = IM_COL32(220, 80, 80, 255);

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
                                    IM_COL32(255, 255, 255, 8), 3.0f);
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
                                    cdl->AddText(ImVec2(ubX + 4.0f, ubY + 1.0f), IM_COL32(120, 235, 160, 255), "Restore");
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
                                cdl->AddText(ImVec2(clX + 8.0f, clY + 1.0f), IM_COL32(220, 80, 80, 255), "Clear");
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

                        const char* subText = "or click Select File below";
                        ImVec2 stSize = ImGui::CalcTextSize(subText);
                        cdl->AddText(ImVec2(centerX - stSize.x / 2, centerY + 40),
                            Vec4ToU32(CLR_TEXT_DIM), subText);

                        // Buttons at bottom of drop zone
                        float btnW = 130.0f, btnH = 34.0f;
                        float btnY2 = treeY + dropH - btnH - 16.0f;

                        ImVec2 selMin2(treeX + treeW / 2 - btnW / 2, btnY2);
                        ImVec2 selMax2(treeX + treeW / 2 + btnW / 2, btnY2 + btnH);
                        bool selHov2 = ImGui::IsMouseHoveringRect(selMin2, selMax2);
                        cdl->AddRectFilled(selMin2, selMax2, selHov2 ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 8.0f);
                        cdl->AddRect(selMin2, selMax2, Vec4ToU32(CLR_STROKE), 8.0f, 0, 1.0f);
                        const char* selLabel = "Select File";
                        ImVec2 selLabelSize = ImGui::CalcTextSize(selLabel);
                        cdl->AddText(ImVec2((selMin2.x + selMax2.x - selLabelSize.x) / 2, (selMin2.y + selMax2.y - selLabelSize.y) / 2),
                            Vec4ToU32(CLR_TEXT), selLabel);

                        if (io.MouseClicked[0] && selHov2)
                            SelectFile(g_hMainWindow);

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
                    float btnW = 110.0f, btnH = 32.0f;
                    float btnY = treeY + selBarH + 10.0f;

                    // Select File button
                    ImVec2 selMin(treeX, btnY);
                    ImVec2 selMax(treeX + btnW, btnY + btnH);
                    bool selHov = ImGui::IsMouseHoveringRect(selMin, selMax);
                    cdl->AddRectFilled(selMin, selMax, selHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                    cdl->AddRect(selMin, selMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                    ImVec2 selT = ImGui::CalcTextSize("Select File");
                    cdl->AddText(ImVec2((selMin.x + selMax.x - selT.x) / 2, (selMin.y + selMax.y - selT.y) / 2), Vec4ToU32(CLR_TEXT), "Select File");

                    // Analyze button
                    ImVec2 anaMin(treeX + btnW + 8, btnY);
                    ImVec2 anaMax(treeX + btnW * 2 + 8, btnY + btnH);
                    bool canAnalyze = !g_selectedFile.empty() && !g_analysisRunning;
                    bool anaHov = canAnalyze && ImGui::IsMouseHoveringRect(anaMin, anaMax);
                    cdl->AddRectFilled(anaMin, anaMax, anaHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG), 6.0f);
                    cdl->AddRect(anaMin, anaMax, Vec4ToU32(CLR_STROKE), 6.0f, 0, 1.0f);
                    ImVec2 anaT = ImGui::CalcTextSize(g_analysisRunning ? "Analyzing..." : "Analyze");
                    cdl->AddText(ImVec2((anaMin.x + anaMax.x - anaT.x) / 2, (anaMin.y + anaMax.y - anaT.y) / 2),
                        canAnalyze ? Vec4ToU32(CLR_TEXT) : Vec4ToU32(CLR_TEXT_DIM), g_analysisRunning ? "Analyzing..." : "Analyze");

                    // Delete button
                    ImVec2 delMin(treeX + btnW * 2 + 16, btnY);
                    ImVec2 delMax(treeX + btnW * 3 + 16, btnY + btnH);
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

                        auto DrawSectionCard = [&](const char* label, int count, ImU32 accentCol, bool hasItems, bool* expanded) {
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
                                IM_COL32(255, 255, 255, 255), scoreBuf);

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
                                IM_COL32(255, 255, 255, 255), confirmTitle);

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
                                    IM_COL32(255, 255, 255, 255), bMsg);
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
                                cdl->AddRectFilled(bCancelMin, bCancelMax, bCancelHov ? IM_COL32(60, 60, 70, 255) : IM_COL32(40, 40, 50, 255), 4.0f);
                                cdl->AddRect(bCancelMin, bCancelMax, IM_COL32(80, 80, 100, 200), 4.0f, 0, 1.0f);
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
                                IM_COL32(255, 255, 255, 255), clTitle);

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
                                IM_COL32(180, 190, 210, 255), "Cancel");

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

                    if (!diskCachePreloaded && !g_uninstallEntries.empty() && g_pd3dDevice) {
                        CreateDefaultIcon();
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
                        float refreshW = 55.0f;
                        float columnsW = 65.0f;
                        float filtersW = 55.0f;
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
                        cdl->AddText(ImVec2(cPos.x + pad, rowY + 4.0f),
                            Vec4ToU32(ImVec4(0.56f, 0.56f, 0.60f, 1.0f)),
                            std::to_string((int)g_filteredIndicesCache.size()).c_str());

                        float numW = ImGui::CalcTextSize(std::to_string((int)g_filteredIndicesCache.size()).c_str()).x;
                        float lx = cPos.x + pad + numW + 8.0f;
                        float legendY = innerY + 3.0f;
                        float pillW = 20.0f;
                        float pillH = 14.0f;
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
                                ImU32 darkHalf = IM_COL32(18, 18, 24, 255);
                                cdl->AddRectFilled(pillMin, pillMax, darkHalf, 6.0f);
                                ImVec2 clipMin(lx, legendY);
                                ImVec2 clipMax(lx + pillW * 0.45f, legendY + pillH);
                                cdl->PushClipRect(clipMin, clipMax, true);
                                cdl->AddRectFilled(pillMin, pillMax, colColor, 6.0f);
                                cdl->PopClipRect();
                            }

                            ImU32 borderColor = isActive ? colColor : IM_COL32(50, 50, 60, 180);
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
                                fg->AddRectFilled(ttMin, ttMax, Vec4ToU32(ImVec4(0.10f, 0.10f, 0.13f, 0.96f)), 5.0f);
                                fg->AddRect(ttMin, ttMax, colColor, 5.0f, 0, 1.0f);
                                fg->AddText(ttPos, IM_COL32(220, 220, 230, 255), item.label);
                            }
                            lx += pillW + 6.0f;
                        }

                        ImVec2 searchMin(searchX, rowY);
                        ImVec2 searchMax(searchX + searchW, rowY + rowH);
                        ImU32 searchBorder = g_uninstallFilterFocused ?
                            Vec4ToU32(CLR_ACCENT) : IM_COL32(40, 40, 50, 255);
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
                                Vec4ToU32(ImVec4(1.0f, 1.0f, 1.0f, 1.0f)), g_uninstallFilter.c_str());
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
                            float capsuleR = rowH / 2.0f;
                            ImVec2 colBtnMin(columnsX, rowY);
                            ImVec2 colBtnMax(columnsX + columnsW, rowY + rowH);
                            bool colBtnHov = io.MousePos.x >= colBtnMin.x && io.MousePos.x <= colBtnMax.x &&
                                             io.MousePos.y >= colBtnMin.y && io.MousePos.y <= colBtnMax.y;
                            ImU32 colBtnBg = colBtnHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG);
                            cdl->AddRectFilled(colBtnMin, colBtnMax, colBtnBg, capsuleR);
                            ImU32 colBtnBorder = colBtnHov ? IM_COL32(142, 132, 255, 220) : IM_COL32(142, 132, 255, 120);
                            cdl->AddRect(colBtnMin, colBtnMax, colBtnBorder, capsuleR, 0, colBtnHov ? 1.5f : 1.0f);
                            ImVec2 colTxt = ImGui::CalcTextSize("Columns");
                            cdl->AddText(ImVec2(colBtnMin.x + (columnsW - colTxt.x) / 2, colBtnMin.y + 3),
                                Vec4ToU32(ImVec4(0.85f, 0.85f, 0.88f, 1.0f)), "Columns");
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
                            ImVec2 fBtnMin(filtersX, rowY);
                            ImVec2 fBtnMax(filtersX + filtersW, rowY + rowH);
                            bool fBtnHov = io.MousePos.x >= fBtnMin.x && io.MousePos.x <= fBtnMax.x &&
                                           io.MousePos.y >= fBtnMin.y && io.MousePos.y <= fBtnMax.y;
                            float capsuleR = rowH / 2.0f;
                            ImU32 fBtnBg = fBtnHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG);
                            cdl->AddRectFilled(fBtnMin, fBtnMax, fBtnBg, capsuleR);
                            ImU32 fBtnBorder = anyFilterOff
                                ? (fBtnHov ? IM_COL32(220, 180, 80, 240) : IM_COL32(220, 180, 80, 160))
                                : (fBtnHov ? IM_COL32(220, 180, 80, 220) : IM_COL32(220, 180, 80, 100));
                            cdl->AddRect(fBtnMin, fBtnMax, fBtnBorder, capsuleR, 0, fBtnHov ? 1.5f : 1.0f);
                            ImVec2 fTxt = ImGui::CalcTextSize("Filters");
                            cdl->AddText(ImVec2(fBtnMin.x + (filtersW - fTxt.x) / 2, fBtnMin.y + 3),
                                Vec4ToU32(ImVec4(0.85f, 0.85f, 0.88f, 1.0f)), "Filters");
                            if (fBtnHov && io.MouseClicked[0]) {
                                g_showFilterChooser = !g_showFilterChooser;
                            }
                        }

                        if (g_showColumnChooser) {
                            ImVec2 popPos(columnsX, rowY + rowH + 4.0f);
                            ImGui::SetNextWindowPos(popPos);
                            ImGui::SetNextWindowSize(ImVec2(160, 0));
                            ImGui::Begin("##colChooser", &g_showColumnChooser,
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
                        }

                        if (g_showFilterChooser) {
                            ImVec2 popPos(filtersX, rowY + rowH + 4.0f);
                            ImGui::SetNextWindowPos(popPos);
                            ImGui::SetNextWindowSize(ImVec2(160, 0));
                            ImGui::Begin("##filterChooser", &g_showFilterChooser,
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
                        }

                        {
                            float capsuleR = rowH / 2.0f;
                            ImVec2 refMin(rightX, rowY);
                            ImVec2 refMax(rightX + refreshW, rowY + rowH);
                            bool refHover = io.MousePos.x >= refMin.x && io.MousePos.x <= refMax.x &&
                                            io.MousePos.y >= refMin.y && io.MousePos.y <= refMax.y;
                            ImU32 refBg = refHover ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_ELEM_BG);
                            cdl->AddRectFilled(refMin, refMax, refBg, capsuleR);
                            ImU32 refBorder = refHover ? IM_COL32(80, 200, 160, 220) : IM_COL32(80, 200, 160, 120);
                            cdl->AddRect(refMin, refMax, refBorder, capsuleR, 0, refHover ? 1.5f : 1.0f);
                            ImVec2 refTxt = ImGui::CalcTextSize("Refresh");
                            cdl->AddText(ImVec2(refMin.x + (refreshW - refTxt.x) / 2, refMin.y + 3),
                                Vec4ToU32(ImVec4(0.85f, 0.85f, 0.88f, 1.0f)), "Refresh");
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
                    float tableH = innerH - 4.0f;

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
                    ImGui::PushStyleColor(ImGuiCol_TableRowBgAlt, ImVec4(0.035f, 0.035f, 0.043f, 1.0f));
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
                        ImGuiTableFlags_BordersInnerV |
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
                                ImU32 checkBg = isChecked ? Vec4ToU32(CLR_ACCENT) : IM_COL32(40, 40, 50, 255);
                                ImU32 checkBorder = isChecked ? Vec4ToU32(CLR_ACCENT) : IM_COL32(80, 80, 100, 200);
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
                                        Vec4ToU32(ImVec4(0.22f, 0.22f, 0.28f, 1.0f)), 3.0f);
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

                        if (filtersActive) {
                            float statusY = cPos.y + cSize.y - 16.0f;
                            std::string resetStr = "Reset Filters";
                            ImVec2 resetSz = ImGui::CalcTextSize(resetStr.c_str());
                            float resetX = cPos.x + cSize.x - pad - resetSz.x;
                            ImVec2 resetMin(resetX, statusY);
                            ImVec2 resetMax(resetX + resetSz.x, statusY + resetSz.y);
                            bool resetHov = io.MousePos.x >= resetMin.x && io.MousePos.x <= resetMax.x &&
                                            io.MousePos.y >= resetMin.y && io.MousePos.y <= resetMax.y;
                            cdl->AddText(resetMin, Vec4ToU32(resetHov ?
                                ImVec4(0.90f, 0.50f, 0.50f, 1.0f) :
                                ImVec4(0.55f, 0.35f, 0.38f, 1.0f)), resetStr.c_str());
                            if (resetHov && io.MouseClicked[0]) {
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
                        }
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
                                g_standardUninstallEntry = selEntry;
                                g_standardUninstallIdx = g_ctxMenuIdx;
                                g_pendingStandardUninstall = true;
                                g_ctxMenuIdx = -1;
                                g_selectedUninstallIdx = -1;
                                ImGui::CloseCurrentPopup();
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

                            {
                                int selCount = 0;
                                for (auto s : g_rowSelected) if (s) selCount++;
                                if (selCount > 0) {
                                    char delSelLabel[64];
                                    snprintf(delSelLabel, sizeof(delSelLabel), "Uninstall Selected (%d)", selCount);
                                    if (ImGui::MenuItem(delSelLabel)) {
                                        std::vector<int> selectedIndices;
                                        std::vector<BlackHole::UninstallEntry> selectedEntries;
                                        for (int si = 0; si < (int)g_rowSelected.size(); si++) {
                                            if (g_rowSelected[si] && si < (int)g_uninstallEntries.size()) {
                                                selectedIndices.push_back(si);
                                                selectedEntries.push_back(g_uninstallEntries[si]);
                                            }
                                        }
                                        BlackHole::ScanDepth depthCopy = g_scanDepth;
                                        g_rowSelected.assign(g_rowSelected.size(), false);
                                        g_ctxMenuIdx = -1;
                                        ImGui::CloseCurrentPopup();
                                        g_scanComplete.store(false);
                                        LaunchBigStackThread([selectedIndices, selectedEntries, depthCopy]() {
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
                                                        } else {
                                                            uninstallerRan = false;
                                                        }
                                                    }
                                                    if (uninstallerRan) {
                                                        std::this_thread::sleep_for(std::chrono::seconds(3));
                                                    }
                                                }
                                                if (!uninstallerRan) {
                                                    PushNotification(L"No uninstaller found, scanning leftovers", se.displayName, false);
                                                    BlackHole::Uninstaller uScan;
                                                    auto leftovers = uScan.ScanLeftovers(se, BlackHole::ScanDepth::Advanced);
                                                    for (auto& item : leftovers) item.checked = true;
                                                    allLeftovers.insert(allLeftovers.end(), leftovers.begin(), leftovers.end());
                                                    BlackHole::Uninstaller uReg;
                                                    uReg.RemoveRegistryEntry(se);
                                                } else {
                                                    BlackHole::Uninstaller u;
                                                    auto leftovers = u.ScanLeftovers(se, depthCopy);
                                                    allLeftovers.insert(allLeftovers.end(), leftovers.begin(), leftovers.end());
                                                }
                                            }
                                            for (size_t i = 0; i < selectedEntries.size(); i++) {
                                                BlackHole::Uninstaller u;
                                                u.RemoveRegistryEntry(selectedEntries[i]);
                                            }
                                            for (auto& item : allLeftovers) {
                                                item.checked = true;
                                            }
                                            BlackHole::Uninstaller uFilter;
                                            auto allInstalled = uFilter.ScanInstalled();
                                            allLeftovers.erase(
                                                std::remove_if(allLeftovers.begin(), allLeftovers.end(),
                                                    [&](const BlackHole::LeftoverItem& item) {
                                                        if (item.type == BlackHole::LeftoverItem::RegistryKey) return false;
                                                        for (auto& app : allInstalled) {
                                                            if (app.installPath.empty()) continue;
                                                            std::wstring appLower = app.installPath;
                                                            std::transform(appLower.begin(), appLower.end(), appLower.begin(), ::towlower);
                                                            std::wstring itemLower = item.path;
                                                            std::transform(itemLower.begin(), itemLower.end(), itemLower.begin(), ::towlower);
                                                            if (itemLower == appLower || itemLower.find(appLower + L"\\") == 0) {
                                                                bool isCurrentEntry = false;
                                                                for (auto& se : selectedEntries) {
                                                                    std::wstring seLower = se.installPath;
                                                                    std::transform(seLower.begin(), seLower.end(), seLower.begin(), ::towlower);
                                                                    if (appLower == seLower) { isCurrentEntry = true; break; }
                                                                }
                                                                if (!isCurrentEntry) return true;
                                                            }
                                                        }
                                                        return false;
                                                    }),
                                                allLeftovers.end());
                                            std::vector<std::wstring> leftoverFiles;
                                            for (auto& item : allLeftovers) {
                                                if (item.type == BlackHole::LeftoverItem::File) {
                                                    leftoverFiles.push_back(item.path);
                                                }
                                            }
                                            if (!leftoverFiles.empty()) {
                                                DetectLockingProcesses(leftoverFiles);
                                            }
                                            if (!allLeftovers.empty()) {
                                                {
                                                    std::lock_guard<std::mutex> lock(g_forceRemovalMutex);
                                                    g_leftoverItems = allLeftovers;
                                                }
                                                g_showLeftoverPopup.store(true);
                                            }
                                            BlackHole::Uninstaller u;
                                            auto freshEntries = u.ScanInstalled();
                                            auto freshOrphans = u.ScanDirectoryOrphans();
                                            freshEntries.insert(freshEntries.end(), freshOrphans.begin(), freshOrphans.end());
                                            u.EnrichEntriesBackground(freshEntries);
                                            {
                                                std::lock_guard<std::mutex> lock(g_scanResultMutex);
                                                g_scanResultPending = std::move(freshEntries);
                                            }
                                            g_initialScanStarted = true;
                                            PushNotification(L"Batch uninstall complete", std::to_wstring(selectedEntries.size()) + L" programs processed", false);
                                            } catch (...) {
                                                PushNotification(L"Batch uninstall failed", L"An error occurred", false);
                                            }
                                            g_scanComplete.store(true);
                                            g_iconThreadGeneration.store(0);
                                        });
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
                    float settingsContentH = 540.0f;
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
                        float cardH = 120.0f;
                        cdl->AddRectFilled(ImVec2(sX, y), ImVec2(sX + cardW, y + cardH), cardBg, 6.0f);
                        cdl->AddRect(ImVec2(sX, y), ImVec2(sX + cardW, y + cardH), cardBorder, 6.0f, 0, 1.0f);
                        float curY = drawSectionHeader(sX, y, "Context Menu");

                        cdl->AddText(ImVec2(sX + 14, curY + 6), labelCol, "Force Delete");

                        ImVec2 fdInstMin(sX + 130, curY);
                        ImVec2 fdInstMax(sX + 130 + 80, curY + 28);
                        bool fdInstHov = ImGui::IsMouseHoveringRect(fdInstMin, fdInstMax);
                        cdl->AddRectFilled(fdInstMin, fdInstMax, fdInstHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_SIDEBAR_BG), 4.0f);
                        cdl->AddRect(fdInstMin, fdInstMax, cardBorder, 4.0f, 0, 1.0f);
                        ImVec2 fdInstT = ImGui::CalcTextSize("Install");
                        cdl->AddText(ImVec2((fdInstMin.x + fdInstMax.x - fdInstT.x) / 2, (fdInstMin.y + fdInstMax.y - fdInstT.y) / 2),
                            labelCol, "Install");

                        ImVec2 fdUninstMin(sX + 216, curY);
                        ImVec2 fdUninstMax(sX + 216 + 80, curY + 28);
                        bool fdUninstHov = ImGui::IsMouseHoveringRect(fdUninstMin, fdUninstMax);
                        cdl->AddRectFilled(fdUninstMin, fdUninstMax, fdUninstHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_SIDEBAR_BG), 4.0f);
                        cdl->AddRect(fdUninstMin, fdUninstMax, cardBorder, 4.0f, 0, 1.0f);
                        ImVec2 fdUninstT = ImGui::CalcTextSize("Uninstall");
                        cdl->AddText(ImVec2((fdUninstMin.x + fdUninstMax.x - fdUninstT.x) / 2, (fdUninstMin.y + fdUninstMax.y - fdUninstT.y) / 2),
                            labelCol, "Uninstall");

                        bool fdInstalled = g_forceDeleteInstalled;
                        cdl->AddText(ImVec2(sX + 306, curY + 6),
                            fdInstalled ? IM_COL32(60, 180, 80, 255) : IM_COL32(180, 60, 60, 255),
                            fdInstalled ? "INSTALLED" : "NOT INSTALLED");

                        ImVec2 fdHelpMin(sX + 410, curY + 6);
                        ImVec2 fdHelpMax(sX + 424, curY + 22);
                        bool fdHelpHov = ImGui::IsMouseHoveringRect(fdHelpMin, fdHelpMax);
                        cdl->AddText(ImVec2(fdHelpMin.x, fdHelpMin.y),
                            fdHelpHov ? headerCol : dimCol, "(?)");
                        if (fdHelpHov) {
                            ImGui::BeginTooltip();
                            ImGui::PushTextWrapPos(350.0f);
                            ImGui::TextColored(ImVec4(0.9f, 0.4f, 0.4f, 1.0f), "FORCE DELETE");
                            ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.92f, 1.0f),
                                "Adds a Force Delete option to the right-click context menu. "
                                "Force Delete permanently removes files and leftover registry entries.");
                            ImGui::PopTextWrapPos();
                            ImGui::EndTooltip();
                        }

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            if (m.x >= fdInstMin.x && m.x <= fdInstMax.x && m.y >= fdInstMin.y && m.y <= fdInstMax.y) {
                                g_forceDeleteInstalled = InstallForceDeleteMenu();
                                PushNotification(g_forceDeleteInstalled ? L"INSTALLED" : L"FAILED",
                                    L"Force Delete context menu", !g_forceDeleteInstalled);
                            }
                            if (m.x >= fdUninstMin.x && m.x <= fdUninstMax.x && m.y >= fdUninstMin.y && m.y <= fdUninstMax.y) {
                                g_forceDeleteInstalled = !UninstallForceDeleteMenu();
                                PushNotification(!g_forceDeleteInstalled ? L"UNINSTALLED" : L"FAILED",
                                    L"Force Delete removed", true);
                            }
                        }

                        curY += 38.0f;

                        cdl->AddText(ImVec2(sX + 14, curY + 6), labelCol, "Analyze & Inspect");

                        ImVec2 aiInstMin(sX + 130, curY);
                        ImVec2 aiInstMax(sX + 130 + 80, curY + 28);
                        bool aiInstHov = ImGui::IsMouseHoveringRect(aiInstMin, aiInstMax);
                        cdl->AddRectFilled(aiInstMin, aiInstMax, aiInstHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_SIDEBAR_BG), 4.0f);
                        cdl->AddRect(aiInstMin, aiInstMax, cardBorder, 4.0f, 0, 1.0f);
                        ImVec2 aiInstT = ImGui::CalcTextSize("Install");
                        cdl->AddText(ImVec2((aiInstMin.x + aiInstMax.x - aiInstT.x) / 2, (aiInstMin.y + aiInstMax.y - aiInstT.y) / 2),
                            labelCol, "Install");

                        ImVec2 aiUninstMin(sX + 216, curY);
                        ImVec2 aiUninstMax(sX + 216 + 80, curY + 28);
                        bool aiUninstHov = ImGui::IsMouseHoveringRect(aiUninstMin, aiUninstMax);
                        cdl->AddRectFilled(aiUninstMin, aiUninstMax, aiUninstHov ? Vec4ToU32(CLR_ELEM_BG_HOVER) : Vec4ToU32(CLR_SIDEBAR_BG), 4.0f);
                        cdl->AddRect(aiUninstMin, aiUninstMax, cardBorder, 4.0f, 0, 1.0f);
                        ImVec2 aiUninstT = ImGui::CalcTextSize("Uninstall");
                        cdl->AddText(ImVec2((aiUninstMin.x + aiUninstMax.x - aiUninstT.x) / 2, (aiUninstMin.y + aiUninstMax.y - aiUninstT.y) / 2),
                            labelCol, "Uninstall");

                        bool aiInstalled = g_analyzeInspectInstalled;
                        cdl->AddText(ImVec2(sX + 306, curY + 6),
                            aiInstalled ? IM_COL32(60, 180, 80, 255) : IM_COL32(180, 60, 60, 255),
                            aiInstalled ? "INSTALLED" : "NOT INSTALLED");

                        ImVec2 aiHelpMin(sX + 410, curY + 6);
                        ImVec2 aiHelpMax(sX + 424, curY + 22);
                        bool aiHelpHov = ImGui::IsMouseHoveringRect(aiHelpMin, aiHelpMax);
                        cdl->AddText(ImVec2(aiHelpMin.x, aiHelpMin.y),
                            aiHelpHov ? headerCol : dimCol, "(?)");
                        if (aiHelpHov) {
                            ImGui::BeginTooltip();
                            ImGui::PushTextWrapPos(350.0f);
                            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "ANALYZE & INSPECT");
                            ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.92f, 1.0f),
                                "Adds an Analyze & Inspect option to the right-click context menu. "
                                "Scans the selected program's install folder, registry entries, locked files, and dependencies.");
                            ImGui::PopTextWrapPos();
                            ImGui::EndTooltip();
                        }

                        if (io.MouseClicked[0]) {
                            ImVec2 m = io.MousePos;
                            if (m.x >= aiInstMin.x && m.x <= aiInstMax.x && m.y >= aiInstMin.y && m.y <= aiInstMax.y) {
                                g_analyzeInspectInstalled = InstallAnalyzeMenu();
                                PushNotification(g_analyzeInspectInstalled ? L"INSTALLED" : L"FAILED",
                                    L"Analyze & Inspect context menu", !g_analyzeInspectInstalled);
                            }
                            if (m.x >= aiUninstMin.x && m.x <= aiUninstMax.x && m.y >= aiUninstMin.y && m.y <= aiUninstMax.y) {
                                g_analyzeInspectInstalled = !UninstallAnalyzeMenu();
                                PushNotification(!g_analyzeInspectInstalled ? L"UNINSTALLED" : L"FAILED",
                                    L"Analyze & Inspect removed", true);
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
                            ImGui::PushStyleColor(ImGuiCol_FrameBg, Vec4ToU32(CLR_SIDEBAR_BG));
                            ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, Vec4ToU32(CLR_ELEM_BG_HOVER));
                            ImGui::PushStyleColor(ImGuiCol_Border, cardBorder);
                            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
                            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6, 4));
                            if (ImGui::ColorEdit3("##GlowColor", g_sidebarGlowColor,
                                ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel | ImGuiColorEditFlags_AlphaPreview)) {
                                SaveConfig();
                            }
                            ImGui::PopStyleVar(2);
                            ImGui::PopStyleColor(3);
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
                            ImGui::PushStyleColor(ImGuiCol_FrameBg, Vec4ToU32(CLR_SIDEBAR_BG));
                            ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, Vec4ToU32(CLR_ELEM_BG_HOVER));
                            ImGui::PushStyleColor(ImGuiCol_Border, cardBorder);
                            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
                            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6, 4));
                            if (ImGui::ColorEdit3("##LineColor", g_lineGlowColor,
                                ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel | ImGuiColorEditFlags_AlphaPreview)) {
                                SaveConfig();
                            }
                            ImGui::PopStyleVar(2);
                            ImGui::PopStyleColor(3);
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
                            cdl->AddRectFilled(lineMin, lineMax, IM_COL32(20, 20, 24, 255), 1.0f);

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
                            cdl->AddCircleFilled(ImVec2(grabX, grabY), grabR, IM_COL32(4, 4, 5, 255), 16);
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

                    // Draw scrollbar indicator if content overflows
                    {
                        float settingsContentH = 540.0f;
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
                                IM_COL32(255, 255, 255, 20), 2.0f);
                            cdl->AddRectFilled(ImVec2(sbX, thumbY), ImVec2(sbX + 4, thumbY + thumbH),
                                IM_COL32(255, 255, 255, 80), 2.0f);
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
                        g_iconThreadRunning.store(false);
                        g_sizeCalcDone.store(true);
                        g_iconThreadGeneration.store(0);
                        g_uninstallEntries.erase(g_uninstallEntries.begin() + g_popupEraseIdx);
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
                                ImGui::TextWrapped("%s", fullPathUtf8.c_str());
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
                            g_iconThreadRunning.store(false);
                            g_sizeCalcDone.store(true);
                            g_iconThreadGeneration.store(0);
                            g_uninstallEntries.erase(g_uninstallEntries.begin() + g_popupEraseIdx);
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

            pdl->AddText(ImVec2(wP.x + 16, wP.y + 12), IM_COL32(255, 255, 255, 255),
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

                ImU32 dockBg = Vec4ToU32(ImVec4(0.024f, 0.024f, 0.028f, 1.0f));
                ddl->AddRectFilled(ImVec2(dockLeft, dockTop), ImVec2(dockLeft + dockW, dockBot), dockBg, 0.0f);
                ddl->AddRectFilled(ImVec2(dockLeft, dockTop), ImVec2(dockLeft + 1, dockBot), IM_COL32(255, 255, 255, 8));

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

                    ImU32 lineCol = isActive ? IM_COL32(
                        (int)(g_sidebarGlowColor[0] * 255),
                        (int)(g_sidebarGlowColor[1] * 255),
                        (int)(g_sidebarGlowColor[2] * 255), 255)
                        : IM_COL32(0, 0, 0, 0);
                    float lineW = 2.5f;
                    float lineX = dockLeft;
                    float lineTop = btnTop + 8.0f;
                    float lineBot = btnBot - 8.0f;

                    if (isActive && g_sidebarGlowEnabled) {
                        int glowR = (int)(g_sidebarGlowColor[0] * 255);
                        int glowG = (int)(g_sidebarGlowColor[1] * 255);
                        int glowB = (int)(g_sidebarGlowColor[2] * 255);
                        int glowA = (int)(dockPulse * 60);
                        for (int g = 3; g >= 1; g--) {
                            float spread = (float)g * 1.5f;
                            ImU32 glowCol = IM_COL32(glowR, glowG, glowB, glowA / (g + 1));
                            ddl->AddRectFilled(ImVec2(lineX - spread, lineTop), ImVec2(lineX + lineW + spread, lineBot), glowCol, 1.0f);
                        }
                    }
                    ddl->AddRectFilled(ImVec2(lineX, lineTop), ImVec2(lineX + lineW, lineBot), lineCol, 1.0f);

                    float iconCX = dockLeft + dockW / 2.0f;
                    float iconCY = btnTop + btnH / 2.0f;
                    float s = 9.5f;
                    float lw = 1.8f;
                    ImU32 iconCol = isActive ? IM_COL32(142, 132, 255, 255)
                                   : isHov ? IM_COL32(200, 200, 210, 255)
                                   : IM_COL32(110, 110, 125, 255);

                    if (i == 0) {
                        // Uninstall: shield with arrow pointing up-out
                        float sw = s * 0.7f, sh = s * 0.9f;
                        ImVec2 pts[5] = {
                            ImVec2(iconCX, iconCY - sh),
                            ImVec2(iconCX + sw, iconCY - sh * 0.5f),
                            ImVec2(iconCX + sw * 0.8f, iconCY + sh * 0.7f),
                            ImVec2(iconCX, iconCY + sh),
                            ImVec2(iconCX - sw * 0.8f, iconCY + sh * 0.7f),
                        };
                        ddl->AddPolyline(pts, 5, iconCol, ImDrawFlags_Closed, lw);
                        // arrow pointing up inside shield
                        float aw = s * 0.25f, ah = s * 0.4f;
                        float ay = iconCY + s * 0.1f;
                        ddl->AddLine(ImVec2(iconCX, ay - ah), ImVec2(iconCX, ay + ah * 0.5f), iconCol, lw);
                        ddl->AddLine(ImVec2(iconCX, ay - ah), ImVec2(iconCX - aw, ay - ah * 0.2f), iconCol, lw);
                        ddl->AddLine(ImVec2(iconCX, ay - ah), ImVec2(iconCX + aw, ay - ah * 0.2f), iconCol, lw);
                        // horizontal line at arrow base
                        ddl->AddLine(ImVec2(iconCX - aw * 0.8f, ay + ah * 0.5f), ImVec2(iconCX + aw * 0.8f, ay + ah * 0.5f), iconCol, lw);
                    } else if (i == 1) {
                        // Delete: trash can - lid with handle, body, bottom line
                        float lidW = s * 0.7f, lidH = s * 0.14f;
                        float lidY = iconCY - s * 0.55f;
                        // lid top surface
                        ddl->AddLine(ImVec2(iconCX - lidW * 0.5f, lidY), ImVec2(iconCX + lidW * 0.5f, lidY), iconCol, lw);
                        // lid rim
                        ddl->AddLine(ImVec2(iconCX - lidW * 0.45f, lidY + lidH), ImVec2(iconCX + lidW * 0.45f, lidY + lidH), iconCol, lw);
                        // handle on lid
                        float hw = s * 0.2f;
                        ddl->AddLine(ImVec2(iconCX - hw, lidY - s * 0.12f), ImVec2(iconCX + hw, lidY - s * 0.12f), iconCol, lw);
                        ddl->AddLine(ImVec2(iconCX - hw, lidY - s * 0.12f), ImVec2(iconCX - hw, lidY), iconCol, lw);
                        ddl->AddLine(ImVec2(iconCX + hw, lidY - s * 0.12f), ImVec2(iconCX + hw, lidY), iconCol, lw);
                        // body - tapered trapezoid
                        float bTop = lidY + lidH + s * 0.08f;
                        float bBot = iconCY + s * 0.65f;
                        float bTopW = s * 0.4f, bBotW = s * 0.32f;
                        ddl->AddLine(ImVec2(iconCX - bTopW, bTop), ImVec2(iconCX - bBotW, bBot), iconCol, lw);
                        ddl->AddLine(ImVec2(iconCX + bTopW, bTop), ImVec2(iconCX + bBotW, bBot), iconCol, lw);
                        // bottom line
                        ddl->AddLine(ImVec2(iconCX - bBotW, bBot), ImVec2(iconCX + bBotW, bBot), iconCol, lw);
                        // two vertical ribs on body
                        float ribX = s * 0.15f;
                        ddl->AddLine(ImVec2(iconCX - ribX, bTop + s * 0.12f), ImVec2(iconCX - ribX * 0.8f, bBot - s * 0.1f), iconCol, lw * 0.8f);
                        ddl->AddLine(ImVec2(iconCX + ribX, bTop + s * 0.12f), ImVec2(iconCX + ribX * 0.8f, bBot - s * 0.1f), iconCol, lw * 0.8f);
                    } else if (i == 2) {
                        // Logs: open book / document
                        float bw = s * 0.55f, bh = s * 0.75f;
                        float top = iconCY - bh * 0.5f, bot = iconCY + bh * 0.5f;
                        // left page
                        ddl->AddRect(ImVec2(iconCX - bw, top), ImVec2(iconCX - s * 0.04f, bot), iconCol, 1.5f, 0, lw);
                        // right page
                        ddl->AddRect(ImVec2(iconCX + s * 0.04f, top), ImVec2(iconCX + bw, bot), iconCol, 1.5f, 0, lw);
                        // spine line
                        ddl->AddLine(ImVec2(iconCX, top - s * 0.05f), ImVec2(iconCX, bot + s * 0.05f), iconCol, lw);
                        // text lines on left page
                        float lineStart = top + s * 0.18f;
                        float lineGap = s * 0.16f;
                        for (int li = 0; li < 3; li++) {
                            float ly = lineStart + li * lineGap;
                            float lwid = (li == 2) ? s * 0.2f : s * 0.35f;
                            ddl->AddLine(ImVec2(iconCX - bw + s * 0.08f, ly), ImVec2(iconCX - bw + s * 0.08f + lwid, ly), iconCol, lw * 0.7f);
                        }
                        // text lines on right page
                        for (int li = 0; li < 3; li++) {
                            float ly = lineStart + li * lineGap;
                            float lwid = (li == 2) ? s * 0.25f : s * 0.35f;
                            ddl->AddLine(ImVec2(iconCX + s * 0.12f, ly), ImVec2(iconCX + s * 0.12f + lwid, ly), iconCol, lw * 0.7f);
                        }
                    } else if (i == 3) {
                        // Settings: gear with proper teeth
                        float outerR = s * 0.6f;
                        float innerR = s * 0.38f;
                        float hubR = s * 0.18f;
                        int teeth = 8;
                        float toothW = 0.22f;
                        for (int t = 0; t < teeth; t++) {
                            float a1 = (float)t / teeth * 6.2832f - 1.5708f;
                            float a2 = (float)(t + toothW) / teeth * 6.2832f - 1.5708f;
                            float a3 = (float)(t + 0.5f - toothW) / teeth * 6.2832f - 1.5708f;
                            float a4 = (float)(t + 0.5f) / teeth * 6.2832f - 1.5708f;
                            // outer tooth
                            ImVec2 o1(iconCX + cosf(a1) * innerR, iconCY + sinf(a1) * innerR);
                            ImVec2 o2(iconCX + cosf(a1) * outerR, iconCY + sinf(a1) * outerR);
                            ImVec2 o3(iconCX + cosf(a2) * outerR, iconCY + sinf(a2) * outerR);
                            ImVec2 o4(iconCX + cosf(a2) * innerR, iconCY + sinf(a2) * innerR);
                            ddl->AddLine(o1, o2, iconCol, lw);
                            ddl->AddLine(o2, o3, iconCol, lw);
                            ddl->AddLine(o3, o4, iconCol, lw);
                            // inner valley
                            ImVec2 iv1(iconCX + cosf(a3) * innerR, iconCY + sinf(a3) * innerR);
                            ImVec2 iv2(iconCX + cosf(a4) * innerR, iconCY + sinf(a4) * innerR);
                            ddl->AddLine(o4, iv1, iconCol, lw);
                            ddl->AddLine(iv1, iv2, iconCol, lw);
                            ddl->AddLine(iv2, ImVec2(iconCX + cosf(a4 + (0.5f - toothW * 2.0f) / teeth * 6.2832f) * innerR, iconCY + sinf(a4 + (0.5f - toothW * 2.0f) / teeth * 6.2832f) * innerR), iconCol, lw);
                        }
                        // center hub
                        ddl->AddCircle(ImVec2(iconCX, iconCY), hubR, iconCol, 12, lw);
                        ddl->AddCircleFilled(ImVec2(iconCX, iconCY), hubR * 0.35f, dockBg, 8);
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
        g_needsRedraw = false;
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
