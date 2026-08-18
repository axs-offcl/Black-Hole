#include "app_config.h"
#include "app_util.h"
#include <Windows.h>
#include <ShlObj.h>
#include <filesystem>
#include <fstream>
#include <string>

extern bool    g_darkMode;
extern bool    g_sendToRecycleBin;
extern bool    g_createRestorePoint;
extern bool    g_sidebarGlowEnabled;
extern float   g_sidebarGlowColor[3];
extern bool    g_lineGlowEnabled;
extern float   g_lineGlowColor[3];
extern bool    g_hideSidebar;
extern bool    g_hideDock;
extern bool    g_windowTransparent;
extern float   g_windowAlpha;
extern bool    g_resizableWindow;
extern bool    g_dockExpanded;
extern bool    g_autoAnalyzeOnStart;
extern bool    g_installMonitorEnabled;

std::wstring GetConfigPath() {
    WCHAR exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring exeDir = std::filesystem::path(exePath).parent_path().wstring();
    std::wstring portablePath = exeDir + L"\\config.ini";
    if (std::filesystem::exists(portablePath)) return portablePath;

    PWSTR appDataPath = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appDataPath)))
        return L"";
    std::wstring path(appDataPath);
    CoTaskMemFree(appDataPath);
    path += L"\\BlackHole\\config.ini";
    return path;
}

void SaveConfig() {
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
        f << "InstallMonitor=" << (g_installMonitorEnabled ? "1" : "0") << "\n";
        f.close();
    }
}

void LoadConfig() {
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

        if (line.find("InstallMonitor=1") != std::string::npos)
            g_installMonitorEnabled = true;
        else if (line.find("InstallMonitor=0") != std::string::npos)
            g_installMonitorEnabled = false;
    }
    f.close();
    ApplyWindowTransparency();
}

void ApplyWindowTransparency() {
    extern HWND g_hMainWindow;
    if (!g_hMainWindow) return;
    LONG style = GetWindowLongW(g_hMainWindow, GWL_EXSTYLE);
    if (g_windowTransparent) {
        SetWindowLongW(g_hMainWindow, GWL_EXSTYLE, style | WS_EX_LAYERED);
        SetLayeredWindowAttributes(g_hMainWindow, 0, (BYTE)(g_windowAlpha * 255), LWA_ALPHA);
    } else {
        SetWindowLongW(g_hMainWindow, GWL_EXSTYLE, style & ~WS_EX_LAYERED);
    }
}
