#pragma once
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

std::wstring GetConfigPath();
void SaveConfig();
void LoadConfig();
void ApplyWindowTransparency();
