#ifndef BLACKHOLE_GUI_H
#define BLACKHOLE_GUI_H

#include <Windows.h>
#include <commctrl.h>
#include <string>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

#define WM_TRAYICON (WM_USER + 1)
#define WM_DELETION_COMPLETE (WM_USER + 2)
#define WM_NOTIFICATION_SHOW (WM_USER + 3)
#define WM_NOTIFICATION_DONE (WM_USER + 4)

#define TIMER_REFRESH_LOGS 1
#define TIMER_NOTIFICATION_AUTO_CLOSE 2
#define TIMER_NOTIFICATION_DONE 3

#define EM_SETBKGNDCOLOR 0x0443

#define IDC_LISTVIEW 1001
#define IDC_BTN_SELECT_FILE 1002
#define IDC_BTN_ACTIVATE_OVERRIDE 1003
#define IDC_BTN_DEACTIVATE_OVERRIDE 1004
#define IDC_EDIT_OVERRIDE_INPUT 1005
#define IDC_EDIT_OVERRIDE_STATUS 1006
#define IDC_STATIC_OVERRIDE_LABEL 1007

#define MENU_FILE_EXIT 2001
#define MENU_TOOLS_SELECT_FILE 2002
#define MENU_TOOLS_INSTALL_CONTEXT 2003
#define MENU_TOOLS_UNINSTALL_CONTEXT 2004
#define MENU_TRAY_SHOW 2005
#define MENU_TRAY_EXIT 2006

#define LOG_REFRESH_INTERVAL_MS 3000
#define NOTIFICATION_AUTO_CLOSE_MS 5000
#define NOTIFICATION_WIDTH 320
#define NOTIFICATION_HEIGHT 100
#define MAX_NOTIFICATION_QUEUE 100

struct NotificationData {
    std::wstring title;
    std::wstring action;
    std::wstring details;
    bool isError;
};

struct DeletionThreadParams {
    HWND hwnd;
    std::wstring filePath;
};

extern HINSTANCE g_hInstance;
extern HWND g_hMainWindow;
extern NOTIFYICONDATAW g_nid;
extern std::queue<NotificationData> g_notificationQueue;
extern std::mutex g_queueMutex;
extern std::atomic<bool> g_notificationActive;

LRESULT CALLBACK MainWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK NotificationWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

void RefreshLogListView(HWND hwndListView);
void ShowNotification(const NotificationData& data);
void ProcessNotificationQueue(HWND hwnd);
void HandleDeletionComplete(HWND hwnd, const std::wstring& filePath, int result);
DWORD WINAPI DeletionWorkerThread(LPVOID lpParam);

bool InstallContextMenu(HWND hwnd);
bool UninstallContextMenu(HWND hwnd);
bool IsRunningAsAdmin();
void RequestElevation();

#endif
