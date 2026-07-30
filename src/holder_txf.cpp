#include <Windows.h>
#include <iostream>
#include <string>

typedef HANDLE (WINAPI *pfnCreateTransaction)(LPSECURITY_ATTRIBUTES, LPVOID, DWORD, DWORD, DWORD, DWORD, LPWSTR);
typedef HANDLE (WINAPI *pfnCreateFileTransactedW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE, HANDLE, PLARGE_INTEGER, HANDLE);

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: holder_txf.exe <filepath>\n";
        std::wcout << L"Holds file in uncommitted NTFS transaction\n";
        return 1;
    }

    std::wstring filePath = argv[1];

    HMODULE hKtmW32 = LoadLibraryW(L"ktmw32.dll");
    if (!hKtmW32) {
        std::wcout << L"Failed to load ktmw32.dll. Error: " << ::GetLastError() << L"\n";
        return 1;
    }

    auto fnCreateTransaction = (pfnCreateTransaction)GetProcAddress(hKtmW32, "CreateTransaction");
    auto fnCreateFileTransactedW = (pfnCreateFileTransactedW)GetProcAddress(hKtmW32, "CreateFileTransactedW");

    if (!fnCreateTransaction || !fnCreateFileTransactedW) {
        std::wcout << L"Failed to get TxF function pointers.\n";
        FreeLibrary(hKtmW32);
        return 1;
    }

    HANDLE hTransaction = fnCreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
    if (!hTransaction) {
        std::wcout << L"Failed to create transaction. Error: " << ::GetLastError() << L"\n";
        FreeLibrary(hKtmW32);
        return 1;
    }

    std::wcout << L"Transaction created.\n";

    HANDLE hFile = fnCreateFileTransactedW(filePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
        NULL, hTransaction, NULL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"Failed to open file transacted. Error: " << ::GetLastError() << L"\n";
        CloseHandle(hTransaction);
        FreeLibrary(hKtmW32);
        return 1;
    }

    std::wcout << L"File opened in uncommitted transaction.\n";
    std::wcout << L"File is locked by TxF. Press Enter to commit & close...\n";
    std::cin.get();

    CloseHandle(hFile);
    CommitTransaction(hTransaction);
    CloseHandle(hTransaction);
    FreeLibrary(hKtmW32);

    std::wcout << L"Transaction committed and closed.\n";
    return 0;
}
