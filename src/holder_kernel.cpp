#include <Windows.h>
#include <iostream>
#include <string>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: holder_kernel.exe <filepath.sys>\n";
        std::wcout << L"Simulates kernel-level file lock via exclusive handle\n";
        return 1;
    }

    std::wstring filePath = argv[1];
    std::wcout << L"Opening file with exclusive access: " << filePath << L"\n";

    HANDLE hFile = CreateFileW(filePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"Failed to open file exclusively. Error: " << ::GetLastError() << L"\n";
        std::wcout << L"Trying with share read...\n";

        hFile = CreateFileW(filePath.c_str(),
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            std::wcout << L"Still failed. Error: " << ::GetLastError() << L"\n";
            return 1;
        }
    }

    std::wcout << L"File opened exclusively. Lock held.\n";
    std::wcout << L"Press Enter to release...\n";
    std::cin.get();

    CloseHandle(hFile);
    std::wcout << L"File released.\n";
    return 0;
}
