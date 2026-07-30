#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: file_holder.exe <filepath>\n";
        return 1;
    }

    std::wstring filePath = argv[1];
    std::wcout << L"Holding file: " << filePath << L"\n";

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"Failed to open file. Error: " << ::GetLastError() << L"\n";
        return 1;
    }

    std::wcout << L"File locked. Press Enter to release...\n";
    std::cin.get();

    CloseHandle(hFile);
    std::wcout << L"File released.\n";
    return 0;
}
