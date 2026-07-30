#include <Windows.h>
#include <iostream>
#include <string>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: holder_mmap.exe <filepath>\n";
        std::wcout << L"Holds file via memory mapping (file handle closed, mapping alive)\n";
        return 1;
    }

    std::wstring filePath = argv[1];
    std::wcout << L"Opening file for memory mapping: " << filePath << L"\n";

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"Failed to open file. Error: " << ::GetLastError() << L"\n";
        return 1;
    }

    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMap) {
        std::wcout << L"Failed to create file mapping. Error: " << ::GetLastError() << L"\n";
        CloseHandle(hFile);
        return 1;
    }

    LPVOID pView = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (!pView) {
        std::wcout << L"Failed to map view. Error: " << ::GetLastError() << L"\n";
        CloseHandle(hMap);
        CloseHandle(hFile);
        return 1;
    }

    CloseHandle(hFile);
    std::wcout << L"File handle closed. Memory mapping still alive.\n";
    std::wcout << L"File is now locked via mapping only.\n";
    std::wcout << L"Press Enter to release mapping...\n";
    std::cin.get();

    UnmapViewOfFile(pView);
    CloseHandle(hMap);
    std::wcout << L"Mapping released.\n";
    return 0;
}
