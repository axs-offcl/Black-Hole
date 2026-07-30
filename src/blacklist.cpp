#include "blacklist.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <Windows.h>

namespace BlackHole {

const std::wstring BlacklistModule::CONFIRMATION_PHRASE = L"I assume full liability";

BlacklistModule::BlacklistModule() {
    ResetOverride();
}

static std::wstring CanonicalizePath(const std::wstring& path) {
    std::wstring cleaned = path;

    size_t qmark = cleaned.find(L"\\\\?\\");
    if (qmark == 0) cleaned = cleaned.substr(4);

    size_t adsColon = std::wstring::npos;
    size_t searchStart = 2;
    while (searchStart < cleaned.size()) {
        size_t pos = cleaned.find(L':', searchStart);
        if (pos == std::wstring::npos) break;
        if (pos > 2) {
            adsColon = pos;
            break;
        }
        searchStart = pos + 1;
    }
    if (adsColon != std::wstring::npos) cleaned = cleaned.substr(0, adsColon);

    while (cleaned.size() > 3 && cleaned.back() == L'\\') cleaned.pop_back();

    DWORD len = GetFullPathNameW(cleaned.c_str(), 0, NULL, NULL);
    if (len > 0) {
        std::wstring buf(len, L'\0');
        DWORD actual = GetFullPathNameW(cleaned.c_str(), len, &buf[0], NULL);
        if (actual > 0 && actual < len) {
            buf.resize(actual);
            cleaned = buf;
        }
    }

    size_t qmark2 = cleaned.find(L"\\\\?\\");
    if (qmark2 == 0) cleaned = cleaned.substr(4);

    while (cleaned.size() > 3 && cleaned.back() == L'\\') cleaned.pop_back();

    return cleaned;
}

bool BlacklistModule::IsInBlacklist(const std::wstring& path) const {
    if (m_override.isActive) {
        return false;
    }

    std::wstring normalizedPath = CanonicalizePath(path);
    std::wstring pathLower = normalizedPath;
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);

    for (size_t i = 0; i < BLACKLIST_SIZE; ++i) {
        std::wstring entry = SYSTEM_BLACKLIST[i];
        std::wstring entryLower = entry;
        std::transform(entryLower.begin(), entryLower.end(), entryLower.begin(), ::towlower);

        if (pathLower.find(entryLower) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

bool BlacklistModule::IsBlockedDevicePath(const std::wstring& path) {
    std::wstring upper = path;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::towupper);

    if (upper.find(L"\\\\.\\") == 0 || upper.find(L"\\\\?\\") == 0) {
        if (upper.find(L"\\\\.\\PHYSICALDRIVE") == 0 ||
            upper.find(L"\\\\.\\TAPE") == 0 ||
            upper.find(L"\\\\.\\CDROM") == 0 ||
            upper.find(L"\\\\.\\FLOPPY") == 0 ||
            upper.find(L"\\\\.\\NPF_") == 0 ||
            upper.find(L"\\\\.\\PIPE\\") == 0) {
            return true;
        }
    }

    static const wchar_t* reserved[] = {
        L"CON", L"PRN", L"AUX", L"NUL",
        L"COM1", L"COM2", L"COM3", L"COM4", L"COM5",
        L"COM6", L"COM7", L"COM8", L"COM9",
        L"LPT1", L"LPT2", L"LPT3", L"LPT4", L"LPT5",
        L"LPT6", L"LPT7", L"LPT8", L"LPT9",
        NULL
    };

    std::wstring filename;
    size_t lastSlash = path.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) {
        filename = path.substr(lastSlash + 1);
    } else {
        filename = path;
    }

    size_t dotPos = filename.find(L'.');
    std::wstring namePart = (dotPos != std::wstring::npos) ? filename.substr(0, dotPos) : filename;
    std::wstring nameUpper = namePart;
    std::transform(nameUpper.begin(), nameUpper.end(), nameUpper.begin(), ::towupper);

    for (const wchar_t** r = reserved; *r; ++r) {
        if (nameUpper == *r) return true;
    }

    return false;
}

bool BlacklistModule::IsOverrideActive() const {
    return m_override.isActive;
}

bool BlacklistModule::SetOverride(bool active, const std::wstring& confirmationText) {
    if (active) {
        if (confirmationText != CONFIRMATION_PHRASE) {
            return false;
        }
        m_override.isActive = true;
        m_override.confirmationText = confirmationText;

        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        struct tm tm;
        localtime_s(&tm, &time);
        std::wstringstream ss;
        ss << std::put_time(&tm, L"%Y-%m-%dT%H:%M:%S");
        m_override.activatedAt = ss.str();
    } else {
        m_override.isActive = false;
        m_override.confirmationText.clear();
        m_override.activatedAt.clear();
    }
    return true;
}

std::wstring BlacklistModule::GetOverrideTimestamp() const {
    return m_override.activatedAt;
}

void BlacklistModule::ResetOverride() {
    m_override.isActive = false;
    m_override.confirmationText.clear();
    m_override.activatedAt.clear();
}

}  // namespace BlackHole
