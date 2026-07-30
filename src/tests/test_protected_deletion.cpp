#include "test_shared.h"
#include "deletor.h"
#include <Windows.h>
#include <aclapi.h>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <random>

#pragma comment(lib, "advapi32.lib")

using namespace BlackHole;
namespace fs = std::filesystem;

static std::wstring GetTestDir() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring dir = std::wstring(tempPath) + L"\\BlackHoleProtectedTests";
    fs::create_directories(dir);
    return dir;
}

static void WriteFile(const std::wstring& path, const std::string& content = "test data") {
    std::ofstream f(path);
    f << content;
    f.close();
}

static std::wstring RandomName(int len) {
    static const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
    std::wstring name;
    std::mt19937 rng((unsigned)GetTickCount());
    std::uniform_int_distribution<int> dist(0, (int)(sizeof(charset)/sizeof(wchar_t)) - 2);
    for (int i = 0; i < len; i++) name += charset[dist(rng)];
    return name;
}

void RegisterProtectedDeletionTests(TestRunner& runner) {

    runner.AddTest("Protected_TripleAttr_ReadOnlySystemHidden", []() {
        std::wstring dir = GetTestDir();
        std::wstring file = dir + L"\\" + RandomName(8) + L".sys";
        WriteFile(file, "fake system file content");

        DWORD attrs = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
        SetFileAttributesW(file.c_str(), attrs);

        DWORD actual = GetFileAttributesW(file.c_str());
        if ((actual & attrs) != attrs) return false;

        Deletor d;
        auto result = d.DeleteFileSafely(file);
        bool deleted = (result.result == DeletionResult::Success);
        bool scheduled = (result.result == DeletionResult::Scheduled_Reboot);
        bool exists = (GetFileAttributesW(file.c_str()) != INVALID_FILE_ATTRIBUTES);
        return (deleted || scheduled) && !exists;
    });

    runner.AddTest("Protected_ACLDenied_DeleteBlocked", []() {
        std::wstring dir = GetTestDir();
        std::wstring file = dir + L"\\" + RandomName(8) + L".txt";
        WriteFile(file, "acl protected content");

        HANDLE hFile = CreateFileW(file.c_str(), WRITE_DAC | READ_CONTROL,
            0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        EXPLICIT_ACCESS ea = {};
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        PSID pSid = NULL;
        if (!AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &pSid)) {
            CloseHandle(hFile);
            return false;
        }

        ea.grfAccessPermissions = DELETE;
        ea.grfAccessMode = DENY_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea.Trustee.ptstrName = (LPTSTR)pSid;

        PACL pOldDacl = NULL;
        GetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            NULL, NULL, &pOldDacl, NULL, NULL);

        PACL pNewDacl = NULL;
        DWORD dwRes = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
        if (dwRes != ERROR_SUCCESS) {
            FreeSid(pSid);
            CloseHandle(hFile);
            return false;
        }

        SetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            NULL, NULL, pNewDacl, NULL);

        LocalFree(pNewDacl);
        FreeSid(pSid);
        CloseHandle(hFile);

        Deletor d;
        auto result = d.DeleteFileSafely(file);
        return result.result == DeletionResult::Success ||
               result.result == DeletionResult::Scheduled_Reboot;
    });

    runner.AddTest("Protected_ACLDenied_AdminCanOverride", []() {
        std::wstring dir = GetTestDir();
        std::wstring file = dir + L"\\" + RandomName(8) + L".txt";
        WriteFile(file, "admin override content");

        HANDLE hFile = CreateFileW(file.c_str(), WRITE_DAC | READ_CONTROL,
            0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        PSID pSid = NULL;
        AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &pSid);

        EXPLICIT_ACCESS ea = {};
        ea.grfAccessPermissions = DELETE;
        ea.grfAccessMode = DENY_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea.Trustee.ptstrName = (LPTSTR)pSid;

        PACL pNewDacl = NULL;
        SetEntriesInAclW(1, &ea, NULL, &pNewDacl);
        SetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            NULL, NULL, pNewDacl, NULL);

        LocalFree(pNewDacl);
        FreeSid(pSid);
        CloseHandle(hFile);

        Deletor d;
        auto result = d.DeleteFileSafely(file);
        bool gone = (GetFileAttributesW(file.c_str()) == INVALID_FILE_ATTRIBUTES);
        return result.result == DeletionResult::Success && gone;
    });

    runner.AddTest("Protected_DeepDirNested", []() {
        std::wstring dir = GetTestDir();
        std::wstring deepDir = dir;
        for (int i = 0; i < 15; i++)
            deepDir += L"\\level" + std::to_wstring(i);
        fs::create_directories(deepDir);

        std::wstring file = deepDir + L"\\deep_file.txt";
        WriteFile(file, "deeply nested");

        Deletor d;
        auto result = d.DeleteFileSafely(dir + L"\\level0");
        bool gone = (GetFileAttributesW(file.c_str()) == INVALID_FILE_ATTRIBUTES);
        return (result.result == DeletionResult::Success ||
                result.result == DeletionResult::Scheduled_Reboot) && gone;
    });

    runner.AddTest("Protected_ZeroByteFile", []() {
        std::wstring dir = GetTestDir();
        std::wstring file = dir + L"\\" + RandomName(8) + L".bin";

        HANDLE hFile = CreateFileW(file.c_str(), GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        CloseHandle(hFile);

        DWORD sz = GetFileAttributesW(file.c_str());
        if (sz == INVALID_FILE_ATTRIBUTES) return false;

        Deletor d;
        auto result = d.DeleteFileSafely(file);
        return result.result == DeletionResult::Success;
    });

    runner.AddTest("Protected_AttributeStripping", []() {
        std::wstring dir = GetTestDir();
        std::wstring file = dir + L"\\" + RandomName(8) + L".sys";
        WriteFile(file, "attribute strip test");

        DWORD heavy = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN |
                      FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        SetFileAttributesW(file.c_str(), heavy);

        Deletor d;
        auto result = d.DeleteFileSafely(file);
        bool gone = (GetFileAttributesW(file.c_str()) == INVALID_FILE_ATTRIBUTES);
        return (result.result == DeletionResult::Success ||
                result.result == DeletionResult::Scheduled_Reboot) && gone;
    });

    runner.AddTest("Protected_EmptyDirWithHiddenChild", []() {
        std::wstring dir = GetTestDir();
        std::wstring parent = dir + L"\\" + RandomName(8);
        fs::create_directories(parent);

        std::wstring child = parent + L"\\hidden_child.txt";
        WriteFile(child, "hidden child");
        SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY);

        Deletor d;
        auto result = d.DeleteFileSafely(parent);
        bool gone = (GetFileAttributesW(child.c_str()) == INVALID_FILE_ATTRIBUTES);
        return (result.result == DeletionResult::Success ||
                result.result == DeletionResult::Scheduled_Reboot) && gone;
    });

    runner.AddTest("Protected_FileWithLongName", []() {
        std::wstring dir = GetTestDir();
        std::wstring longName(120, L'x');
        longName += L".txt";
        std::wstring file = dir + L"\\" + longName;

        HANDLE hFile = CreateFileW(file.c_str(), GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        DWORD written;
        const char* data = "long name test";
        WriteFile(hFile, data, (DWORD)strlen(data), &written, NULL);
        CloseHandle(hFile);

        Deletor d;
        auto result = d.DeleteFileSafely(file);
        bool gone = (GetFileAttributesW(file.c_str()) == INVALID_FILE_ATTRIBUTES);
        return (result.result == DeletionResult::Success ||
                result.result == DeletionResult::Scheduled_Reboot) && gone;
    });

    runner.AddTest("Protected_SystemAndReadonlyCombo", []() {
        std::wstring dir = GetTestDir();
        std::wstring file = dir + L"\\combo_system_readonly.txt";
        WriteFile(file, "combo test");

        DWORD combo = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY;
        SetFileAttributesW(file.c_str(), combo);

        Deletor d;
        auto result = d.DeleteFileSafely(file);
        bool gone = (GetFileAttributesW(file.c_str()) == INVALID_FILE_ATTRIBUTES);
        return (result.result == DeletionResult::Success ||
                result.result == DeletionResult::Scheduled_Reboot) && gone;
    });

    runner.AddTest("Protected_BrokenSymlink", []() {
        std::wstring dir = GetTestDir();
        std::wstring link = dir + L"\\" + RandomName(8) + L"_link.txt";

        CreateSymbolicLinkW(link.c_str(), L"C:\\totally\\nonexistent\\target.txt", 0);
        DWORD attrs = GetFileAttributesW(link.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            DWORD err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PRIVILEGE_NOT_HELD)
                return true;
        }

        Deletor d;
        auto result = d.DeleteFileSafely(link);
        return result.result == DeletionResult::Success ||
               result.result == DeletionResult::Scheduled_Reboot ||
               result.result == DeletionResult::Failed_PathNotFound;
    });

    runner.AddTest("Protected_MultipleFilesInSequence", []() {
        std::wstring dir = GetTestDir();
        std::wstring parent = dir + L"\\" + RandomName(6);
        fs::create_directories(parent);

        for (int i = 0; i < 5; i++) {
            std::wstring f = parent + L"\\file_" + std::to_wstring(i) + L".txt";
            WriteFile(f, "batch test " + std::to_string(i));
            SetFileAttributesW(f.c_str(),
                FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }

        Deletor d;
        int deleted = 0;
        for (int i = 0; i < 5; i++) {
            std::wstring f = parent + L"\\file_" + std::to_wstring(i) + L".txt";
            auto result = d.DeleteFileSafely(f);
            if (result.result == DeletionResult::Success ||
                result.result == DeletionResult::Scheduled_Reboot)
                deleted++;
        }

        auto dirResult = d.DeleteFileSafely(parent);
        bool allGone = true;
        for (int i = 0; i < 5; i++) {
            std::wstring f = parent + L"\\file_" + std::to_wstring(i) + L".txt";
            if (GetFileAttributesW(f.c_str()) != INVALID_FILE_ATTRIBUTES)
                allGone = false;
        }
        return deleted == 5 && allGone;
    });
}
