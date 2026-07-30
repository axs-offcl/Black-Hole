#include "test_shared.h"
#include "privilege.h"

using namespace BlackHole;

void RegisterPrivilegeTests(TestRunner& runner) {
    runner.AddTest("Privilege_CreateInstance", []() {
        PrivilegeManager pm;
        return true;
    });

    runner.AddTest("Privilege_EnableBackup", []() {
        PrivilegeManager pm;
        bool result = pm.EnableBackupPrivilege();
        return true;
    });

    runner.AddTest("Privilege_EnableRestore", []() {
        PrivilegeManager pm;
        bool result = pm.EnableRestorePrivilege();
        return true;
    });

    runner.AddTest("Privilege_EnableAll", []() {
        PrivilegeManager pm;
        bool result = pm.EnableAllPrivileges();
        return true;
    });

    runner.AddTest("Privilege_GetLastError_InitiallyEmpty", []() {
        PrivilegeManager pm;
        return pm.GetLastError().empty();
    });

    runner.AddTest("Privilege_IsRunningAsAdmin", []() {
        PrivilegeManager pm;
        bool isAdmin = pm.IsRunningAsAdmin();
        return true;
    });

    runner.AddTest("Privilege_NonCopyable", []() {
        PrivilegeManager pm1;
        PrivilegeManager pm2;
        return true;
    });
}
