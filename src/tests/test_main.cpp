#include "test_shared.h"

int main() {
    TestRunner& runner = TestRunner::Instance();

    RegisterBlacklistTests(runner);
    RegisterPrivilegeTests(runner);
    RegisterDeletorTests(runner);
    RegisterLoggerTests(runner);
    RegisterProtectedDeletionTests(runner);
    RegisterUninstallerTests(runner);

    return runner.RunAll();
}
