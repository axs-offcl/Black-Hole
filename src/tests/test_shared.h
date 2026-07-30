#ifndef BLACKHOLE_TEST_SHARED_H
#define BLACKHOLE_TEST_SHARED_H

#include <iostream>
#include <string>
#include <vector>
#include <functional>

struct TestResult {
    std::string name;
    bool passed;
    std::string message;
};

class TestRunner {
public:
    static TestRunner& Instance() {
        static TestRunner instance;
        return instance;
    }

    void AddTest(const std::string& name, std::function<bool()> testFunc) {
        tests.push_back({name, testFunc, ""});
    }

    int RunAll() {
        int passed = 0;
        int failed = 0;
        std::cout << "Black Hole (B-H) v2.0 - Unit Tests\n";
        std::cout << "====================================\n\n";

        for (auto& t : tests) {
            std::cout << "Running: " << t.name << "... ";
            try {
                bool result = t.func();
                if (result) {
                    std::cout << "PASS\n";
                    passed++;
                } else {
                    std::cout << "FAIL\n";
                    failed++;
                }
            } catch (const std::exception& e) {
                std::cout << "EXCEPTION: " << e.what() << "\n";
                failed++;
            } catch (...) {
                std::cout << "UNKNOWN EXCEPTION\n";
                failed++;
            }
        }

        std::cout << "\n====================================\n";
        std::cout << "Results: " << passed << " passed, " << failed << " failed, "
                  << (passed + failed) << " total\n";
        return failed;
    }

private:
    struct Test {
        std::string name;
        std::function<bool()> func;
        std::string message;
    };
    std::vector<Test> tests;
};

extern void RegisterBlacklistTests(TestRunner& runner);
extern void RegisterPrivilegeTests(TestRunner& runner);
extern void RegisterDeletorTests(TestRunner& runner);
extern void RegisterLoggerTests(TestRunner& runner);
extern void RegisterProtectedDeletionTests(TestRunner& runner);
extern void RegisterUninstallerTests(TestRunner& runner);

#endif
