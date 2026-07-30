#pragma once
#include <string>
#include <vector>
#include <Windows.h>

namespace BlackHole {

struct LockInfo {
    DWORD pid = 0;
    std::wstring processName;
    bool isProtected = false;
};

struct RegistryRef {
    std::wstring keyPath;
    std::wstring valueName;
    std::wstring valueData;
};

struct ServiceRef {
    std::wstring serviceName;
    std::wstring displayName;
    DWORD startType = 0;
    DWORD processId = 0;
};

struct DependentApp {
    std::wstring appName;
    std::wstring installPath;
    std::wstring reason;
};

struct RelatedFile {
    std::wstring path;
    ULONGLONG fileSize = 0;
    bool isDirectory = false;
};

struct LeftoverRef {
    std::wstring path;
    std::wstring typeName;
    std::wstring description;
};

enum class RiskLevel { Safe, Low, Medium, High, Critical };

struct ImpactAnalysis {
    std::wstring filePath;
    std::wstring fileName;
    ULONGLONG fileSize = 0;
    std::wstring fileType;
    std::wstring publisher;
    std::wstring version;
    bool isSigned = false;
    bool isSystemFile = false;

    std::vector<LockInfo> lockedBy;
    std::vector<DependentApp> dependentApps;
    std::vector<RegistryRef> registryRefs;
    std::vector<ServiceRef> serviceRefs;
    std::vector<RelatedFile> relatedFiles;
    ULONGLONG totalRelatedSize = 0;
    std::vector<LeftoverRef> leftovers;

    int riskScore = 0;
    RiskLevel riskLevel = RiskLevel::Safe;
    std::wstring recommendation;

    bool analyzed = false;
};

class ImpactAnalyzer {
public:
    ImpactAnalysis Analyze(const std::wstring& filePath);

private:
    void GatherFileInfo(ImpactAnalysis& result);
    void DetectLocks(ImpactAnalysis& result);
    void ScanRegistryReferences(ImpactAnalysis& result);
    void ScanServiceReferences(ImpactAnalysis& result);
    void FindDependentApps(ImpactAnalysis& result);
    void FindRelatedFiles(ImpactAnalysis& result);
    void PredictLeftovers(ImpactAnalysis& result);
    void CalculateRiskScore(ImpactAnalysis& result);
    bool IsSystemCriticalPath(const std::wstring& path);
};

}
