#ifndef BLACKHOLE_UNINSTALLER_H
#define BLACKHOLE_UNINSTALLER_H

#include <Windows.h>
#include <string>
#include <vector>
#include <set>
#include <map>

namespace BlackHole {

enum class ScanDepth { Safe, Moderate, Advanced };

enum class LeftoverConfidence { Safe, Moderate, Risky };

enum class InstallerType { Unknown, Msi, InnoSetup, Nsis, InstallShield, PowerShell, SdbInst, StoreApp, Chocolatey, Scoop, WindowsFeature };

enum class CertStatus { Unknown, NotFound, Verified, Unverified };
enum class Bitness { Unknown, X86, X64, ARM64 };

struct StartupEntry;

struct UninstallEntry {
    std::wstring displayName;
    std::wstring displayVersion;
    std::wstring publisher;
    std::wstring installPath;
    std::wstring uninstallString;
    std::wstring quietUninstallString;
    std::wstring displayIcon;
    std::wstring registryKey;
    std::wstring aboutUrl;
    std::wstring installSource;
    std::wstring modifyPath;
    DWORD estimatedSize = 0;
    std::wstring installDate;
    bool isSystemComponent = false;
    bool isMsiInstaller = false;
    bool isOrphaned = false;
    bool isProtected = false;
    bool isUpdate = false;
    InstallerType installerType = InstallerType::Unknown;
    CertStatus certStatus = CertStatus::Unknown;
    Bitness bitness = Bitness::Unknown;
    std::vector<std::wstring> sortedExecutables;
    std::wstring displayNameLower;
    std::wstring publisherLower;
    std::wstring registryKeyLower;
    std::vector<StartupEntry> startupEntries;
};

struct LeftoverItem {
    std::wstring path;
    std::wstring displayName;
    enum Type { File, Directory, RegistryKey } type;
    bool checked = true;
    LeftoverConfidence confidence = LeftoverConfidence::Safe;
    int rawScore = 0;
};

struct ForceRemovalResult {
    bool success = false;
    std::vector<LeftoverItem> leftovers;
};

struct PEMetadata {
    std::wstring companyName;
    std::wstring fileDescription;
    std::wstring productName;
    std::wstring fileVersion;
    std::wstring productVersion;
};

struct StartupEntry {
    std::wstring name;
    std::wstring command;
    std::wstring location;
    enum LocationType { RunKey, RunOnce, StartupFolder, TaskScheduler, Service };
    LocationType locationType = RunKey;
    bool enabled = true;
    bool isProtected = false;
};

int Sift4Distance(const std::wstring& s1, const std::wstring& s2, int maxOffset = 5);
std::wstring ROT13(const std::wstring& input);
bool ExtractPEMetadata(const std::wstring& exePath, PEMetadata& outData);
void EnrichEntryFromPE(UninstallEntry& entry);
std::wstring ResolveAppIconPath(const UninstallEntry& entry);
HICON ExtractAppIcon(const UninstallEntry& entry);
HICON ExtractIconFromPNG(const std::wstring& pngPath);
CertStatus VerifyCertificate(const std::wstring& filePath);
Bitness DetectBitness(const std::wstring& exePath);
bool IsMicrosoftApp(const UninstallEntry& entry);
bool IsStoreApp(const UninstallEntry& entry);

class Uninstaller {
public:
    Uninstaller();
    ~Uninstaller() = default;

    std::vector<UninstallEntry> ScanInstalled();
    std::vector<UninstallEntry> ScanExtras();
    void EnrichEntriesBackground(std::vector<UninstallEntry>& entries);
    std::vector<UninstallEntry> ScanStoreApps();
    std::vector<UninstallEntry> ScanDirectoryOrphans();
    std::vector<UninstallEntry> ScanChocolateyPackages();
    std::vector<UninstallEntry> ScanScoopPackages();
    std::vector<UninstallEntry> ScanWindowsFeatures();
    std::vector<StartupEntry> ScanStartupEntries();

    void GenerateQuietSwitches(UninstallEntry& entry);
    void RunInfoAdders(std::vector<UninstallEntry>& entries);
    bool ExportToJSON(const std::vector<UninstallEntry>& entries, const std::wstring& filePath);
    bool ExportToXML(const std::vector<UninstallEntry>& entries, const std::wstring& filePath);
    void DeduplicateEntries(std::vector<UninstallEntry>& entries);
    bool UninstallStandard(const UninstallEntry& entry);
    bool UninstallStoreApp(const UninstallEntry& entry);
    bool ForceRemove(const UninstallEntry& entry);
    bool RemoveRegistryEntry(const UninstallEntry& entry);
    std::vector<LeftoverItem> ScanLeftovers(const UninstallEntry& entry,
                                            ScanDepth depth = ScanDepth::Safe,
                                            bool basicOnly = false);
    bool PurgeLeftovers(const std::vector<LeftoverItem>& items, bool createRestorePoint = false);
    ForceRemovalResult ForceRemovalPipeline(const UninstallEntry& entry,
                                            ScanDepth depth = ScanDepth::Safe,
                                            bool createRestorePoint = false);

    std::wstring ResolveInstallPath(const UninstallEntry& entry);

    bool CreateRestorePoint(const std::wstring& appName);
    bool CreateSystemRestorePoint(const std::wstring& appName);
    bool BackupRegistryKey(const std::wstring& appName, const std::wstring& regPath);
    std::wstring GetBackupDir() const;

    static bool IsProtectedPath(const std::wstring& path);
    static bool IsProtectedRegistryKey(const std::wstring& regPath);
    static InstallerType DetectInstallerType(const std::wstring& uninstallString, HKEY rootKey, const std::wstring& regPath);

    std::wstring GetLastError() const { return m_lastError; }

    void RemoveDuplicates(std::vector<LeftoverItem>& items);
    void MergeCrossHiveEntries(std::vector<LeftoverItem>& items);
    void SortUninstallQueue(std::vector<UninstallEntry>& queue);

    LeftoverConfidence TestScoreConfidence(const std::wstring& cand, const std::wstring& kw,
                                           const std::wstring& pub, const std::wstring& inst,
                                           bool isReg, int depth);

private:
    void ScanRegistryKey(HKEY rootKey, const std::wstring& subKey,
                         std::vector<UninstallEntry>& results);
    std::wstring ReadRegString(HKEY hKey, const std::wstring& name);
    DWORD ReadRegDword(HKEY hKey, const std::wstring& name);
    void ScanDirectory(const std::wstring& dir, const std::wstring& keyword,
                       std::vector<LeftoverItem>& results, ScanDepth depth);
    void ScanInstallDirContents(const std::wstring& dir, const std::wstring& keyword,
                                const std::wstring& publisher, std::vector<LeftoverItem>& results,
                                ScanDepth depth, int currentDepth = 0);
    void ScanRegistryForLeftovers(HKEY rootKey, const std::wstring& subKey,
                                  const std::wstring& keyword,
                                  const std::wstring& publisher,
                                  const std::wstring& installPath,
                                  std::vector<LeftoverItem>& results, ScanDepth depth);
    void ScanStartMenu(std::vector<LeftoverItem>& results, const std::wstring& keyword);
    void ScanDesktop(std::vector<LeftoverItem>& results, const std::wstring& keyword);
    void ScanAppPaths(std::vector<LeftoverItem>& results, const std::wstring& keyword);
    void ScanRunKeys(std::vector<LeftoverItem>& results, const std::wstring& keyword);
    void ScanServices(std::vector<LeftoverItem>& results, const std::wstring& keyword,
                      const std::wstring& publisher = L"", const std::wstring& installPath = L"");
    void ScanCOM(std::vector<LeftoverItem>& results, const std::wstring& keyword,
                 const std::wstring& publisher = L"", const std::wstring& installPath = L"");
    void ScanFirewallRules(std::vector<LeftoverItem>& results, const std::wstring& keyword);
    void ScanInstallerCaches(std::vector<LeftoverItem>& results, const std::wstring& keyword);
    void ScanPrefetch(std::vector<LeftoverItem>& results, const UninstallEntry& entry);
    void ScanWERReports(std::vector<LeftoverItem>& results, const UninstallEntry& entry);
    void ScanMSIUpgradeCodes(std::vector<LeftoverItem>& results, const UninstallEntry& entry);
    void ScanUserAssist(std::vector<LeftoverItem>& results, const UninstallEntry& entry);
    void ScanEventLog(std::vector<LeftoverItem>& results, const UninstallEntry& entry);
    void ScanAppCompatFlags(std::vector<LeftoverItem>& results, const UninstallEntry& entry);
    void ScanCOMDeep(std::vector<LeftoverItem>& results, const std::wstring& keyword);
    void ScanProgramFilesOrphans(std::vector<LeftoverItem>& results, const UninstallEntry& entry);
    void ScanAudioPolicyConfig(std::vector<LeftoverItem>& results, const UninstallEntry& entry);
    void ScanHeapLeakDetection(std::vector<LeftoverItem>& results, const UninstallEntry& entry);
    void ScanInstallerFolders(std::vector<LeftoverItem>& results, const UninstallEntry& entry);
    void ScanDebugTracing(std::vector<LeftoverItem>& results, const UninstallEntry& entry);
    void ScanRegisteredApplications(std::vector<LeftoverItem>& results, const UninstallEntry& entry);
    void ScanScheduledTasks(std::vector<LeftoverItem>& results, const std::wstring& keyword,
                            const std::wstring& publisher, const std::wstring& installPath);
    void ScanOrphanedInstallerFiles(std::vector<LeftoverItem>& results, const std::wstring& keyword,
                                    const std::wstring& publisher);

    LeftoverConfidence ScoreConfidence(const std::wstring& candidateName,
                                       const std::wstring& keyword,
                                       const std::wstring& publisher,
                                       const std::wstring& installPath,
                                       bool isRegistry, int depth,
                                       int& outRawScore);

    bool IsStopWord(const std::wstring& word);
    bool IsUsedByOtherApp(const std::wstring& path,
                          const std::vector<UninstallEntry>& allApps,
                          const std::wstring& currentName);
    bool IsExecutableMatch(const std::wstring& fileName, const UninstallEntry& entry);
    std::wstring NormalizeName(const std::wstring& name);

    void FilterByConfidence(std::vector<LeftoverItem>& items, ScanDepth depth);

    std::wstring m_lastError;
    std::vector<UninstallEntry> m_cachedApps;
};

HICON ExtractProgramIcon(const std::wstring& displayIcon);

}

#endif
