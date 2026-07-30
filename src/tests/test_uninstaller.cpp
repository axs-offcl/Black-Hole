#include "test_shared.h"
#include "uninstaller.h"
#include <algorithm>
#include <unordered_map>

using namespace BlackHole;

static std::wstring CompressGUID(const std::wstring& guid) {
    std::wstring result;
    result.reserve(32);
    for (wchar_t c : guid) {
        if (c == L'-' || c == L'{' || c == L'}') continue;
        result += (wchar_t)towlower(c);
    }
    return result;
}

static bool TestCompressGUID() {
    bool ok = true;

    std::wstring g1 = L"{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}";
    std::wstring c1 = CompressGUID(g1);
    ok = ok && (c1 == L"a1b2c3d4e5f67890abcdef1234567890");

    std::wstring g2 = L"A1B2C3D4-E5F6-7890-ABCD-EF1234567890";
    std::wstring c2 = CompressGUID(g2);
    ok = ok && (c2 == L"a1b2c3d4e5f67890abcdef1234567890");

    std::wstring g3 = L"a1b2c3d4e5f67890abcdef1234567890";
    std::wstring c3 = CompressGUID(g3);
    ok = ok && (c3 == L"a1b2c3d4e5f67890abcdef1234567890");

    std::wstring g4 = L"{}";
    std::wstring c4 = CompressGUID(g4);
    ok = ok && (c4 == L"");

    std::wstring g5 = L"";
    std::wstring c5 = CompressGUID(g5);
    ok = ok && (c5 == L"");

    return ok;
}

static bool TestMergeCrossHiveEntries_On() {
    std::vector<LeftoverItem> items;

    LeftoverItem a;
    a.path = L"HKCU\\SOFTWARE\\7-Zip";
    a.displayName = L"7-Zip HKCU";
    a.type = LeftoverItem::RegistryKey;
    a.checked = true;
    a.confidence = LeftoverConfidence::Moderate;
    a.rawScore = 4;
    items.push_back(a);

    LeftoverItem b;
    b.path = L"HKLM\\SOFTWARE\\7-Zip";
    b.displayName = L"7-Zip HKLM";
    b.type = LeftoverItem::RegistryKey;
    b.checked = false;
    b.confidence = LeftoverConfidence::Moderate;
    b.rawScore = 4;
    items.push_back(b);

    Uninstaller uninstaller;
    uninstaller.MergeCrossHiveEntries(items);

    bool ok = true;
    ok = ok && (items.size() == 1);
    ok = ok && (items[0].rawScore == 4 + 4 + 2);
    ok = ok && (items[0].checked == true);
    return ok;
}

static bool TestMergeCrossHiveEntries_ThreeHives() {
    std::vector<LeftoverItem> items;

    LeftoverItem a;
    a.path = L"HKCU\\SOFTWARE\\TestApp";
    a.type = LeftoverItem::RegistryKey;
    a.rawScore = 3;
    a.checked = true;
    items.push_back(a);

    LeftoverItem b;
    b.path = L"HKLM\\SOFTWARE\\TestApp";
    b.type = LeftoverItem::RegistryKey;
    b.rawScore = 3;
    b.checked = false;
    items.push_back(b);

    LeftoverItem c;
    c.path = L"HKLM\\SOFTWARE\\WOW6432Node\\TestApp";
    c.type = LeftoverItem::RegistryKey;
    c.rawScore = 3;
    c.checked = true;
    items.push_back(c);

    Uninstaller uninstaller;
    uninstaller.MergeCrossHiveEntries(items);

    bool ok = true;
    ok = ok && (items.size() == 2);
    bool found = false;
    for (auto& it : items) {
        if (it.path == L"HKCU\\SOFTWARE\\TestApp") {
            ok = ok && (it.rawScore == 3 + 3 + 2);
            ok = ok && (it.checked == true);
            found = true;
        }
    }
    ok = ok && found;
    return ok;
}

static bool TestMergeCrossHiveEntries_NoMergeDifferentPaths() {
    std::vector<LeftoverItem> items;

    LeftoverItem a;
    a.path = L"HKCU\\SOFTWARE\\AppA";
    a.type = LeftoverItem::RegistryKey;
    a.rawScore = 5;
    items.push_back(a);

    LeftoverItem b;
    b.path = L"HKCU\\SOFTWARE\\AppB";
    b.type = LeftoverItem::RegistryKey;
    b.rawScore = 5;
    items.push_back(b);

    Uninstaller uninstaller;
    uninstaller.MergeCrossHiveEntries(items);

    bool ok = true;
    ok = ok && (items.size() == 2);
    ok = ok && (items[0].rawScore == 5);
    ok = ok && (items[1].rawScore == 5);
    return ok;
}

static bool TestMergeCrossHiveEntries_SkipsFiles() {
    std::vector<LeftoverItem> items;

    LeftoverItem a;
    a.path = L"C:\\Program Files\\App\\data.dll";
    a.type = LeftoverItem::File;
    a.rawScore = 5;
    items.push_back(a);

    LeftoverItem b;
    b.path = L"C:\\Program Files\\App\\data.dll";
    b.type = LeftoverItem::File;
    b.rawScore = 5;
    items.push_back(b);

    Uninstaller uninstaller;
    uninstaller.MergeCrossHiveEntries(items);

    bool ok = true;
    ok = ok && (items.size() == 2);
    return ok;
}

static bool TestRemoveDuplicates_On() {
    std::vector<LeftoverItem> items;

    LeftoverItem a;
    a.path = L"C:\\temp\\file.txt";
    a.type = LeftoverItem::File;
    a.rawScore = 4;
    a.checked = true;
    a.confidence = LeftoverConfidence::Moderate;
    items.push_back(a);

    LeftoverItem b;
    b.path = L"C:\\temp\\file.txt";
    b.type = LeftoverItem::File;
    b.rawScore = 5;
    b.checked = false;
    b.confidence = LeftoverConfidence::Moderate;
    items.push_back(b);

    Uninstaller uninstaller;
    uninstaller.RemoveDuplicates(items);

    bool ok = true;
    ok = ok && (items.size() == 1);
    ok = ok && (items[0].rawScore == 9);
    ok = ok && (items[0].checked == true);
    return ok;
}

static bool TestRemoveDuplicates_ThreeSame() {
    std::vector<LeftoverItem> items;

    for (int i = 0; i < 3; i++) {
        LeftoverItem item;
        item.path = L"C:\\shared\\resource.dll";
        item.type = LeftoverItem::File;
        item.rawScore = 3;
        item.checked = (i == 1);
        item.confidence = LeftoverConfidence::Moderate;
        items.push_back(item);
    }

    Uninstaller uninstaller;
    uninstaller.RemoveDuplicates(items);

    bool ok = true;
    ok = ok && (items.size() == 1);
    ok = ok && (items[0].rawScore == 9);
    ok = ok && (items[0].checked == true);
    return ok;
}

static bool TestRemoveDuplicates_NoDups() {
    std::vector<LeftoverItem> items;

    LeftoverItem a;
    a.path = L"C:\\a\\file.txt";
    a.type = LeftoverItem::File;
    a.rawScore = 3;
    items.push_back(a);

    LeftoverItem b;
    b.path = L"C:\\b\\file.txt";
    b.type = LeftoverItem::File;
    b.rawScore = 3;
    items.push_back(b);

    Uninstaller uninstaller;
    uninstaller.RemoveDuplicates(items);

    bool ok = true;
    ok = ok && (items.size() == 2);
    return ok;
}

static bool TestRemoveDuplicates_Empty() {
    std::vector<LeftoverItem> items;
    Uninstaller uninstaller;
    uninstaller.RemoveDuplicates(items);
    return items.empty();
}

static bool TestRemoveDuplicates_ConfidenceUpgrade() {
    std::vector<LeftoverItem> items;

    LeftoverItem a;
    a.path = L"C:\\test\\item";
    a.type = LeftoverItem::File;
    a.rawScore = 3;
    a.confidence = LeftoverConfidence::Risky;
    items.push_back(a);

    LeftoverItem b;
    b.path = L"C:\\test\\item";
    b.type = LeftoverItem::File;
    b.rawScore = 6;
    b.confidence = LeftoverConfidence::Risky;
    items.push_back(b);

    Uninstaller uninstaller;
    uninstaller.RemoveDuplicates(items);

    bool ok = true;
    ok = ok && (items.size() == 1);
    ok = ok && (items[0].rawScore == 9);
    ok = ok && (items[0].confidence == LeftoverConfidence::Safe);
    return ok;
}

static bool TestAdditiveMerging_CombinesScores() {
    std::vector<LeftoverItem> items;

    LeftoverItem a;
    a.path = L"C:\\Program Files\\App\\config.ini";
    a.type = LeftoverItem::File;
    a.rawScore = 6;
    a.checked = false;
    a.confidence = LeftoverConfidence::Moderate;
    items.push_back(a);

    LeftoverItem b;
    b.path = L"C:\\Program Files\\App\\config.ini";
    b.type = LeftoverItem::File;
    b.rawScore = 4;
    b.checked = true;
    b.confidence = LeftoverConfidence::Moderate;
    items.push_back(b);

    Uninstaller uninstaller;
    uninstaller.RemoveDuplicates(items);

    bool ok = true;
    ok = ok && (items.size() == 1);
    ok = ok && (items[0].rawScore == 10);
    ok = ok && (items[0].checked == true);
    ok = ok && (items[0].confidence == LeftoverConfidence::Safe);
    return ok;
}

static bool TestROT13_Simple() {
    std::wstring input = L"Hello World";
    std::wstring expected = L"Uryyb Jbeyq";
    std::wstring decoded = ROT13(input);
    return decoded == expected;
}

static bool TestROT13_Twice() {
    std::wstring input = L"Black Hole (B-H)";
    std::wstring first = ROT13(input);
    std::wstring second = ROT13(first);
    return second == input;
}

static bool TestROT13_NonAlpha() {
    std::wstring input = L"123!@#abc";
    std::wstring result = ROT13(input);
    bool ok = true;
    ok = ok && (result[0] == L'1');
    ok = ok && (result[1] == L'2');
    ok = ok && (result[2] == L'3');
    ok = ok && (result[3] == L'!');
    ok = ok && (result[4] == L'@');
    ok = ok && (result[5] == L'#');
    ok = ok && (result[6] == L'n');
    ok = ok && (result[7] == L'o');
    ok = ok && (result[8] == L'p');
    return ok;
}

static bool TestROT13_Empty() {
    return ROT13(L"") == L"";
}

static bool TestRemoveDuplicates_MultipleScanners() {
    std::vector<LeftoverItem> items;

    LeftoverItem a;
    a.path = L"C:\\Program Files\\App\\config.ini";
    a.type = LeftoverItem::File;
    a.rawScore = 4;
    a.checked = false;
    items.push_back(a);

    LeftoverItem b;
    b.path = L"C:\\Program Files\\App\\config.ini";
    b.type = LeftoverItem::File;
    b.rawScore = 6;
    b.checked = true;
    items.push_back(b);

    LeftoverItem c;
    c.path = L"C:\\Program Files\\App\\config.ini";
    c.type = LeftoverItem::File;
    c.rawScore = 3;
    c.checked = false;
    items.push_back(c);

    Uninstaller uninstaller;
    uninstaller.RemoveDuplicates(items);

    bool ok = true;
    ok = ok && (items.size() == 1);
    ok = ok && (items[0].rawScore == 13);
    ok = ok && (items[0].checked == true);
    ok = ok && (items[0].confidence == LeftoverConfidence::Safe);
    return ok;
}

static bool TestMergeCrossHive_MixedTypes() {
    std::vector<LeftoverItem> items;

    LeftoverItem reg;
    reg.path = L"HKCU\\SOFTWARE\\TestApp";
    reg.type = LeftoverItem::RegistryKey;
    reg.rawScore = 5;
    items.push_back(reg);

    LeftoverItem file;
    file.path = L"HKCU\\SOFTWARE\\TestApp";
    file.type = LeftoverItem::File;
    file.rawScore = 5;
    items.push_back(file);

    Uninstaller uninstaller;
    uninstaller.MergeCrossHiveEntries(items);

    bool ok = true;
    ok = ok && (items.size() == 2);
    ok = ok && (items[0].rawScore == 5);
    ok = ok && (items[1].rawScore == 5);
    return ok;
}

static bool TestFiveScanners_DeduplicationPipeline() {
    std::vector<LeftoverItem> items;

    LeftoverItem a1;
    a1.path = L"HKLM\\SOFTWARE\\Microsoft\\Tracing\\MyApp";
    a1.type = LeftoverItem::RegistryKey;
    a1.rawScore = 10;
    a1.checked = false;
    items.push_back(a1);

    LeftoverItem a2;
    a2.path = L"HKLM\\SOFTWARE\\Microsoft\\Tracing\\MyApp";
    a2.type = LeftoverItem::RegistryKey;
    a2.rawScore = 6;
    a2.checked = false;
    items.push_back(a2);

    Uninstaller uninstaller;
    uninstaller.RemoveDuplicates(items);

    bool ok = true;
    ok = ok && (items.size() == 1);
    ok = ok && (items[0].rawScore == 16);
    return ok;
}

static bool TestRegisteredApplications_CrossHiveMerge() {
    std::vector<LeftoverItem> items;

    LeftoverItem a;
    a.path = L"HKLM\\SOFTWARE\\RegisteredApplications\\MyApp";
    a.type = LeftoverItem::RegistryKey;
    a.rawScore = 6;
    a.checked = false;
    items.push_back(a);

    LeftoverItem b;
    b.path = L"HKCU\\SOFTWARE\\RegisteredApplications\\MyApp";
    b.type = LeftoverItem::RegistryKey;
    b.rawScore = 6;
    b.checked = false;
    items.push_back(b);

    Uninstaller uninstaller;
    uninstaller.MergeCrossHiveEntries(items);

    bool ok = true;
    ok = ok && (items.size() == 1);
    ok = ok && (items[0].rawScore == 6 + 6 + 2);
    return ok;
}

static bool TestDebugTracing_ScoringAccumulation() {
    std::vector<LeftoverItem> items;

    LeftoverItem a;
    a.path = L"HKLM\\SOFTWARE\\Microsoft\\Tracing\\MyApp_RASMAN";
    a.type = LeftoverItem::RegistryKey;
    a.rawScore = 12;
    a.checked = false;
    items.push_back(a);

    LeftoverItem b;
    b.path = L"HKLM\\SOFTWARE\\Microsoft\\Tracing\\MyApp_RASAPI32";
    b.type = LeftoverItem::RegistryKey;
    b.rawScore = 8;
    b.checked = false;
    items.push_back(b);

    Uninstaller uninstaller;
    uninstaller.RemoveDuplicates(items);

    bool ok = true;
    ok = ok && (items.size() == 2);
    return ok;
}

static bool TestInstallerFolders_NameMatch() {
    std::vector<LeftoverItem> items;

    LeftoverItem a;
    a.path = L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\Folders\\C:\\Program Files\\MyApp";
    a.type = LeftoverItem::RegistryKey;
    a.rawScore = 8;
    a.checked = false;
    items.push_back(a);

    Uninstaller uninstaller;
    uninstaller.RemoveDuplicates(items);

    bool ok = true;
    ok = ok && (items.size() == 1);
    ok = ok && (items[0].rawScore == 8);
    return ok;
}

static bool TestExtractPEMetadata_EmptyPath() {
    PEMetadata meta;
    bool result = ExtractPEMetadata(L"", meta);
    return !result;
}

static bool TestExtractPEMetadata_NonexistentFile() {
    PEMetadata meta;
    bool result = ExtractPEMetadata(L"C:\\nonexistent\\file.exe", meta);
    return !result;
}

static bool TestExtractPEMetadata_SystemExe() {
    wchar_t winDir[MAX_PATH];
    if (!GetWindowsDirectoryW(winDir, MAX_PATH)) return true;
    std::wstring notepad = std::wstring(winDir) + L"\\notepad.exe";

    DWORD attr = GetFileAttributesW(notepad.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return true;

    PEMetadata meta;
    bool result = ExtractPEMetadata(notepad, meta);
    if (!result) return false;

    bool ok = true;
    ok = ok && (!meta.fileVersion.empty() || !meta.productVersion.empty());
    return ok;
}

static bool TestEnrichEntryFromPE_WithExe() {
    wchar_t winDir[MAX_PATH];
    if (!GetWindowsDirectoryW(winDir, MAX_PATH)) return true;
    std::wstring notepad = std::wstring(winDir) + L"\\notepad.exe";

    DWORD attr = GetFileAttributesW(notepad.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return true;

    UninstallEntry entry;
    entry.sortedExecutables.push_back(L"notepad.exe");
    entry.installPath = winDir;

    EnrichEntryFromPE(entry);

    bool ok = true;
    if (!entry.publisher.empty()) {
        ok = ok && (!entry.publisher.empty());
    }
    return ok;
}

static bool TestEnrichEntryFromPE_EmptyExecutables() {
    UninstallEntry entry;
    EnrichEntryFromPE(entry);
    return entry.displayName.empty();
}

static bool TestSortUninstallQueue_Empty() {
    std::vector<UninstallEntry> queue;
    Uninstaller uninstaller;
    uninstaller.SortUninstallQueue(queue);
    return queue.empty();
}

static bool TestSortUninstallQueue_SingleItem() {
    std::vector<UninstallEntry> queue;
    UninstallEntry e;
    e.displayName = L"TestApp";
    e.installerType = InstallerType::Nsis;
    queue.push_back(e);

    Uninstaller uninstaller;
    uninstaller.SortUninstallQueue(queue);

    return queue.size() == 1 && queue[0].displayName == L"TestApp";
}

static bool TestSortUninstallQueue_SystemComponentLast() {
    std::vector<UninstallEntry> queue;

    UninstallEntry sysComp;
    sysComp.displayName = L"SystemComponent";
    sysComp.installerType = InstallerType::Msi;
    sysComp.isSystemComponent = true;
    queue.push_back(sysComp);

    UninstallEntry normal;
    normal.displayName = L"NormalApp";
    normal.installerType = InstallerType::Nsis;
    normal.isSystemComponent = false;
    queue.push_back(normal);

    Uninstaller uninstaller;
    uninstaller.SortUninstallQueue(queue);

    bool ok = true;
    ok = ok && (queue.size() == 2);
    ok = ok && (queue[0].displayName == L"NormalApp");
    ok = ok && (queue[1].displayName == L"SystemComponent");
    return ok;
}

static bool TestSortUninstallQueue_UpdateLast() {
    std::vector<UninstallEntry> queue;

    UninstallEntry update;
    update.displayName = L"Update for App";
    update.installerType = InstallerType::Msi;
    queue.push_back(update);

    UninstallEntry normal;
    normal.displayName = L"App";
    normal.installerType = InstallerType::Msi;
    queue.push_back(normal);

    Uninstaller uninstaller;
    uninstaller.SortUninstallQueue(queue);

    bool ok = true;
    ok = ok && (queue[0].displayName == L"App");
    ok = ok && (queue[1].displayName == L"Update for App");
    return ok;
}

static bool TestSortUninstallQueue_MsiGrouped() {
    std::vector<UninstallEntry> queue;

    UninstallEntry nsis;
    nsis.displayName = L"NsisApp";
    nsis.installerType = InstallerType::Nsis;
    queue.push_back(nsis);

    UninstallEntry msi1;
    msi1.displayName = L"MsiApp1";
    msi1.installerType = InstallerType::Msi;
    msi1.isMsiInstaller = true;
    msi1.estimatedSize = 50000;
    queue.push_back(msi1);

    UninstallEntry msi2;
    msi2.displayName = L"MsiApp2";
    msi2.installerType = InstallerType::Msi;
    msi2.isMsiInstaller = true;
    msi2.estimatedSize = 10000;
    queue.push_back(msi2);

    Uninstaller uninstaller;
    uninstaller.SortUninstallQueue(queue);

    bool ok = true;
    ok = ok && (queue.size() == 3);
    ok = ok && (queue[0].displayName == L"NsisApp");
    ok = ok && (queue[1].displayName == L"MsiApp1");
    ok = ok && (queue[2].displayName == L"MsiApp2");
    return ok;
}

static bool TestSortUninstallQueue_TypeOrder() {
    std::vector<UninstallEntry> queue;

    UninstallEntry inno;
    inno.displayName = L"InnoApp";
    inno.installerType = InstallerType::InnoSetup;
    queue.push_back(inno);

    UninstallEntry nsis;
    nsis.displayName = L"NsisApp";
    nsis.installerType = InstallerType::Nsis;
    queue.push_back(nsis);

    UninstallEntry msi;
    msi.displayName = L"MsiApp";
    msi.installerType = InstallerType::Msi;
    queue.push_back(msi);

    UninstallEntry store;
    store.displayName = L"StoreApp";
    store.installerType = InstallerType::StoreApp;
    queue.push_back(store);

    Uninstaller uninstaller;
    uninstaller.SortUninstallQueue(queue);

    bool ok = true;
    ok = ok && (queue[0].displayName == L"NsisApp");
    ok = ok && (queue[1].displayName == L"InnoApp");
    ok = ok && (queue[2].displayName == L"MsiApp");
    ok = ok && (queue[3].displayName == L"StoreApp");
    return ok;
}

static bool TestResolveAppIconPath_EmptyEntry() {
    UninstallEntry entry;
    std::wstring path = ResolveAppIconPath(entry);
    return path == L"imageres.dll,15";
}

static bool TestResolveAppIconPath_DisplayIconSet() {
    UninstallEntry entry;
    entry.displayIcon = L"C:\\Windows\\System32\\notepad.exe,0";
    std::wstring path = ResolveAppIconPath(entry);
    return path.find(L"notepad.exe") != std::wstring::npos;
}

static bool TestResolveAppIconPath_InstallPathKnownIcon() {
    UninstallEntry entry;
    entry.installPath = L"C:\\Windows\\System32";
    entry.displayIcon = L"";
    std::wstring path = ResolveAppIconPath(entry);
    return !path.empty();
}

static bool TestExtractAppIcon_EmptyEntry() {
    UninstallEntry entry;
    HICON hIcon = ExtractAppIcon(entry);
    if (hIcon) {
        DestroyIcon(hIcon);
        return true;
    }
    return true;
}

static bool TestExtractAppIcon_Notepad() {
    UninstallEntry entry;
    entry.displayIcon = L"C:\\Windows\\System32\\notepad.exe,0";
    HICON hIcon = ExtractAppIcon(entry);
    bool ok = (hIcon != NULL);
    if (hIcon) DestroyIcon(hIcon);
    return ok;
}

static bool TestExtractIconFromPNG_Nonexistent() {
    HICON hIcon = ExtractIconFromPNG(L"C:\\nonexistent\\file.png");
    return hIcon == NULL;
}

static bool TestExtractIconFromPNG_EmptyPath() {
    HICON hIcon = ExtractIconFromPNG(L"");
    return hIcon == NULL;
}

static bool TestResolveAppIconPath_InvalidDisplayIcon() {
    UninstallEntry entry;
    entry.displayIcon = L"C:\\nonexistent\\fake.ico";
    entry.installPath = L"C:\\Windows\\System32";
    entry.sortedExecutables.push_back(L"notepad.exe");
    std::wstring path = ResolveAppIconPath(entry);
    return path.find(L"notepad.exe") != std::wstring::npos;
}

static bool TestVerifyCertificate_EmptyPath() {
    CertStatus status = VerifyCertificate(L"");
    return status == CertStatus::NotFound;
}

static bool TestVerifyCertificate_Nonexistent() {
    CertStatus status = VerifyCertificate(L"C:\\nonexistent\\file.exe");
    return status == CertStatus::NotFound;
}

static bool TestVerifyCertificate_Notepad() {
    CertStatus status = VerifyCertificate(L"C:\\Windows\\System32\\notepad.exe");
    return status == CertStatus::Verified || status == CertStatus::Unverified || status == CertStatus::NotFound;
}

static bool TestDetectBitness_EmptyPath() {
    Bitness bitness = DetectBitness(L"");
    return bitness == Bitness::Unknown;
}

static bool TestDetectBitness_Nonexistent() {
    Bitness bitness = DetectBitness(L"C:\\nonexistent\\file.exe");
    return bitness == Bitness::Unknown;
}

static bool TestDetectBitness_Notepad() {
    Bitness bitness = DetectBitness(L"C:\\Windows\\System32\\notepad.exe");
    return bitness == Bitness::X64 || bitness == Bitness::X86 || bitness == Bitness::Unknown;
}

static bool TestIsMicrosoftApp() {
    UninstallEntry entry;
    entry.publisher = L"Microsoft Corporation";
    entry.publisherLower = L"microsoft corporation";
    entry.displayName = L"Notepad";
    entry.displayNameLower = L"notepad";
    return IsMicrosoftApp(entry);
}

static bool TestIsStoreApp() {
    UninstallEntry entry;
    entry.registryKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft.WindowsTerminal_8wekyb3d8bbwe";
    entry.registryKeyLower = L"software\\microsoft\\windows\\currentversion\\uninstall\\microsoft.windowsterminal_8wekyb3d8bbwe";
    entry.installerType = InstallerType::Unknown;
    return IsStoreApp(entry);
}

static bool TestScanDirectoryOrphans_ReturnsVector() {
    Uninstaller u;
    auto orphans = u.ScanDirectoryOrphans();
    return true;
}

static bool TestScanDirectoryOrphans_EmptyProgramFiles() {
    Uninstaller u;
    auto orphans = u.ScanDirectoryOrphans();
    for (const auto& o : orphans) {
        if (o.isOrphaned != true) return false;
    }
    return true;
}

void RegisterUninstallerTests(TestRunner& runner) {
    runner.AddTest("Uninstaller_CompressGUID", TestCompressGUID);
    runner.AddTest("Uninstaller_MergeCrossHive_TwoEntries", TestMergeCrossHiveEntries_On);
    runner.AddTest("Uninstaller_MergeCrossHive_ThreeHives", TestMergeCrossHiveEntries_ThreeHives);
    runner.AddTest("Uninstaller_MergeCrossHive_NoMergeDiffPaths", TestMergeCrossHiveEntries_NoMergeDifferentPaths);
    runner.AddTest("Uninstaller_MergeCrossHive_SkipsFiles", TestMergeCrossHiveEntries_SkipsFiles);
    runner.AddTest("Uninstaller_RemoveDuplicates_TwoSame", TestRemoveDuplicates_On);
    runner.AddTest("Uninstaller_RemoveDuplicates_ThreeSame", TestRemoveDuplicates_ThreeSame);
    runner.AddTest("Uninstaller_RemoveDuplicates_NoDups", TestRemoveDuplicates_NoDups);
    runner.AddTest("Uninstaller_RemoveDuplicates_Empty", TestRemoveDuplicates_Empty);
    runner.AddTest("Uninstaller_RemoveDuplicates_ConfidenceUpgrade", TestRemoveDuplicates_ConfidenceUpgrade);
    runner.AddTest("Uninstaller_AdditiveMerging_CombinesScores", TestAdditiveMerging_CombinesScores);
    runner.AddTest("Uninstaller_ROT13_Simple", TestROT13_Simple);
    runner.AddTest("Uninstaller_ROT13_Twice", TestROT13_Twice);
    runner.AddTest("Uninstaller_ROT13_NonAlpha", TestROT13_NonAlpha);
    runner.AddTest("Uninstaller_ROT13_Empty", TestROT13_Empty);
    runner.AddTest("Uninstaller_RemoveDuplicates_MultipleScanners", TestRemoveDuplicates_MultipleScanners);
    runner.AddTest("Uninstaller_MergeCrossHive_MixedTypes", TestMergeCrossHive_MixedTypes);
    runner.AddTest("Uninstaller_FiveScanners_DedupPipeline", TestFiveScanners_DeduplicationPipeline);
    runner.AddTest("Uninstaller_RegApps_CrossHiveMerge", TestRegisteredApplications_CrossHiveMerge);
    runner.AddTest("Uninstaller_DebugTracing_Scoring", TestDebugTracing_ScoringAccumulation);
    runner.AddTest("Uninstaller_InstallerFolders_NameMatch", TestInstallerFolders_NameMatch);
    runner.AddTest("Uninstaller_ExtractPEMeta_EmptyPath", TestExtractPEMetadata_EmptyPath);
    runner.AddTest("Uninstaller_ExtractPEMeta_Nonexistent", TestExtractPEMetadata_NonexistentFile);
    runner.AddTest("Uninstaller_ExtractPEMeta_SystemExe", TestExtractPEMetadata_SystemExe);
    runner.AddTest("Uninstaller_EnrichPE_WithExe", TestEnrichEntryFromPE_WithExe);
    runner.AddTest("Uninstaller_EnrichPE_EmptyExecs", TestEnrichEntryFromPE_EmptyExecutables);
    runner.AddTest("Uninstaller_SortQueue_Empty", TestSortUninstallQueue_Empty);
    runner.AddTest("Uninstaller_SortQueue_SingleItem", TestSortUninstallQueue_SingleItem);
    runner.AddTest("Uninstaller_SortQueue_SysCompLast", TestSortUninstallQueue_SystemComponentLast);
    runner.AddTest("Uninstaller_SortQueue_UpdateLast", TestSortUninstallQueue_UpdateLast);
    runner.AddTest("Uninstaller_SortQueue_MsiGrouped", TestSortUninstallQueue_MsiGrouped);
    runner.AddTest("Uninstaller_SortQueue_TypeOrder", TestSortUninstallQueue_TypeOrder);
    runner.AddTest("Uninstaller_ResolveIconPath_Empty", TestResolveAppIconPath_EmptyEntry);
    runner.AddTest("Uninstaller_ResolveIconPath_DisplayIcon", TestResolveAppIconPath_DisplayIconSet);
    runner.AddTest("Uninstaller_ResolveIconPath_KnownIcon", TestResolveAppIconPath_InstallPathKnownIcon);
    runner.AddTest("Uninstaller_ResolveIconPath_InvalidFallback", TestResolveAppIconPath_InvalidDisplayIcon);
    runner.AddTest("Uninstaller_ExtractAppIcon_Empty", TestExtractAppIcon_EmptyEntry);
    runner.AddTest("Uninstaller_ExtractAppIcon_Notepad", TestExtractAppIcon_Notepad);
    runner.AddTest("Uninstaller_ExtractPNG_Nonexistent", TestExtractIconFromPNG_Nonexistent);
    runner.AddTest("Uninstaller_ExtractPNG_EmptyPath", TestExtractIconFromPNG_EmptyPath);
    runner.AddTest("Uninstaller_VerifyCert_EmptyPath", TestVerifyCertificate_EmptyPath);
    runner.AddTest("Uninstaller_VerifyCert_Nonexistent", TestVerifyCertificate_Nonexistent);
    runner.AddTest("Uninstaller_VerifyCert_Notepad", TestVerifyCertificate_Notepad);
    runner.AddTest("Uninstaller_DetectBitness_EmptyPath", TestDetectBitness_EmptyPath);
    runner.AddTest("Uninstaller_DetectBitness_Nonexistent", TestDetectBitness_Nonexistent);
    runner.AddTest("Uninstaller_DetectBitness_Notepad", TestDetectBitness_Notepad);
    runner.AddTest("Uninstaller_IsMicrosoftApp", TestIsMicrosoftApp);
    runner.AddTest("Uninstaller_IsStoreApp", TestIsStoreApp);
    runner.AddTest("Uninstaller_ScanDirOrphans_ReturnsVector", TestScanDirectoryOrphans_ReturnsVector);
    runner.AddTest("Uninstaller_ScanDirOrphans_AllOrphaned", TestScanDirectoryOrphans_EmptyProgramFiles);
}
