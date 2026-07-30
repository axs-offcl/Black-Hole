; Black Hole (B-H) v2.0.0 - NSIS Installer Script
; Requires NSIS 3.0+ with UAC plugin

!include "MUI2.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"

; ============================================================================
; General Settings
; ============================================================================

Name "Black Hole (B-H) v2.0.0"
OutFile "BlackHoleInstaller.exe"
InstallDir "$PROGRAMFILES\BlackHole"
InstallDirRegKey HKLM "Software\BlackHole" "InstallDir"
RequestExecutionLevel admin

; ============================================================================
; Version Information
; ============================================================================

VIProductVersion "2.0.0.0"
VIAddVersionKey "ProductName" "Black Hole (B-H)"
VIAddVersionKey "CompanyName" "Black Hole Project"
VIAddVersionKey "FileDescription" "Secure File Deletion Utility"
VIAddVersionKey "FileVersion" "2.0.0.0"
VIAddVersionKey "ProductVersion" "2.0.0.0"
VIAddVersionKey "LegalCopyright" "Copyright (C) 2026"

; ============================================================================
; Interface Settings
; ============================================================================

!define MUI_ABORTWARNING
!define MUI_ICON "blackhole.ico"
!define MUI_UNICON "blackhole.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "header.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "wizard.bmp"

; ============================================================================
; Pages
; ============================================================================

; Welcome page
!insertmacro MUI_PAGE_WELCOME

; License page
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"

; Components page
!insertmacro MUI_PAGE_COMPONENTS

; Directory page
!insertmacro MUI_PAGE_DIRECTORY

; Instfiles page
!insertmacro MUI_PAGE_INSTFILES

; Finish page
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; ============================================================================
; Languages
; ============================================================================

!insertmacro MUI_LANGUAGE "English"

; ============================================================================
; Installer Sections
; ============================================================================

Section "Black Hole Core Files" SecCore
    SectionIn RO
    
    ; Set output path to installation directory
    SetOutPath "$INSTDIR"
    
    ; Install main executable
    File "bin\Release\BlackHole.exe"
    
    ; Install CLI executable
    File "bin\Release\BlackHoleCLI.exe"
    
    ; Install static library
    File "lib\Release\BlackHoleCore.lib"
    
    ; Install headers
    SetOutPath "$INSTDIR\include"
    File "include\*.h"
    
    ; Store installation folder
    WriteRegStr HKLM "Software\BlackHole" "InstallDir" "$INSTDIR"
    
    ; Create uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    
    ; Add to Programs and Features
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BlackHole" \
        "DisplayName" "Black Hole (B-H)"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BlackHole" \
        "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BlackHole" \
        "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BlackHole" \
        "DisplayVersion" "2.0.0"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BlackHole" \
        "Publisher" "Black Hole Project"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BlackHole" \
        "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BlackHole" \
        "NoRepair" 1
    
    ; Calculate and store installed size
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BlackHole" \
        "EstimatedSize" "$0"
SectionEnd

Section "Start Menu Shortcuts" SecStartMenu
    CreateDirectory "$SMPROGRAMS\Black Hole"
    CreateShortCut "$SMPROGRAMS\Black Hole\Black Hole Dashboard.lnk" "$INSTDIR\BlackHole.exe"
    CreateShortCut "$SMPROGRAMS\Black Hole\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Desktop Shortcut" SecDesktop
    CreateShortCut "$DESKTOP\Black Hole.lnk" "$INSTDIR\BlackHole.exe"
SectionEnd

Section "Context Menu Integration" SecContextMenu
    ; Register context menu
    WriteRegStr HKCR "*\shell\SendToBlackHole" "" "Send to Black Hole"
    WriteRegStr HKCR "*\shell\SendToBlackHole\command" "" '"$INSTDIR\BlackHole.exe" --delete "%1"'
SectionEnd

; ============================================================================
; Section Descriptions
; ============================================================================

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} \
        "Core application files required to run Black Hole."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenu} \
        "Create Start Menu shortcuts for easy access."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} \
        "Create a desktop shortcut."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecContextMenu} \
        "Add 'Send to Black Hole' option in right-click context menu."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ============================================================================
; Uninstaller Section
; ============================================================================

Section "Uninstall"
    ; Remove files
    Delete "$INSTDIR\BlackHole.exe"
    Delete "$INSTDIR\BlackHoleCLI.exe"
    Delete "$INSTDIR\BlackHoleCore.lib"
    Delete "$INSTDIR\include\*.h"
    RMDir "$INSTDIR\include"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"
    
    ; Remove Start Menu shortcuts
    Delete "$SMPROGRAMS\Black Hole\Black Hole Dashboard.lnk"
    Delete "$SMPROGRAMS\Black Hole\Uninstall.lnk"
    RMDir "$SMPROGRAMS\Black Hole"
    
    ; Remove desktop shortcut
    Delete "$DESKTOP\Black Hole.lnk"
    
    ; Remove context menu
    DeleteRegKey HKCR "*\shell\SendToBlackHole\command"
    DeleteRegKey HKCR "*\shell\SendToBlackHole"
    
    ; Remove registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BlackHole"
    DeleteRegKey HKLM "Software\BlackHole"
    
    ; Remove application data (optional - uncomment if desired)
    ; RMDir /r "$APPDATA\BlackHole"
SectionEnd

; ============================================================================
; Callbacks
; ============================================================================

Function .onInit
    ; Check if already installed
    ReadRegStr $0 HKLM "Software\BlackHole" "InstallDir"
    ${If} $0 != ""
        MessageBox MB_YESNO|MB_ICONQUESTION \
            "Black Hole is already installed. Do you want to overwrite the existing installation?" \
            IDYES continueInstall
        Abort
        continueInstall:
    ${EndIf}
FunctionEnd

Function un.onInit
    MessageBox MB_YESNO|MB_ICONQUESTION \
        "Are you sure you want to completely remove Black Hole and all of its components?" \
        IDYES proceedUninstall
    Abort
    proceedUninstall:
FunctionEnd
