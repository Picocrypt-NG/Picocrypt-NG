; Picocrypt-NG NSIS installer script (canonical source-of-truth).
;
; Build:   makensis -WX -V4 -DVERSION=<version> dist/windows/installer.nsi
; Signed uninstaller round trip:
;   makensis -WX -V4 -DVERSION=<version> -DEXPORT_UNINST dist/windows/installer.nsi
;   sign dist/windows/Uninstall.exe externally
;   makensis -WX -V4 -DVERSION=<version> -DIMPORT_UNINST dist/windows/installer.nsi
; Output:  dist/windows/Picocrypt-NG-Setup.exe (per OutFile, written adjacent to this script)
;
; Decision references:
;   D-01 canonical location           D-21 six-key registry layout
;   D-03 -DVERSION CI inject point    D-22 RegisteredApplications/Capabilities
;   D-05 -WX -V4 strict mode          D-23 Add/Remove Programs entry
;   D-07 per-machine HKLM + UAC       D-25/D-26 SHChangeNotify
;   D-09 x64 guard                    D-27 hybrid uninstaller cleanup
;   D-10 MUI2 page sequence           D-28 RMDir (only if empty)
;   D-11 LICENSE via ${__FILEDIR__}   Pitfall 4 SetRegView 64
;   D-14 English-only LangString      Pitfall 11 MUI_FINISHPAGE_RUN admin-token caveat
;   D-20 ProgID=PicocryptNG.pcv

; --- VERSION guard (D-03, Pitfall 3) ---
!ifndef VERSION
  !error "VERSION must be defined via -DVERSION=... on the makensis command line"
!endif

; --- Includes (D-10, all stock — no external plugins) ---
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"
!include "Sections.nsh"

; --- Defines ---
!define APPNAME     "Picocrypt-NG"
!define COMPANYNAME "Picocrypt-NG developers"
!define DESCRIPTION "Small, secure file encryption tool"
!define HELPURL     "https://github.com/Picocrypt/Picocrypt-NG"
!define PROGID      "PicocryptNG.pcv"
!define ARP         "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

; --- Installer attributes ---
Name              "${APPNAME}"
OutFile "Picocrypt-NG-Setup.exe"
InstallDir        "$PROGRAMFILES64\${APPNAME}"
InstallDirRegKey  HKLM "Software\${APPNAME}" "InstallDir"
RequestExecutionLevel admin
Unicode           true
SetCompressor     /SOLID lzma
ShowInstDetails   show
ShowUnInstDetails show

VIProductVersion  "${VERSION}.0.0"
VIAddVersionKey   "ProductName"     "${APPNAME}"
VIAddVersionKey   "FileDescription" "${APPNAME} installer"
VIAddVersionKey   "FileVersion"     "${VERSION}"
VIAddVersionKey   "ProductVersion"  "${VERSION}"
VIAddVersionKey   "LegalCopyright"  "(c) ${COMPANYNAME}"

; --- MUI2 pages (D-10, D-11, D-13, D-15) ---
; License path uses ${__FILEDIR__}\..\..\LICENSE per Pitfall 5 (script-relative,
; not CWD-relative — the brittle CWD form is forbidden by the contract test).
!define MUI_ABORTWARNING
!define MUI_ICON   "${__FILEDIR__}\..\..\images\key.ico"
!define MUI_UNICON "${__FILEDIR__}\..\..\images\key.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${__FILEDIR__}\..\..\LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

; The per-machine installer is elevated; launch the app separately as the user.
!insertmacro MUI_PAGE_FINISH

!ifndef IMPORT_UNINST
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!endif

!insertmacro MUI_LANGUAGE "English"

; --- .onInit + un.onInit (D-09 + Pitfall 4 — SetRegView 64 MANDATORY) ---
Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "Picocrypt-NG requires 64-bit Windows."
    Abort
  ${EndIf}
  SetRegView 64
FunctionEnd

!ifndef IMPORT_UNINST
Function un.onInit
  SetRegView 64
FunctionEnd
!endif

; --- Section: Picocrypt-NG (required, hidden via leading dash, RO) ---
Section "-Picocrypt-NG (required)" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR"

  ; --- Binaries (D-29: portable artifact installed as Picocrypt-NG.exe) ---
  ; File /oname= writes straight to the install name and overwrites by default,
  ; so re-install/upgrade replaces the prior binary in place. A plain Rename fails
  ; when $INSTDIR\Picocrypt-NG.exe already exists from an earlier version, silently
  ; keeping the stale binary (discussion #163).
  ;
  ; Running-instance guard: a running Picocrypt-NG locks Picocrypt-NG.exe, so the
  ; overwrite fails. SetOverwrite try surfaces that as the error flag (instead of
  ; the stock Abort/Retry/Ignore dialog whose "Ignore" would leave a stale binary).
  ; Ask the user to close the app and retry; abort on cancel. We deliberately do
  ; NOT force-kill — that could corrupt an in-progress encryption.
  SetOverwrite try
  pcng_main_retry:
  ClearErrors
  File "/oname=Picocrypt-NG.exe" "${__FILEDIR__}\..\..\src\Picocrypt-NG-portable.exe"
  ${If} ${Errors}
    ; /SD IDCANCEL: silent installs (/S) get no dialog, so default to cancel ->
    ; abort rather than looping on the implicit retry default.
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION \
      "Could not update Picocrypt-NG.exe.$\r$\nIt may still be running - please close Picocrypt-NG, then click Retry." \
      /SD IDCANCEL \
      IDRETRY pcng_main_retry
    ; Non-zero exit so unattended installs can detect the failure.
    SetErrorLevel 2
    Abort "Setup cannot continue while Picocrypt-NG is running."
  ${EndIf}
  SetOverwrite on

  ; Sweep the orphaned portable binary left by the pre-fix upgrade bug (#163) on
  ; machines that already hit it; harmless no-op on clean installs.
  Delete "$INSTDIR\Picocrypt-NG-portable.exe"

  File "${__FILEDIR__}\..\..\src\Picocrypt-NG-cli.exe"

  ; --- File-type icon (always copied; Default Apps UI may need it even if SecAssoc unchecked) ---
  File "${__FILEDIR__}\..\..\images\pcv-icon.ico"

  ; --- Uninstaller writer ---
!ifdef IMPORT_UNINST
  File "/oname=Uninstall.exe" "${__FILEDIR__}\Uninstall.exe"
!else
  WriteUninstaller "$INSTDIR\Uninstall.exe"
!endif

  ; --- InstallDir record for re-install detection (D-24) ---
  WriteRegStr HKLM "Software\${APPNAME}" "InstallDir" "$INSTDIR"

  ; --- Add/Remove Programs entry (D-23) ---
  WriteRegStr HKLM "${ARP}" "DisplayName"          "${APPNAME}"
  WriteRegStr HKLM "${ARP}" "DisplayIcon"          '"$INSTDIR\Picocrypt-NG.exe",0'
  WriteRegStr HKLM "${ARP}" "DisplayVersion"       "${VERSION}"
  WriteRegStr HKLM "${ARP}" "Publisher"            "${COMPANYNAME}"
  WriteRegStr HKLM "${ARP}" "URLInfoAbout"         "${HELPURL}"
  WriteRegStr HKLM "${ARP}" "InstallLocation"      "$INSTDIR"
  WriteRegStr HKLM "${ARP}" "UninstallString"      '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${ARP}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKLM "${ARP}" "NoModify" 1
  WriteRegDWORD HKLM "${ARP}" "NoRepair" 1

  ; --- EstimatedSize MUST come AFTER File commands (Pitfall 7) ---
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${ARP}" "EstimatedSize" "$0"
SectionEnd

!ifdef EXPORT_UNINST
  ; Export the generated uninstaller for external signing and -DIMPORT_UNINST.
  !uninstfinalize 'echo copy /Y "%1" "${__FILEDIR__}\Uninstall.exe"&copy /Y "%1" "${__FILEDIR__}\Uninstall.exe" >nul'
!endif

; --- Section: Associate .pcv files (D-21 six-key, D-22 capabilities, D-25 SHChangeNotify) ---
Section "Associate .pcv files" SecAssoc
  ; --- Extension key (D-21) ---
  WriteRegStr HKLM "Software\Classes\.pcv" ""              "${PROGID}"
  WriteRegStr HKLM "Software\Classes\.pcv" "ContentType"   "application/x-pcv"
  WriteRegStr HKLM "Software\Classes\.pcv" "PerceivedType" "document"

  ; --- OpenWithProgids (multi-app coexistence, D-21) ---
  WriteRegStr HKLM "Software\Classes\.pcv\OpenWithProgids" "${PROGID}" ""

  ; --- ProgID key (D-21) ---
  WriteRegStr HKLM "Software\Classes\${PROGID}" ""                "Picocrypt-NG encrypted volume"
  WriteRegStr HKLM "Software\Classes\${PROGID}" "FriendlyAppName" "${APPNAME}"
  WriteRegStr HKLM "Software\Classes\${PROGID}\DefaultIcon" ""    '"$INSTDIR\pcv-icon.ico"'
  WriteRegStr HKLM "Software\Classes\${PROGID}\shell\open\command" "" '"$INSTDIR\Picocrypt-NG.exe" "%1"'

  ; --- ApplicationCapabilities (D-22) ---
  WriteRegStr HKLM "Software\${APPNAME}\Capabilities" "ApplicationName"        "${APPNAME}"
  WriteRegStr HKLM "Software\${APPNAME}\Capabilities" "ApplicationDescription" "${DESCRIPTION}"
  WriteRegStr HKLM "Software\${APPNAME}\Capabilities" "ApplicationIcon"        '"$INSTDIR\Picocrypt-NG.exe",0'
  WriteRegStr HKLM "Software\${APPNAME}\Capabilities\FileAssociations" ".pcv"  "${PROGID}"

  ; --- RegisteredApplications (D-22; required for Win 10/11 Default Apps UI) ---
  WriteRegStr HKLM "Software\RegisteredApplications" "${APPNAME}" "Software\${APPNAME}\Capabilities"

  ; --- Notify shell (D-25; SHCNE_ASSOCCHANGED=0x08000000, SHCNF_IDLIST=0x0000) ---
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0x0000, p 0, p 0)'
SectionEnd

; --- Section: Desktop shortcut ---
Section "Desktop shortcut" SecDesktop
  CreateShortCut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\Picocrypt-NG.exe"
SectionEnd

; --- Section: Start Menu folder ---
Section "Start Menu folder" SecStartMenu
  CreateDirectory "$SMPROGRAMS\${APPNAME}"
  CreateShortCut  "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk"  "$INSTDIR\Picocrypt-NG.exe"
  CreateShortCut  "$SMPROGRAMS\${APPNAME}\Uninstall.lnk"   "$INSTDIR\Uninstall.exe"
SectionEnd

; --- LangString descriptions (Pitfall 8 — MUST come AFTER MUI_LANGUAGE and AFTER all sections) ---
LangString DESC_SecAssoc     ${LANG_ENGLISH} "Make Picocrypt-NG the default handler for .pcv files (Open With + Default Apps integration)."
LangString DESC_SecDesktop   ${LANG_ENGLISH} "Add a Desktop shortcut for Picocrypt-NG."
LangString DESC_SecStartMenu ${LANG_ENGLISH} "Create a Start Menu folder with Picocrypt-NG and its uninstaller."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecAssoc}     $(DESC_SecAssoc)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop}   $(DESC_SecDesktop)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenu} $(DESC_SecStartMenu)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; --- Section: Uninstall (D-27 hybrid cleanup, D-26 SHChangeNotify, D-28 RMDir-if-empty) ---
!ifndef IMPORT_UNINST
Section "Uninstall"
  ; --- Hybrid cleanup — only our keys; preserve other apps' OpenWithProgids (D-27) ---
  DeleteRegKey   HKLM "Software\Classes\${PROGID}"
  DeleteRegValue HKLM "Software\Classes\.pcv\OpenWithProgids" "${PROGID}"

  ; --- Conditional reset of .pcv default if it's still us (D-27) ---
  ReadRegStr $0 HKLM "Software\Classes\.pcv" ""
  ${If} $0 == "${PROGID}"
    DeleteRegValue HKLM "Software\Classes\.pcv" ""
    DeleteRegValue HKLM "Software\Classes\.pcv" "ContentType"
    DeleteRegValue HKLM "Software\Classes\.pcv" "PerceivedType"
    DeleteRegKey /ifempty HKLM "Software\Classes\.pcv\OpenWithProgids"
    DeleteRegKey /ifempty HKLM "Software\Classes\.pcv"
  ${EndIf}

  ; --- App namespace + RegisteredApplications + ARP (D-27) ---
  DeleteRegValue HKLM "Software\RegisteredApplications" "${APPNAME}"
  DeleteRegKey   HKLM "Software\${APPNAME}"
  DeleteRegKey   HKLM "${ARP}"

  ; --- Files (D-28) ---
  Delete "$INSTDIR\Picocrypt-NG.exe"
  Delete "$INSTDIR\Picocrypt-NG-cli.exe"
  Delete "$INSTDIR\Picocrypt-NG-portable.exe"  ; orphan from pre-fix upgrade bug (#163)
  Delete "$INSTDIR\pcv-icon.ico"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir  "$INSTDIR"

  ; --- Shortcuts (D-28) ---
  Delete "$DESKTOP\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}\Uninstall.lnk"
  RMDir  "$SMPROGRAMS\${APPNAME}"

  ; --- Notify shell (D-26) ---
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0x0000, p 0, p 0)'
SectionEnd
!endif
