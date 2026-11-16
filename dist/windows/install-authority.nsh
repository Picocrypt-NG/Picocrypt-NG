; Per-machine execution targets may only be published below protected local
; directories. All Win32 calls use stock NSIS System; no extra signed component.
!ifndef PCNG_INSTALL_AUTHORITY
!define PCNG_INSTALL_AUTHORITY
!if ${NSIS_PTR_SIZE} != 4
  !error "The installation authority implementation requires the reviewed x86 Unicode NSIS stub."
!endif

Var pcngCreate
Var pcngMake
Var pcngPath
Var pcngResolved
Var pcngRemaining
Var pcngComponent
Var pcngMissing
Var pcngKind
Var pcngOK
Var pcngReason
Var pcngSid
Var pcngTrusted
Var pcngAdminSid
Var pcngSystemSid
Var pcngInstallerSid
Var pcngCreatorSid
Var pcngHandle
Var pcngInfo
Var pcngSD
Var pcngDacl
Var pcngAce
Var pcngIndex
Var pcngCount
Var pcngMask
Var pcngNewSD
Var pcngSA

!macro PCNG_AUTHORITY_FUNCTIONS Prefix
Function ${Prefix}pcng.TrustedSid
  StrCpy $pcngTrusted 0
  System::Call 'advapi32::EqualSid(p $pcngSid, p $pcngAdminSid) i.r9'
  ${If} $9 <> 0
    StrCpy $pcngTrusted 1
  ${EndIf}
  System::Call 'advapi32::EqualSid(p $pcngSid, p $pcngSystemSid) i.r9'
  ${If} $9 <> 0
    StrCpy $pcngTrusted 1
  ${EndIf}
  System::Call 'advapi32::EqualSid(p $pcngSid, p $pcngInstallerSid) i.r9'
  ${If} $9 <> 0
    StrCpy $pcngTrusted 1
  ${EndIf}
FunctionEnd

; pcngKind: 0 = ancestor, 1 = install directory, 2 = existing payload file.
; Reject unsafe allow ACEs conservatively, even if a deny ACE might mask them.
; Unknown/object/callback ACEs are unsupported and fail closed.
Function ${Prefix}pcng.CheckObject
  StrCpy $pcngOK 0
  StrCpy $pcngReason "Setup cannot verify that this path is protected: $pcngPath.$\r$\nChoose Program Files or an administrator-owned directory with standard protected permissions and no reparse points."
  StrCpy $pcngSD 0
  StrCpy $pcngInfo 0
  ; Data/list access makes Windows enforce sharing checks; attributes alone
  ; cannot detect a data writer retained from before an ACL change.
  System::Call 'kernel32::CreateFileW(w "$pcngPath", i 0x20081, i 1, p 0, i 3, i 0x02200000, p 0) p.r0'
  StrCpy $pcngHandle $0
  ${If} $pcngHandle == -1
    Return
  ${EndIf}
  System::Alloc 52
  Pop $pcngInfo
  ${If} $pcngInfo == 0
    Goto object_done
  ${EndIf}
  System::Call 'kernel32::GetFileInformationByHandle(p $pcngHandle, p $pcngInfo) i.r0'
  ${If} $0 == 0
    Goto object_done
  ${EndIf}
  System::Call '*$pcngInfo(i.r0, &v36, i.r1)'
  IntOp $2 $0 & 0x400
  ${If} $2 <> 0
    Goto object_done
  ${EndIf}
  IntOp $2 $0 & 0x10
  ${If} $pcngKind == 2
    ${If} $2 <> 0
      Goto object_done
    ${EndIf}
    ${If} $1 <> 1
      Goto object_done
    ${EndIf}
  ${ElseIf} $2 == 0
    Goto object_done
  ${EndIf}
  System::Call 'kernel32::GetFinalPathNameByHandleW(p $pcngHandle, w.r0, i ${NSIS_MAX_STRLEN}, i 0) i.r1'
  ${If} $1 == 0
  ${OrIf} $1 >= ${NSIS_MAX_STRLEN}
    Goto object_done
  ${EndIf}
  StrCpy $1 $0 4
  ${If} $1 != "\\?\"
    Goto object_done
  ${EndIf}
  StrCpy $pcngResolved $0 "" 4
  System::Call 'advapi32::GetSecurityInfo(p $pcngHandle, i 1, i 5, *p.r0, p 0, *p.r1, p 0, *p.r2) i.r3'
  StrCpy $pcngSid $0
  StrCpy $pcngDacl $1
  StrCpy $pcngSD $2
  ${If} $3 <> 0
  ${OrIf} $pcngSid == 0
  ${OrIf} $pcngDacl == 0
    Goto object_done
  ${EndIf}
  Call ${Prefix}pcng.TrustedSid
  ${If} $pcngTrusted == 0
    Goto object_done
  ${EndIf}
  System::Call 'advapi32::IsValidAcl(p $pcngDacl) i.r0'
  ${If} $0 == 0
    Goto object_done
  ${EndIf}
  System::Call 'advapi32::GetAclInformation(p $pcngDacl, p $pcngInfo, i 12, i 2) i.r0'
  ${If} $0 == 0
    Goto object_done
  ${EndIf}
  System::Call '*$pcngInfo(i.r0)'
  StrCpy $pcngCount $0
  StrCpy $pcngIndex 0
  ; Ancestors may allow creating a subdirectory (the normal drive-root ACL),
  ; but never rebinding a protected child or modifying the ancestor itself.
  StrCpy $pcngMask 0x500D0152
  ${If} $pcngKind <> 0
    StrCpy $pcngMask 0x500D0156
  ${EndIf}
  ace_loop:
    ${If} $pcngIndex >= $pcngCount
      StrCpy $pcngOK 1
      Goto object_done
    ${EndIf}
    System::Call 'advapi32::GetAce(p $pcngDacl, i $pcngIndex, *p.r0) i.r1'
    ${If} $1 == 0
      Goto object_done
    ${EndIf}
    StrCpy $pcngAce $0
    System::Call '*$pcngAce(&i1.r0, &i1.r1, &i2.r2, i.r3)'
    ${If} $0 == 1
      Goto ace_next
    ${EndIf}
    ${If} $0 <> 0
    ${OrIf} $2 < 16
      Goto object_done
    ${EndIf}
    IntOp $0 $1 & 0xE0
    ${If} $0 <> 0
      Goto object_done
    ${EndIf}
    IntOp $0 $1 & 0x08
    ${If} $0 <> 0
    ${AndIf} $pcngKind <> 1
      Goto ace_next
    ${EndIf}
    IntOp $3 $3 & $pcngMask
    ${If} $3 == 0
      Goto ace_next
    ${EndIf}
    IntOp $pcngSid $pcngAce + 8
    System::Call 'advapi32::IsValidSid(p $pcngSid) i.r3'
    ${If} $3 == 0
      Goto object_done
    ${EndIf}
    ; CREATOR OWNER is safe only as an inheritance-only trustee: the creation
    ; token's default owner was independently checked before this traversal.
    ${If} $0 <> 0
      System::Call 'advapi32::EqualSid(p $pcngSid, p $pcngCreatorSid) i.r3'
      ${If} $3 <> 0
        Goto ace_next
      ${EndIf}
    ${EndIf}
    Call ${Prefix}pcng.TrustedSid
    ${If} $pcngTrusted == 0
      Goto object_done
    ${EndIf}
    ace_next:
      IntOp $pcngIndex $pcngIndex + 1
      Goto ace_loop
  object_done:
    ${If} $pcngSD <> 0
      System::Call 'kernel32::LocalFree(p $pcngSD)'
    ${EndIf}
    ${If} $pcngInfo <> 0
      System::Free $pcngInfo
    ${EndIf}
    System::Call 'kernel32::CloseHandle(p $pcngHandle)'
FunctionEnd

Function ${Prefix}pcng.WalkInstallPath
  StrCpy $pcngRemaining $INSTDIR "" 3
  StrCpy $pcngPath $INSTDIR 3
  StrCpy $pcngMissing 0
  StrCpy $pcngKind 0
  Call ${Prefix}pcng.CheckObject
  ${If} $pcngOK == 0
    Return
  ${EndIf}
  ; A drive-root alias (including SUBST) must not rebind in another user's
  ; DOS-device namespace. Handle resolution must yield this actual drive root.
  ${If} $pcngResolved != $pcngPath
    StrCpy $pcngOK 0
    Return
  ${EndIf}
  component_loop:
    StrCpy $pcngComponent ""
    character_loop:
      StrCpy $0 $pcngRemaining 1
      StrCpy $pcngRemaining $pcngRemaining "" 1
      ${If} $0 == "\"
      ${OrIf} $0 == ""
        Goto component_ready
      ${EndIf}
      ${If} $0 == ":"
      ${OrIf} $0 == "*"
      ${OrIf} $0 == "?"
      ${OrIf} $0 == '"'
      ${OrIf} $0 == "<"
      ${OrIf} $0 == ">"
      ${OrIf} $0 == "|"
      ${OrIf} $0 == "/"
        StrCpy $pcngOK 0
        Return
      ${EndIf}
      StrCpy $pcngComponent "$pcngComponent$0"
      Goto character_loop
    component_ready:
      StrCpy $0 $pcngComponent 1 -1
      ${If} $pcngComponent == ""
      ${OrIf} $0 == "."
      ${OrIf} $0 == " "
        StrCpy $pcngOK 0
        Return
      ${EndIf}
      StrLen $0 $pcngPath
      ${If} $0 == 3
        StrCpy $pcngPath "$pcngPath$pcngComponent"
      ${Else}
        StrCpy $pcngPath "$pcngPath\$pcngComponent"
      ${EndIf}
      StrCpy $pcngKind 0
      ${If} $pcngRemaining == ""
        StrCpy $pcngKind 1
      ${EndIf}
      System::Call 'kernel32::GetFileAttributesW(w "$pcngPath") i.r0 ?e'
      Pop $1
      ${If} $0 == -1
        ${If} $pcngCreate <> 1
          StrCpy $pcngOK 0
          Return
        ${EndIf}
        ${If} $1 <> 2
        ${AndIf} $1 <> 3
          StrCpy $pcngOK 0
          Return
        ${EndIf}
        StrCpy $pcngMissing 1
        ${If} $pcngMake == 1
          System::Call 'kernel32::CreateDirectoryW(w "$pcngPath", p $pcngSA) i.r0'
          ${If} $0 == 0
            StrCpy $pcngOK 0
            Return
          ${EndIf}
          StrCpy $pcngMissing 0
        ${EndIf}
      ${EndIf}
      ${If} $pcngMissing == 0
        Call ${Prefix}pcng.CheckObject
        ${If} $pcngOK == 0
          Return
        ${EndIf}
        StrCpy $pcngPath $pcngResolved
      ${EndIf}
      ${If} $pcngRemaining != ""
        Goto component_loop
      ${EndIf}
      StrCpy $INSTDIR $pcngPath
      StrCpy $pcngOK 1
FunctionEnd

Function ${Prefix}pcng.RequireProtectedInstallDir
  StrCpy $pcngReason "Setup requires a protected directory on a local fixed drive. Choose Program Files or an administrator-owned directory without user write permissions or reparse points."
  StrCpy $pcngAdminSid 0
  StrCpy $pcngSystemSid 0
  StrCpy $pcngInstallerSid 0
  StrCpy $pcngCreatorSid 0
  StrCpy $pcngNewSD 0
  StrCpy $pcngSA 0
  StrCpy $0 $INSTDIR 2 1
  ${If} $0 != ":\"
    Goto authority_refused
  ${EndIf}
  System::Call 'kernel32::GetFullPathNameW(w "$INSTDIR", i ${NSIS_MAX_STRLEN}, w.r0, p 0) i.r1'
  ${If} $1 <= 3
  ${OrIf} $1 >= ${NSIS_MAX_STRLEN}
    Goto authority_refused
  ${EndIf}
  StrCpy $INSTDIR $0
  StrCpy $0 $INSTDIR 3
  System::Call 'kernel32::GetDriveTypeW(w r0) i.r1'
  ${If} $1 <> 3
    Goto authority_refused
  ${EndIf}
  System::Call 'kernel32::GetVolumeInformationW(w r0, p 0, i 0, p 0, p 0, *i.r1, p 0, i 0) i.r2'
  IntOp $1 $1 & 8
  ${If} $2 == 0
  ${OrIf} $1 == 0
    Goto authority_refused
  ${EndIf}
  System::Call 'advapi32::ConvertStringSidToSidW(w "S-1-5-32-544", *p.r0) i.r1'
  StrCpy $pcngAdminSid $0
  ${If} $1 == 0
    Goto authority_refused
  ${EndIf}
  System::Call 'advapi32::ConvertStringSidToSidW(w "S-1-5-18", *p.r0) i.r1'
  StrCpy $pcngSystemSid $0
  ${If} $1 == 0
    Goto authority_refused
  ${EndIf}
  System::Call 'advapi32::ConvertStringSidToSidW(w "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", *p.r0) i.r1'
  StrCpy $pcngInstallerSid $0
  ${If} $1 == 0
    Goto authority_refused
  ${EndIf}
  System::Call 'advapi32::ConvertStringSidToSidW(w "S-1-3-0", *p.r0) i.r1'
  StrCpy $pcngCreatorSid $0
  ${If} $1 == 0
    Goto authority_refused
  ${EndIf}
  ; CREATOR OWNER inheritance is evaluated against the actual token owner,
  ; never against the elevated user's account name or current group list.
  System::Call 'kernel32::GetCurrentProcess() p.r0'
  System::Call 'advapi32::OpenProcessToken(p r0, i 8, *p.r1) i.r2'
  ${If} $2 == 0
    Goto authority_refused
  ${EndIf}
  StrCpy $pcngHandle $1
  System::Alloc 256
  Pop $pcngInfo
  ${If} $pcngInfo == 0
    System::Call 'kernel32::CloseHandle(p $pcngHandle)'
    Goto authority_refused
  ${EndIf}
  System::Call 'advapi32::GetTokenInformation(p $pcngHandle, i 4, p $pcngInfo, i 256, *i.r0) i.r1'
  StrCpy $2 $1
  ${If} $2 <> 0
    System::Call '*$pcngInfo(p.r0)'
    StrCpy $pcngSid $0
    Call ${Prefix}pcng.TrustedSid
  ${EndIf}
  System::Free $pcngInfo
  System::Call 'kernel32::CloseHandle(p $pcngHandle)'
  ${If} $2 == 0
    Goto authority_refused
  ${EndIf}
  ${If} $pcngTrusted == 0
    Goto authority_refused
  ${EndIf}
  StrCpy $pcngMake 0
  Call ${Prefix}pcng.WalkInstallPath
  ${If} $pcngOK == 0
    Goto authority_refused
  ${EndIf}
  ; Inspect every existing destination, including the orphan deleted on upgrade.
  Push "Picocrypt-NG.exe"
  Push "Picocrypt-NG-cli.exe"
  Push "Uninstall.exe"
  Push "pcv-icon.ico"
  Push "Picocrypt-NG-portable.exe"
  StrCpy $pcngCount 5
  payload_loop:
    Pop $0
    StrCpy $pcngPath "$INSTDIR\$0"
    Push $pcngCount
    System::Call 'kernel32::GetFileAttributesW(w "$pcngPath") i.r0 ?e'
    Pop $1
    ${If} $0 == -1
      StrCpy $pcngOK 0
      ${If} $1 == 2
      ${OrIf} $1 == 3
        StrCpy $pcngOK 1
      ${EndIf}
    ${Else}
      StrCpy $pcngKind 2
      Call ${Prefix}pcng.CheckObject
    ${EndIf}
    Pop $pcngCount
    ${If} $pcngOK == 0
      ; Balance the pending filename stack before leaving the function.
      payload_discard:
        IntOp $pcngCount $pcngCount - 1
        ${If} $pcngCount > 0
          Pop $0
          Goto payload_discard
        ${EndIf}
      Goto authority_refused
    ${EndIf}
    IntOp $pcngCount $pcngCount - 1
    ${If} $pcngCount > 0
      Goto payload_loop
    ${EndIf}
  ${If} $pcngCreate == 1
    ; Only newly created directories receive this ACL. Existing locations are
    ; checked, never repaired, and no recursive ACL operation is performed.
    System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)", i 1, *p.r0, p 0) i.r1'
    StrCpy $pcngNewSD $0
    ${If} $1 == 0
      Goto authority_refused
    ${EndIf}
    System::Call '*(i 12, p $pcngNewSD, i 0) p.r0'
    StrCpy $pcngSA $0
    StrCpy $pcngMake 1
    Call ${Prefix}pcng.WalkInstallPath
    ${If} $pcngOK == 0
      Goto authority_refused
    ${EndIf}
  ${EndIf}
  StrCpy $pcngOK 1
  Goto authority_cleanup
  authority_refused:
    StrCpy $pcngOK 0
  authority_cleanup:
    System::Call 'kernel32::LocalFree(p $pcngAdminSid)'
    System::Call 'kernel32::LocalFree(p $pcngSystemSid)'
    System::Call 'kernel32::LocalFree(p $pcngInstallerSid)'
    System::Call 'kernel32::LocalFree(p $pcngCreatorSid)'
    System::Call 'kernel32::LocalFree(p $pcngNewSD)'
    ${If} $pcngSA <> 0
      System::Free $pcngSA
    ${EndIf}
    ${If} $pcngOK == 0
      SetErrorLevel 5
      MessageBox MB_OK|MB_ICONSTOP "$pcngReason" /SD IDOK
      Abort "$pcngReason"
    ${EndIf}
FunctionEnd
!macroend

!insertmacro PCNG_AUTHORITY_FUNCTIONS ""
!ifndef IMPORT_UNINST
!insertmacro PCNG_AUTHORITY_FUNCTIONS "un."
!endif
!endif
