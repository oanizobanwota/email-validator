; Custom NSIS hooks for electron-builder (picked up automatically from build/installer.nsh).
;
; Why: the stock installer upgrades by running the PREVIOUS version's uninstaller and, if that
; exe does not exit cleanly, shows "Email Validator cannot be closed" and gives up. A damaged
; old uninstaller ("installer integrity check has failed") therefore blocked every upgrade and
; uninstall. These hooks make an upgrade independent of the old uninstaller.

; Defining customCheckAppRunning stops electron-builder from including these itself.
!include "getProcessInfo.nsh"
Var pid

!macro customCheckAppRunning
  ; Stock behaviour first: find a running copy of the app and ask to close it.
  !insertmacro _CHECK_APP_RUNNING
  ; Belt and braces: force-kill anything still holding the files (a hung instance).
  nsExec::Exec `"$SYSDIR\cmd.exe" /c taskkill /f /t /im "${APP_EXECUTABLE_FILENAME}"`
  Pop $0

  !ifndef BUILD_UNINSTALLER
    ; Retire the previous version ourselves (installer only).
    Push $R0
    Push $R1
    Push $R2
    Push $R3

    ClearErrors
    ReadRegStr $R1 SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY}" UninstallString
    !ifdef UNINSTALL_REGISTRY_KEY_2
      ${If} $R1 == ""
        ReadRegStr $R1 SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY_2}" UninstallString
      ${EndIf}
    !endif
    ${If} $R1 != ""
      !insertmacro GetInQuotes $R2 "$R1"
      ReadRegStr $R3 SHELL_CONTEXT "${INSTALL_REGISTRY_KEY}" InstallLocation
      ${If} $R3 == ""
        ${StdUtils.GetParentPath} $R3 "$R2"
      ${EndIf}

      DetailPrint "Removing previous version from $R3"
      StrCpy $R0 1
      ${If} ${FileExists} "$R2"
        ; Run a copy of it silently, keeping user data and skipping its self-integrity check.
        CopyFiles /SILENT "$R2" "$PLUGINSDIR\previous-uninstaller.exe"
        ClearErrors
        ExecWait '"$PLUGINSDIR\previous-uninstaller.exe" /S /NCRC /KEEP_APP_DATA /currentuser --updated _?=$R3' $R0
        ${If} ${Errors}
          StrCpy $R0 1
        ${EndIf}
      ${EndIf}

      ${If} $R0 != 0
        DetailPrint "Previous uninstaller unusable (code $R0); cleaning up directly"
        ; Only delete a folder that is really ours: named after the product and holding the app exe.
        ${StdUtils.GetFileNamePart} $R1 "$R3"
        ${If} $R1 == "${PRODUCT_FILENAME}"
        ${AndIf} ${FileExists} "$R3\${APP_EXECUTABLE_FILENAME}"
          RMDir /r "$R3"
        ${EndIf}
      ${EndIf}

      ; Either way the old registration goes, or the stock flow retries the broken exe.
      DeleteRegKey SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY}"
      !ifdef UNINSTALL_REGISTRY_KEY_2
        DeleteRegKey SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY_2}"
      !endif
      DeleteRegKey SHELL_CONTEXT "${INSTALL_REGISTRY_KEY}"
      ClearErrors
    ${EndIf}

    Pop $R3
    Pop $R2
    Pop $R1
    Pop $R0
  !endif
!macroend
