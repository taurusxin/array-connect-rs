!macro NSIS_HOOK_PREINSTALL
  ; The default running-process check only looks for the new executable.
  ${If} ${FileExists} "$INSTDIR\arraysslvpn-desktop.exe"
    !insertmacro CheckIfAppIsRunning "$INSTDIR\arraysslvpn-desktop.exe" "${PRODUCTNAME}"
  ${EndIf}
!macroend
