#!/usr/bin/env bash
set -euo pipefail

app=$1
desktop=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
helper="$app/Contents/Resources/array-connect-vpnd"
[[ -x "$helper" ]]
[[ $(plutil -extract CFBundleIdentifier raw -o - "$app/Contents/Info.plist") == "com.taurusxin.arrayconnect" ]]
expected=$(cat "$desktop/src-tauri/gen/macos/array-connect-vpnd.sha256")
actual=$(shasum -a 256 "$helper")
[[ "${actual%% *}" == "$expected" ]]
LC_ALL=C grep -aFq "$expected" "$app/Contents/MacOS/array-connect"
plutil -lint "$desktop/../src/network/macos_service/vpnd.plist"
codesign --verify --deep --strict "$app"
codesign --verify --strict -R='=identifier "com.taurusxin.arrayconnect.vpnd"' "$helper"

app_signature=$(codesign -dv --verbose=4 "$app" 2>&1)
helper_signature=$(codesign -dv --verbose=4 "$helper" 2>&1)
grep -Fxq 'Identifier=com.taurusxin.arrayconnect' <<<"$app_signature"
grep -Fxq 'Identifier=com.taurusxin.arrayconnect.vpnd' <<<"$helper_signature"
if [[ "${APPLE_SIGNING_IDENTITY:--}" != "-" ]]; then
  app_team=$(sed -n 's/^TeamIdentifier=//p' <<<"$app_signature")
  helper_team=$(sed -n 's/^TeamIdentifier=//p' <<<"$helper_signature")
  [[ "$app_team" == "$helper_team" ]]
  [[ "$app_team" =~ ^[A-Z0-9]{10}$ ]]
  grep -q '^Authority=Developer ID Application:' <<<"$app_signature"
  grep -q '^Authority=Developer ID Application:' <<<"$helper_signature"
fi
