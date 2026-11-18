#!/usr/bin/env bash
set -euo pipefail

app=$1
helper="$app/Contents/MacOS/array-connect-network"
plist="$app/Contents/Library/LaunchDaemons/com.taurusxin.arrayconnect.network.plist"
[[ -x "$helper" ]]
plutil -lint "$plist"
[[ $(plutil -extract BundleProgram raw -o - "$plist") == "Contents/MacOS/array-connect-network" ]]
[[ $(plutil -extract Label raw -o - "$plist") == "com.taurusxin.arrayconnect.network" ]]
codesign --verify --deep --strict "$app"

app_signature=$(codesign -dv --verbose=4 "$app" 2>&1)
helper_signature=$(codesign -dv --verbose=4 "$helper" 2>&1)
grep -Fxq 'Identifier=com.taurusxin.arrayconnect' <<<"$app_signature"
grep -Fxq 'Identifier=com.taurusxin.arrayconnect.network' <<<"$helper_signature"
app_team=$(sed -n 's/^TeamIdentifier=//p' <<<"$app_signature")
helper_team=$(sed -n 's/^TeamIdentifier=//p' <<<"$helper_signature")
[[ -n "$app_team" && "$app_team" == "$helper_team" ]]
if [[ "${APPLE_SIGNING_IDENTITY:-}" != "-" ]]; then
  [[ "$app_team" =~ ^[A-Z0-9]{10}$ ]]
  grep -q '^Authority=Developer ID Application:' <<<"$app_signature"
  grep -q '^Authority=Developer ID Application:' <<<"$helper_signature"
fi
