param([ValidateSet('amd64','arm64','x86')][string]$Architecture = 'amd64')
$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$archivePath = Join-Path $projectRoot 'target\wintun-0.14.1.zip'
$resourceDirectory = Join-Path $projectRoot 'desktop\src-tauri\resources'
$expectedHash = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
[System.IO.Directory]::CreateDirectory((Split-Path $archivePath)) | Out-Null
if (!(Test-Path -LiteralPath $archivePath)) {
    Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $archivePath -UseBasicParsing
}
$hasher = [System.Security.Cryptography.SHA256]::Create()
$actualHash = [System.BitConverter]::ToString($hasher.ComputeHash([System.IO.File]::ReadAllBytes($archivePath))).Replace('-', '').ToLowerInvariant()
$hasher.Dispose()
if ($actualHash -ne $expectedHash) {
    throw 'Wintun archive SHA-256 mismatch; remove the cached archive and retry.'
}
[System.IO.Directory]::CreateDirectory($resourceDirectory) | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    foreach ($pair in @(@("wintun/bin/$Architecture/wintun.dll", 'wintun.dll'), @('wintun/LICENSE.txt', 'WINTUN-LICENSE.txt'))) {
        $entry = $archive.GetEntry($pair[0])
        if ($null -eq $entry) { throw "Required archive entry not found: $($pair[0])" }
        $inputStream = $entry.Open()
        $outputStream = [System.IO.File]::Create((Join-Path $resourceDirectory $pair[1]))
        try { $inputStream.CopyTo($outputStream) } finally { $inputStream.Dispose(); $outputStream.Dispose() }
    }
} finally { $archive.Dispose() }
Write-Output "Prepared official signed Wintun 0.14.1 ($Architecture), SHA-256 verified."
