param([Parameter(Mandatory = $true)][string]$Executable)
$ErrorActionPreference = 'Stop'
$resolvedExecutable = (Resolve-Path -LiteralPath $Executable).Path
# Load resources as data; never execute the application or trigger UAC.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ArrayConnectManifestReader {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct ActivationContext {
        public uint Size, Flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string Source;
        public ushort Architecture, Language;
        [MarshalAs(UnmanagedType.LPWStr)] public string AssemblyDirectory;
        public IntPtr ResourceName;
        [MarshalAs(UnmanagedType.LPWStr)] public string ApplicationName;
        public IntPtr Module;
    }
    [DllImport("kernel32.dll", EntryPoint = "CreateActCtxW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr CreateActivationContext(ref ActivationContext context);
    [DllImport("kernel32.dll", EntryPoint = "ReleaseActCtx")]
    public static extern void ReleaseActivationContext(IntPtr context);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibraryEx(string file, IntPtr reserved, uint flags);
    [DllImport("kernel32.dll", EntryPoint = "FindResourceW", SetLastError = true)]
    public static extern IntPtr FindResource(IntPtr module, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LockResource(IntPtr resource);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SizeofResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll")]
    public static extern bool FreeLibrary(IntPtr module);
}
'@
$module = [ArrayConnectManifestReader]::LoadLibraryEx($resolvedExecutable, [IntPtr]::Zero, 0x22)
if ($module -eq [IntPtr]::Zero) { throw 'Cannot load executable resources as data.' }
try {
    $resource = [ArrayConnectManifestReader]::FindResource($module, [IntPtr]1, [IntPtr]24)
    if ($resource -eq [IntPtr]::Zero) { throw 'Embedded application manifest was not found.' }
    $size = [ArrayConnectManifestReader]::SizeofResource($module, $resource)
    $data = [ArrayConnectManifestReader]::LockResource([ArrayConnectManifestReader]::LoadResource($module, $resource))
    if ($size -eq 0 -or $data -eq [IntPtr]::Zero) { throw 'Cannot read application manifest.' }
    $bytes = New-Object byte[] $size
    [Runtime.InteropServices.Marshal]::Copy($data, $bytes, 0, $size)
    $manifest = [xml]([Text.Encoding]::UTF8.GetString($bytes).Trim([char]0).Trim())
    $level = $manifest.SelectSingleNode("//*[local-name()='requestedExecutionLevel']")
    if ($null -eq $level -or $level.level -ne 'requireAdministrator' -or $level.uiAccess -ne 'false') {
        throw 'The EXE does not request requireAdministrator with uiAccess=false.'
    }
    $activation = New-Object ArrayConnectManifestReader+ActivationContext
    $activation.Size = [Runtime.InteropServices.Marshal]::SizeOf($activation)
    $activation.Flags = 8
    $activation.Source = $resolvedExecutable
    $activation.ResourceName = [IntPtr]1
    $context = [ArrayConnectManifestReader]::CreateActivationContext([ref]$activation)
    if ($context -eq [IntPtr]::Zero -or $context -eq [IntPtr](-1)) {
        throw "Windows rejected the activation context: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    [ArrayConnectManifestReader]::ReleaseActivationContext($context)
    Write-Output 'Verified embedded manifest: requireAdministrator, uiAccess=false; Windows activation context is valid.'
} finally { [ArrayConnectManifestReader]::FreeLibrary($module) | Out-Null }
