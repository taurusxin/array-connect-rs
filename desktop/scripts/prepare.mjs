import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

if (process.platform === "win32") {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const arch = { x64: "amd64", arm64: "arm64", ia32: "x86" }[process.arch];
  if (!arch)
    throw new Error(`Unsupported Windows architecture: ${process.arch}`);
  execFileSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      path.join(root, "scripts/prepare-wintun.ps1"),
      "-Architecture",
      arch,
    ],
    { stdio: "inherit", windowsHide: true },
  );
  const target =
    process.env.CARGO_TARGET_DIR ?? path.join(root, "src-tauri/target");
  for (const profile of ["debug", "release"]) {
    mkdirSync(path.join(target, profile), { recursive: true });
    copyFileSync(
      path.join(root, "src-tauri/resources/wintun.dll"),
      path.join(target, profile, "wintun.dll"),
    );
  }
}
