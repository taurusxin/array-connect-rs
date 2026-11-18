import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const desktop = fileURLToPath(new URL("../", import.meta.url));
const root = path.resolve(desktop, "..");
const target =
  process.argv[2] ??
  process.env.TAURI_ENV_TARGET_TRIPLE ??
  { arm64: "aarch64-apple-darwin", x64: "x86_64-apple-darwin" }[process.arch];
const macTargets = ["aarch64-apple-darwin", "x86_64-apple-darwin"];
if (
  process.platform !== "darwin" ||
  ![...macTargets, "universal-apple-darwin"].includes(target)
) {
  throw new Error(
    "The network helper requires a macOS target and the Apple SDK.",
  );
}
const cargoOutput = path.join(root, "target", "macos-network-service");
const staging = path.join(desktop, "src-tauri", "gen", "macos");
const binary = "array-connect-network";
const staged = path.join(staging, `${binary}-${target}`);
mkdirSync(staging, { recursive: true });
const sources = (
  target === "universal-apple-darwin" ? macTargets : [target]
).map((arch) => {
  execFileSync(
    "cargo",
    [
      "build",
      "--locked",
      "--release",
      "--no-default-features",
      "--features",
      "macos-network-service",
      "--bin",
      binary,
      "--target",
      arch,
      "--target-dir",
      cargoOutput,
    ],
    { cwd: root, stdio: "inherit" },
  );
  const output = path.join(staging, `${binary}-${arch}`);
  copyFileSync(path.join(cargoOutput, arch, "release", binary), output);
  chmodSync(output, 0o755);
  return output;
});
if (sources.length > 1) {
  execFileSync("lipo", ["-create", ...sources, "-output", staged], {
    stdio: "inherit",
  });
  chmodSync(staged, 0o755);
}
