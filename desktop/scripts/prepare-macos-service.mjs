import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
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
const binary = "array-connect-vpnd";
const staged = path.join(staging, binary);
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
  return path.join(cargoOutput, arch, "release", binary);
});
if (sources.length > 1) {
  execFileSync("lipo", ["-create", ...sources, "-output", staged], {
    stdio: "inherit",
  });
} else {
  copyFileSync(sources[0], staged);
}
chmodSync(staged, 0o755);
const identity = process.env.APPLE_SIGNING_IDENTITY || "-";
execFileSync(
  "/usr/bin/codesign",
  [
    "--force",
    "--sign",
    identity,
    "--options",
    "runtime",
    identity === "-" ? "--timestamp=none" : "--timestamp",
    "--identifier",
    "com.taurusxin.arrayconnect.vpnd",
    staged,
  ],
  { stdio: "inherit" },
);
const digest = createHash("sha256").update(readFileSync(staged)).digest("hex");
writeFileSync(path.join(staging, `${binary}.sha256`), `${digest}\n`);
