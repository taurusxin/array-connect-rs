"""Tag validation and release packaging; never changes versions or creates tags."""

import argparse
import hashlib
import json
import os
import re
import shutil
import tarfile
import tomllib
import zipfile
from pathlib import Path

TARGETS = {
    "x86_64-pc-windows-msvc": ("windows-x86_64", ("-setup.exe",)),
    "x86_64-unknown-linux-gnu": ("linux-x86_64", (".deb", ".AppImage")),
    "aarch64-apple-darwin": ("macos-aarch64", (".dmg",)),
    "x86_64-apple-darwin": ("macos-x86_64", (".dmg",)),
}
ROOT = Path(__file__).resolve().parents[2]


def tag_version(tag):
    number = r"(?:0|[1-9][0-9]*)"
    match = re.fullmatch(
        rf"v({number}\.{number}\.{number}(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)",
        tag,
    )
    if not match:
        raise ValueError(
            "Release tag must be vMAJOR.MINOR.PATCH, optionally with a SemVer prerelease/build suffix"
        )
    prerelease = match[2]
    if prerelease and any(
        part.isdigit() and len(part) > 1 and part[0] == "0"
        for part in prerelease.split(".")
    ):
        raise ValueError("Numeric prerelease identifiers must not have leading zeroes")
    return match[1], bool(prerelease)


def validate_versions(root, tag):
    version, prerelease = tag_version(tag)
    versions = {}
    for name in ("Cargo.toml", "desktop/src-tauri/Cargo.toml"):
        versions[name] = tomllib.loads((root / name).read_text(encoding="utf-8"))[
            "package"
        ]["version"]
    for name in ("desktop/package.json", "desktop/src-tauri/tauri.conf.json"):
        versions[name] = json.loads((root / name).read_text(encoding="utf-8"))[
            "version"
        ]
    for name, packages in (
        ("Cargo.lock", ("arraysslvpn",)),
        ("desktop/src-tauri/Cargo.lock", ("arraysslvpn", "arraysslvpn-desktop")),
    ):
        data = tomllib.loads((root / name).read_text(encoding="utf-8"))
        for package in packages:
            entries = [p for p in data["package"] if p["name"] == package]
            if len(entries) != 1:
                raise ValueError(f"Expected one {package} package in {name}")
            versions[f"{name} ({package})"] = entries[0]["version"]
    mismatches = [
        f"{name}: {actual}" for name, actual in versions.items() if actual != version
    ]
    if mismatches:
        raise ValueError(
            f"Tag {tag} does not match package versions; update versions only when preparing a release:\n"
            + "\n".join(mismatches)
        )
    return version, prerelease


def cli_name(version, target):
    platform, _ = TARGETS[target]
    extension = ".zip" if platform.startswith("windows-") else ".tar.gz"
    return f"arraysslvpn-cli-{version}-{platform}{extension}"


def desktop_names(version, target):
    platform, suffixes = TARGETS[target]
    return [f"array-connect-{version}-{platform}{suffix}" for suffix in suffixes]


def package_cli(root, output, version, target):
    windows = target == "x86_64-pc-windows-msvc"
    binary = "array-connect.exe" if windows else "array-connect"
    files = [(root / "target" / target / "release" / binary, binary)]
    files += [
        (root / name, name)
        for name in ("README.md", "LICENSE", "NOTICE", "config.example.toml")
    ]
    if windows:
        resources = root / "desktop/src-tauri/resources"
        files += [
            (resources / name, name) for name in ("wintun.dll", "WINTUN-LICENSE.txt")
        ]
    for source, _ in files:
        if not source.is_file():
            raise ValueError(f"Required CLI release file is missing: {source}")
    output.mkdir(parents=True, exist_ok=True)
    name = cli_name(version, target)
    destination = output / name
    directory = name.removesuffix(".zip" if windows else ".tar.gz")
    if windows:
        with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
            for source, name in files:
                archive.write(source, f"{directory}/{name}")
    else:
        with tarfile.open(destination, "w:gz") as archive:
            for source, name in files:
                info = archive.gettarinfo(str(source), f"{directory}/{name}")
                info.mode = 0o755 if name == binary else 0o644
                with source.open("rb") as stream:
                    archive.addfile(info, stream)
    return destination


def collect_desktop(root, output, version, target):
    bundle = root / "desktop/src-tauri/target" / target / "release/bundle"
    _, suffixes = TARGETS[target]
    patterns = {
        "-setup.exe": "nsis/*.exe",
        ".deb": "deb/*.deb",
        ".AppImage": "appimage/*.AppImage",
        ".dmg": "dmg/*.dmg",
    }
    sources = []
    for suffix in suffixes:
        matches = list(bundle.glob(patterns[suffix]))
        if len(matches) != 1:
            raise ValueError(
                f"Expected exactly one installer matching {bundle / patterns[suffix]}, found {len(matches)}"
            )
        sources.append(matches[0])
    output.mkdir(parents=True, exist_ok=True)
    for source, name in zip(sources, desktop_names(version, target), strict=True):
        shutil.copyfile(source, output / name)


def write_checksums(output, version):
    expected = {cli_name(version, target) for target in TARGETS}
    for target in TARGETS:
        expected.update(desktop_names(version, target))
    actual = {p.name for p in output.iterdir() if p.name != "SHA256SUMS"}
    if actual != expected:
        raise ValueError(
            f"Release asset set is incomplete or unexpected. Missing: {sorted(expected - actual)}; unexpected: {sorted(actual - expected)}"
        )
    lines = []
    for name in sorted(expected):
        with (output / name).open("rb") as stream:
            lines.append(
                f"{hashlib.file_digest(stream, 'sha256').hexdigest()}  {name}\n"
            )
    (output / "SHA256SUMS").write_text("".join(lines), encoding="utf-8", newline="\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "cli", "desktop", "checksums"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--output", type=Path, default=ROOT / "target/release-assets")
    args = parser.parse_args()
    try:
        version, prerelease = tag_version(args.tag)
        if args.command == "validate":
            validate_versions(ROOT, args.tag)
            data = f"version={version}\nprerelease={str(prerelease).lower()}\n"
            print(data, end="")
            if path := os.environ.get("GITHUB_OUTPUT"):
                with open(path, "a", encoding="utf-8", newline="\n") as output:
                    output.write(data)
        elif args.command == "checksums":
            write_checksums(args.output, version)
        else:
            if args.target is None:
                parser.error(
                    "--target is required when packaging CLI or desktop assets"
                )
            if args.command == "cli":
                print(package_cli(ROOT, args.output, version, args.target))
            else:
                collect_desktop(ROOT, args.output, version, args.target)
    except (ValueError, OSError, KeyError) as error:
        parser.exit(1, f"Release validation/packaging failed: {error}\n")


if __name__ == "__main__":
    main()
