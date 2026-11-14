import hashlib
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.output = self.root / "output"

    def write(self, name, text="test content"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def versions(self, version):
        for name in ("Cargo.toml", "desktop/src-tauri/Cargo.toml"):
            self.write(name, f'[package]\nversion = "{version}"\n')
        for name in ("desktop/package.json", "desktop/src-tauri/tauri.conf.json"):
            self.write(name, json.dumps({"version": version}))
        self.write(
            "Cargo.lock", f'[[package]]\nname = "arraysslvpn"\nversion = "{version}"\n'
        )
        self.write(
            "desktop/src-tauri/Cargo.lock",
            f'[[package]]\nname = "arraysslvpn"\nversion = "{version}"\n[[package]]\nname = "arraysslvpn-desktop"\nversion = "{version}"\n',
        )

    def test_semver_tags_and_prerelease_detection(self):
        self.assertEqual(release.tag_version("v1.2.3"), ("1.2.3", False))
        self.assertEqual(
            release.tag_version("v1.2.3-rc.1+build.5"), ("1.2.3-rc.1+build.5", True)
        )
        for tag in (
            "main",
            "1.2.3",
            "v1.2",
            "v01.2.3",
            "v1.2.3-01",
            "v1.2.3; echo bad",
            "v1.2.3\n",
        ):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.tag_version(tag)

    def test_version_validation_is_read_only_and_rejects_manifest_and_lock_drift(self):
        self.versions("1.2.3")
        before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(
            release.validate_versions(self.root, "v1.2.3"), ("1.2.3", False)
        )
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.write("desktop/package.json", '{"version":"1.2.4"}')
        with self.assertRaisesRegex(ValueError, "desktop/package.json"):
            release.validate_versions(self.root, "v1.2.3")
        self.versions("1.2.3")
        self.write(
            "Cargo.lock", '[[package]]\nname = "arraysslvpn"\nversion = "1.0.0"\n'
        )
        with self.assertRaisesRegex(ValueError, "Cargo.lock"):
            release.validate_versions(self.root, "v1.2.3")

    def test_windows_archive_requires_and_includes_wintun_and_license(self):
        target = "x86_64-pc-windows-msvc"
        self.write(f"target/{target}/release/arraysslvpn.exe")
        for name in ("README.md", "LICENSE", "NOTICE", "config.example.toml"):
            self.write(name)
        with self.assertRaisesRegex(ValueError, "wintun.dll"):
            release.package_cli(self.root, self.output, "1.2.3", target)
        for name in ("wintun.dll", "WINTUN-LICENSE.txt"):
            self.write(f"desktop/src-tauri/resources/{name}")
        archive = release.package_cli(self.root, self.output, "1.2.3", target)
        with zipfile.ZipFile(archive) as package:
            self.assertEqual(
                {Path(name).name for name in package.namelist()},
                {
                    "arraysslvpn.exe",
                    "wintun.dll",
                    "WINTUN-LICENSE.txt",
                    "README.md",
                    "LICENSE",
                    "NOTICE",
                    "config.example.toml",
                },
            )

    def test_unix_archive_preserves_executable_mode(self):
        target = "aarch64-apple-darwin"
        self.write(f"target/{target}/release/arraysslvpn")
        for name in ("README.md", "LICENSE", "NOTICE", "config.example.toml"):
            self.write(name)
        archive = release.package_cli(self.root, self.output, "1.2.3", target)
        with tarfile.open(archive) as package:
            members = {
                Path(member.name).name: member for member in package.getmembers()
            }
            self.assertEqual(members["arraysslvpn"].mode, 0o755)
            self.assertEqual(members["LICENSE"].mode, 0o644)

    def test_desktop_collection_rejects_missing_or_ambiguous_installers(self):
        target = "x86_64-unknown-linux-gnu"
        bundle = f"desktop/src-tauri/target/{target}/release/bundle"
        with self.assertRaises(ValueError):
            release.collect_desktop(self.root, self.output, "1.2.3", target)
        self.write(f"{bundle}/deb/Array Connect.deb", "deb")
        self.write(f"{bundle}/appimage/Array Connect.AppImage", "appimage")
        release.collect_desktop(self.root, self.output, "1.2.3", target)
        self.assertEqual(
            {p.name for p in self.output.iterdir()},
            set(release.desktop_names("1.2.3", target)),
        )
        self.write(f"{bundle}/deb/old-build.deb")
        with self.assertRaisesRegex(ValueError, "found 2"):
            release.collect_desktop(self.root, self.output, "1.2.3", target)

    def test_checksums_require_both_products_and_all_platforms(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            release.write_checksums(self.output, "1.2.3")
        names = []
        for target in release.TARGETS:
            names += [
                release.cli_name("1.2.3", target),
                *release.desktop_names("1.2.3", target),
            ]
        for name in names:
            (self.output / name).write_bytes(name.encode())
        release.write_checksums(self.output, "1.2.3")
        sums = (self.output / "SHA256SUMS").read_text(encoding="utf-8")
        for name in names:
            self.assertIn(
                f"{hashlib.sha256(name.encode()).hexdigest()}  {name}\n", sums
            )
        release.write_checksums(self.output, "1.2.3")
        self.assertEqual(sums, (self.output / "SHA256SUMS").read_text(encoding="utf-8"))
        (self.output / "unexpected.log").write_text("do not publish")
        with self.assertRaisesRegex(ValueError, "unexpected.log"):
            release.write_checksums(self.output, "1.2.3")


if __name__ == "__main__":
    unittest.main()
