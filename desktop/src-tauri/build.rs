fn main() {
    println!("cargo:rerun-if-changed=windows/app.manifest");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let path = "gen/macos/array-connect-vpnd.sha256";
        println!("cargo:rerun-if-changed={path}");
        let digest = std::fs::read_to_string(path)
            .expect("prepare array-connect-vpnd with node scripts/prepare-macos-service.mjs");
        let digest = digest.trim();
        assert!(digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()));
        println!("cargo:rustc-env=ARRAY_CONNECT_VPND_SHA256={digest}");
    }
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(
        tauri_build::WindowsAttributes::new().app_manifest(include_str!("windows/app.manifest")),
    ))
    .expect("failed to build application resources");
}
