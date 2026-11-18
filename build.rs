fn main() {
    #[cfg(feature = "macos-network-service")]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let source = "src/network/macos_service";
        let info = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join(source)
            .join("helper-info.plist");
        println!("cargo:rerun-if-changed={source}");
        cc::Build::new()
            .files([format!("{source}/client.m"), format!("{source}/server.m")])
            .flag("-fobjc-arc")
            .flag("-fblocks")
            .compile("array_connect_macos_network");
        for framework in ["Foundation", "Security", "SystemConfiguration"] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
        println!(
            "cargo:rustc-link-arg-bin=array-connect-vpnd=-Wl,-sectcreate,__TEXT,__info_plist,{}",
            info.display()
        );
    }
}
