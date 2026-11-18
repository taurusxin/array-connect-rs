fn main() -> std::process::ExitCode {
    #[cfg(target_os = "macos")]
    if let Err(error) = arraysslvpn::network::macos_service::run_daemon() {
        eprintln!("Array Connect network service: {error}");
    }
    #[cfg(not(target_os = "macos"))]
    eprintln!("Array Connect network service requires macOS");
    std::process::ExitCode::FAILURE
}
