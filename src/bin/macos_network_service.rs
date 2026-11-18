fn main() -> std::process::ExitCode {
    #[cfg(target_os = "macos")]
    {
        use arraysslvpn::network::macos_service;
        let args: Vec<_> = std::env::args().skip(1).collect();
        let result = match args.as_slice() {
            [] => macos_service::run_daemon(),
            [operation, hash] if operation == "--install" => macos_service::install_daemon(hash),
            _ => {
                eprintln!("invalid array-connect-vpnd arguments");
                return std::process::ExitCode::FAILURE;
            }
        };
        match result {
            Ok(()) => return std::process::ExitCode::SUCCESS,
            Err(error) => eprintln!("array-connect-vpnd: {error}"),
        }
    }
    #[cfg(not(target_os = "macos"))]
    eprintln!("Array Connect network service requires macOS");
    std::process::ExitCode::FAILURE
}
