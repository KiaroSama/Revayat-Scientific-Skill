//! Explicit packaged Unix runtime companion; never an implicit shell wrapper.
fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments == [std::ffi::OsString::from("--version")] {
        println!("revayat-process-owner {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if arguments != [std::ffi::OsString::from("--internal-owner-v1")] {
        eprintln!("revayat-process-owner requires its private runtime protocol");
        std::process::exit(2);
    }
    #[cfg(unix)]
    if revayat_scientific::runtime::owner::cli().is_err() {
        eprintln!("Unix runtime owner protocol or cleanup failed");
        std::process::exit(2);
    }
    #[cfg(not(unix))]
    {
        eprintln!("Unix runtime companion is not used on this platform");
        std::process::exit(2);
    }
}
