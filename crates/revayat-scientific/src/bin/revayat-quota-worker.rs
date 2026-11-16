//! Fixed native Windows quota worker; no arbitrary executable or host-controller role.
fn main() {
    #[cfg(all(windows, target_arch = "x86_64"))]
    let status = revayat_scientific::windows_security::native::quota_worker_main();
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    let status = {
        eprintln!("Native quota controls require Windows x64.");
        1
    };
    std::process::exit(status);
}
