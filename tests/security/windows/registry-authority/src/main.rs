pub use registry_authority::*;
#[cfg(all(windows, target_arch = "x86_64"))]
mod runner;

fn main() {
    if std::env::args_os()
        .skip(1)
        .eq([std::ffi::OsString::from("--oracle")])
    {
        print!("{}", oracle::generate());
        return;
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    runner::main();
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        eprintln!("registry-authority requires Windows x64; only --oracle is portable");
        std::process::exit(1);
    }
}
