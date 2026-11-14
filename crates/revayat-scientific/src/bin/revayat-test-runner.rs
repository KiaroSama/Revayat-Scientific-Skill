//! Hosted test collector owns its process boundary instead of borrowing the CLI worker's.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = revayat_scientific::migration::execution::cli(&args) {
        eprintln!("test runner failed: {error:#}");
        let code = error
            .downcast_ref::<revayat_scientific::migration::execution::TestExecutionFailure>()
            .and_then(|failure| failure.exit)
            .filter(|exit| (1..=255).contains(exit))
            .unwrap_or(2);
        std::process::exit(code);
    }
}
