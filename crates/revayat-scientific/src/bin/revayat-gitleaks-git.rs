//! Actual Git stream adapter; its enclosing scanner owns the complete child tree.
fn main() {
    match revayat_scientific::ci_tools::gitleaks_git_main() {
        Ok(code) => std::process::exit(code),
        Err(_) => {
            eprintln!("The verified Git child could not confirm completion.");
            std::process::exit(1);
        }
    }
}
