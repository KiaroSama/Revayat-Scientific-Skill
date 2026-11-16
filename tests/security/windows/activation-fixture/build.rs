//! Fixed resource encoding only; never discovers or invokes an external resource compiler.
#[path = "src/resource.rs"]
mod resource;
fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=src/resource.rs");
    if std::env::var("TARGET").as_deref() != Ok("x86_64-pc-windows-msvc") {
        return Ok(());
    }
    let output = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR")
            .ok_or_else(|| std::io::Error::other("fixed fixture OUT_DIR is absent"))?,
    )
    .join("explicit-id2.res");
    let bytes = resource::encode();
    std::fs::write(&output, &bytes)?;
    if std::fs::read(&output)? != bytes {
        return Err(std::io::Error::other(
            "fixed fixture resource readback differs",
        ));
    }
    println!(
        "cargo::rustc-link-arg-bin=startup-explicit-id2={}",
        output.display()
    );
    println!("cargo::rustc-link-arg-bin=startup-explicit-id2=/MANIFEST:NO");
    println!("cargo::rustc-link-arg-bin=startup-explicit-id2=/ALLOWISOLATION:NO");
    Ok(())
}
