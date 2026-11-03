//! Dependency-free entrypoint built into the read-only TeX image.
use std::{
    env, fs, io,
    path::Path,
    process::{Command, Stdio},
};
fn directories(source: &Path, target: &Path) -> io::Result<()> {
    for entry in fs::read_dir(source)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::other("linked input refused"));
        }
        if metadata.is_dir() {
            let next = target.join(path.file_name().unwrap());
            fs::create_dir_all(&next)?;
            directories(&path, &next)?;
        }
    }
    Ok(())
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args_os().collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("one TeX source required".into());
    }
    let source = Path::new(&args[1]);
    if source != Path::new("/input/.revayat-main.tex")
        || !source.is_file()
        || source.canonicalize()? != source
    {
        return Err("invalid isolated TeX source".into());
    }
    for path in ["/tmp/tex-home", "/tmp/tex-var", "/tmp/tex-config"] {
        fs::create_dir_all(path)?;
    }
    directories(Path::new("/input"), Path::new("/output"))?;
    for pass in 1..=2 {
        let log = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(format!("/output/console-pass-{pass}.log"))?;
        let errors = log.try_clone()?;
        let status = Command::new("xelatex")
            .args([
                "-no-shell-escape",
                "-interaction=nonstopmode",
                "-halt-on-error",
                "-file-line-error",
                "-jobname=document",
                "-output-directory=/output",
            ])
            .arg(source)
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(errors)
            .status()?;
        if !status.success() {
            return Err(format!("XeLaTeX pass failed: {pass}").into());
        }
    }
    if fs::metadata("/output/document.pdf")?.len() == 0 {
        return Err("empty output".into());
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("revayat-tex-entry: {error}");
        std::process::exit(2);
    }
}
