//! Dependency-free entrypoint built into the read-only TeX image.
use std::{
    env, fs, io,
    path::Path,
    process::{Command, Stdio},
};
const OUTPUT_BYTES: u64 = 268_435_456;
const OUTPUT_CHUNK: u64 = 1024 * 1024;
const OUTPUT_NAMES: &[&str] = &[
    "document.pdf",
    "console-pass-1.log",
    "console-pass-2.log",
    "sandbox-verified.json",
    "probe.txt",
    "public-one.txt",
    "public-two.txt",
];

fn read_output(args: &[std::ffi::OsString]) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Seek, SeekFrom, Write};
    if args.len() != 3 {
        return Err("output name, offset and length required".into());
    }
    let name = args[0].to_str().ok_or("output name is not UTF-8")?;
    if !OUTPUT_NAMES.contains(&name) {
        return Err("invalid output name".into());
    }
    let offset: u64 = args[1].to_str().ok_or("invalid output offset")?.parse()?;
    let count: u64 = args[2].to_str().ok_or("invalid output length")?.parse()?;
    let path = Path::new("/output").join(name);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file()
        || path.canonicalize()? != path
        || metadata.len() > OUTPUT_BYTES
        || count == 0
        || count > OUTPUT_CHUNK
        || offset
            .checked_add(count)
            .is_none_or(|end| end > metadata.len())
    {
        return Err("unsafe bounded output read".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err("linked output artifact refused".into());
        }
    }
    let mut file = fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; count as usize];
    file.read_exact(&mut bytes)?;
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0] as usize;
        let b = chunk.get(1).copied().unwrap_or(0) as usize;
        let c = chunk.get(2).copied().unwrap_or(0) as usize;
        encoded.extend([
            ALPHABET[a >> 2],
            ALPHABET[((a & 3) << 4) | (b >> 4)],
            if chunk.len() > 1 {
                ALPHABET[((b & 15) << 2) | (c >> 6)]
            } else {
                b'='
            },
            if chunk.len() > 2 {
                ALPHABET[c & 63]
            } else {
                b'='
            },
        ]);
    }
    io::stdout().lock().write_all(&encoded)?;
    Ok(())
}

fn output_manifest(names: &[std::ffi::OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if names.len() > 512 {
        return Err("output inventory exceeds bound".into());
    }
    let mut files = Vec::new();
    let mut total = 0u64;
    for name in names {
        let name = name.to_str().ok_or("output name is not UTF-8")?;
        if !OUTPUT_NAMES.contains(&name) {
            return Err("invalid output name".into());
        }
        let path = Path::new("/output").join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file() || path.canonicalize()? != path {
            return Err("nonregular output artifact refused".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err("linked output artifact refused".into());
            }
        }
        total = total
            .checked_add(metadata.len())
            .ok_or("output size overflow")?;
        if total > OUTPUT_BYTES {
            return Err("output aggregate delivery budget exceeded".into());
        }
        let digest = Command::new("/usr/bin/sha256sum")
            .arg("--")
            .arg(&path)
            .stdin(Stdio::null())
            .output()?;
        let digest_text = std::str::from_utf8(&digest.stdout)?;
        let sha256 = digest_text
            .split_whitespace()
            .next()
            .ok_or("missing output digest")?;
        if !digest.status.success()
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("invalid output digest".into());
        }
        files.push(format!(
            "{{\"name\":\"{name}\",\"size\":{},\"sha256\":\"{sha256}\"}}",
            metadata.len()
        ));
    }
    println!("[{}]", files.join(","));
    Ok(())
}
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
    if args.get(1).is_some_and(|arg| arg == "--hold") && args.len() == 2 {
        // The synchronous exec owns compilation and its exit status. PID 1 only
        // preserves the tmpfs until the receipt owner has copied bounded results.
        loop {
            std::thread::park();
        }
    }
    if args.get(1).is_some_and(|arg| arg == "--output-manifest") {
        return output_manifest(&args[2..]);
    }
    if args.get(1).is_some_and(|arg| arg == "--read-output") {
        return read_output(&args[2..]);
    }
    if args.len() == 3 && args[1] == "--engine-info" && args[2] == "weasyprint" {
        if !Command::new("/usr/bin/weasyprint")
            .arg("--version")
            .stdin(Stdio::null())
            .status()?
            .success()
        {
            return Err("WeasyPrint readiness failed".into());
        }
        return Ok(());
    }
    if args.len() == 2 && args[1] == "--weasyprint" {
        let source = Path::new("/input/.revayat-main.html");
        if !source.is_file() || source.canonicalize()? != source {
            return Err("invalid isolated HTML source".into());
        }
        fs::create_dir_all("/tmp/tex-home")?;
        let log = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open("/output/console-pass-1.log")?;
        let errors = log.try_clone()?;
        let status = Command::new("/usr/bin/weasyprint")
            .args([
                "--encoding",
                "utf-8",
                "--base-url",
                "/input",
                "/input/.revayat-main.html",
                "/output/document.pdf",
            ])
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(errors)
            .status()?;
        if !status.success() || fs::metadata("/output/document.pdf")?.len() == 0 {
            return Err("isolated WeasyPrint failed".into());
        }
        return Ok(());
    }
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
