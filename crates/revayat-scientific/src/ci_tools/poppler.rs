//! Pinned hosted Windows Poppler and actual PDF/raster readiness, without shell programs.
use super::{
    CommandSpec, Result,
    automation::{ToolReceipt, checked_run, cleanup_owned_at},
    ensure, fs,
};
use anyhow::Context;
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::Duration,
};

const URL: &str = "https://github.com/oschwartz10612/poppler-windows/releases/download/v26.09.0-0/Release-26.09.0-0.zip";
const SHA256: &str = "7a6f256a0ddf7536182246a5733331bf4677cbcc34f4663774947ad34556c8d0";
const LIMIT: u64 = 64 * 1024 * 1024;
const RECEIPT: &str = "revayat-poppler-owned.json";
const PREFIX: &str = "revayat-poppler-";
const TOOLS: &[&str] = &["pdfinfo", "pdftotext", "pdftoppm", "pdffonts"];

fn parent() -> Result<PathBuf> {
    ensure!(
        std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true"),
        "Poppler setup requires hosted CI"
    );
    PathBuf::from(std::env::var_os("RUNNER_TEMP").context("RUNNER_TEMP is required")?)
        .canonicalize()
        .map_err(Into::into)
}

fn safe_member(name: &str) -> Result<PathBuf> {
    ensure!(
        !name.contains(['\\', ':', '\0', '<', '>', '"', '|', '?', '*'])
            && name.len() <= 4096
            && !name
                .trim_end_matches('/')
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."),
        "invalid Poppler archive path"
    );
    let path = Path::new(name);
    ensure!(
        !path.as_os_str().is_empty()
            && path.components().all(|part| {
                let Component::Normal(part) = part else {
                    return false;
                };
                let Some(text) = part.to_str() else {
                    return false;
                };
                let stem = text.split('.').next().unwrap_or("").to_ascii_uppercase();
                !text.ends_with(['.', ' '])
                    && !text.chars().any(char::is_control)
                    && ![
                        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
                        "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6",
                        "LPT7", "LPT8", "LPT9",
                    ]
                    .contains(&stem.as_str())
            }),
        "unsafe Poppler archive component"
    );
    Ok(path.to_owned())
}

fn extract(bytes: &[u8], directory: &Path) -> Result<()> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    ensure!(
        archive.len() > 0 && archive.len() <= 16384,
        "invalid Poppler archive member count"
    );
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        let mut member = archive.by_index(index)?;
        let relative = safe_member(&member.name()?)?;
        ensure!(
            member.enclosed_name().as_deref() == Some(relative.as_path())
                && seen.insert(relative.to_string_lossy().to_ascii_lowercase())
                && member
                    .unix_mode()
                    .is_none_or(|mode| matches!(mode & 0o170000, 0 | 0o040000 | 0o100000)),
            "unsafe or duplicate Poppler archive member"
        );
        total = total
            .checked_add(member.size())
            .context("Poppler archive size overflow")?;
        ensure!(
            member.size() <= 128 * 1024 * 1024 && total <= 512 * 1024 * 1024,
            "Poppler archive extraction exceeds bound"
        );
        let destination = directory.join(relative);
        if member.is_dir() {
            fs::create_dir_all(destination)?;
            continue;
        }
        fs::create_dir_all(destination.parent().context("archive parent missing")?)?;
        let expected = member.size();
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        let copied = std::io::copy(&mut member.by_ref().take(expected + 1), &mut file)?;
        ensure!(copied == expected, "Poppler member size differs");
        file.flush()?;
    }
    Ok(())
}

fn ready(bin: Option<&Path>, scratch: &Path, pinned: bool) -> Result<()> {
    let executable = |name: &str| -> Result<PathBuf> {
        if let Some(bin) = bin {
            let path = bin.join(format!("{name}.exe"));
            ensure!(
                path.is_file() && !crate::identity::is_link(&path)?,
                "Poppler executable missing"
            );
            Ok(path)
        } else {
            crate::runtime::executable(name)
        }
    };
    for name in TOOLS {
        let output = checked_run(
            CommandSpec::new(executable(name)?.as_os_str()).args(["-v"]),
            15,
        )?;
        let mut bytes = output.stdout;
        bytes.extend(output.stderr);
        let text = std::str::from_utf8(&bytes).context("Poppler version is not UTF-8")?;
        let version = text
            .lines()
            .next()
            .and_then(|line| line.strip_prefix(&format!("{name} version ")))
            .context("Poppler identity missing")?;
        ensure!(
            !version.is_empty()
                && version.len() <= 64
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.'),
            "invalid Poppler version"
        );
        ensure!(
            !pinned || version == "26.09.0",
            "Poppler pinned version differs"
        );
        println!("tool={name} version={version}");
    }
    use lopdf::{Document, Object, Stream, dictionary};
    let mut document = Document::with_version("1.7");
    let pages = document.new_object_id();
    let content = document.add_object(Stream::new(
        dictionary! {},
        b"0 0 0 rg 0 0 72 72 re f\n".to_vec(),
    ));
    let page = document.add_object(dictionary!{"Type"=>"Page", "Parent"=>pages, "MediaBox"=>vec![Object::from(0),Object::from(0),Object::from(72),Object::from(72)], "Resources"=>dictionary!{}, "Contents"=>content});
    document.objects.insert(
        pages,
        dictionary! {"Type"=>"Pages", "Kids"=>vec![Object::Reference(page)], "Count"=>1}.into(),
    );
    let catalog = document.add_object(dictionary! {"Type"=>"Catalog", "Pages"=>pages});
    document.trailer.set("Root", catalog);
    let input = scratch.join("painted.pdf");
    document.save(&input)?;
    let before = fs::read(&input)?;
    let mut raster = CommandSpec::new(executable("pdftoppm")?.as_os_str()).args([
        "-f",
        "1",
        "-singlefile",
        "-r",
        "72",
        "-png",
    ]);
    raster.args.extend([
        input.into_os_string(),
        scratch.join("page").into_os_string(),
    ]);
    checked_run(raster, 30)?;
    let image = image::open(scratch.join("page.png"))?.to_rgb8();
    ensure!(
        image.dimensions() == (72, 72) && image.get_pixel(36, 36).0 == [0, 0, 0],
        "Poppler painted raster readiness failed"
    );
    ensure!(
        fs::read(scratch.join("painted.pdf"))? == before,
        "Poppler changed readiness input"
    );
    println!("poppler_readiness=painted-raster source_preserved=true");
    Ok(())
}

pub(super) fn prepare() -> Result<()> {
    ensure!(
        cfg!(windows) && cfg!(target_arch = "x86_64"),
        "pinned Poppler setup requires Windows x86_64"
    );
    let parent = parent()?;
    ensure!(
        !parent.join(RECEIPT).try_exists()?,
        "Poppler receipt already exists"
    );
    let directory = tempfile::Builder::new()
        .prefix(PREFIX)
        .tempdir_in(&parent)?;
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;
    let response = client
        .get(URL)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|_| anyhow::anyhow!("pinned Poppler download failed"))?;
    ensure!(
        response.content_length().is_none_or(|size| size <= LIMIT),
        "Poppler download exceeds bound"
    );
    let mut bytes = Vec::new();
    response
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("Poppler download read failed"))?;
    super::automation::verified_download(&bytes, LIMIT, SHA256)?;
    extract(&bytes, directory.path())?;
    let bin = directory
        .path()
        .join("poppler-26.09.0/Library/bin")
        .canonicalize()?;
    let scratch = tempfile::Builder::new()
        .prefix("revayat-poppler-check-")
        .tempdir_in(&parent)?;
    ready(Some(&bin), scratch.path(), true)?;
    let installed = directory.path().canonicalize()?;
    let text = bin.to_str().context("Poppler path must be UTF-8")?;
    ensure!(!text.contains(['\r', '\n']), "invalid Poppler path");
    let receipt = parent.join(RECEIPT);
    let mut record = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt)?;
    let publication = (|| -> Result<()> {
        serde_json::to_writer(
            &mut record,
            &ToolReceipt {
                identity: crate::identity::path_object_id(&installed)?,
                directory: installed,
            },
        )?;
        record.flush()?;
        let mut output = fs::OpenOptions::new()
            .append(true)
            .open(std::env::var_os("GITHUB_PATH").context("GITHUB_PATH required")?)?;
        writeln!(output, "{text}")?;
        output.flush()?;
        Ok(())
    })();
    drop(record);
    if let Err(error) = publication {
        return Err(super::automation::publication_failure(
            error,
            fs::remove_file(receipt),
        ));
    }
    let _installed = directory.keep();
    println!("poppler=26.09.0 checksum=verified");
    Ok(())
}

pub(super) fn preflight() -> Result<()> {
    let scratch = tempfile::Builder::new()
        .prefix("revayat-poppler-check-")
        .tempdir_in(parent()?)?;
    ready(None, scratch.path(), cfg!(windows))
}

pub(super) fn cleanup() -> Result<()> {
    cleanup_owned_at(&parent()?, RECEIPT, PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn corrupt_poppler_archive_and_missing_tool_fail_without_sensitive_details() {
        let error =
            super::super::automation::verified_download(b"PRIVATE_DOWNLOAD_CANARY", LIMIT, SHA256)
                .unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE_"));
        let root = tempfile::tempdir().unwrap();
        let error = ready(Some(root.path()), root.path(), true).unwrap_err();
        assert_eq!(error.to_string(), "Poppler executable missing");
    }

    #[test]
    fn extraction_preserves_unicode_paths_and_refuses_existing_delivery() {
        use zip::write::SimpleFileOptions;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file("folder with spaces/فارسی.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"verified fixture").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let root = tempfile::tempdir().unwrap();
        extract(&bytes, root.path()).unwrap();
        let destination = root.path().join("folder with spaces/فارسی.txt");
        assert_eq!(fs::read(&destination).unwrap(), b"verified fixture");
        fs::write(&destination, b"previous delivery").unwrap();
        assert!(extract(&bytes, root.path()).is_err());
        assert_eq!(fs::read(destination).unwrap(), b"previous delivery");
    }

    #[test]
    fn archive_paths_reject_windows_aliases_and_escape() {
        for name in [
            "../escape",
            "/escape",
            "C:/escape",
            "bin\\escape",
            "bin/NUL.dll",
            "bin/a.",
            "bin/a ",
            "bin/COM1.exe",
            "bin/../escape",
        ] {
            assert!(safe_member(name).is_err(), "{name}");
        }
        assert!(safe_member("poppler-26.09.0/Library/bin/pdfinfo.exe").is_ok());
    }
    #[test]
    fn extraction_refuses_duplicate_case_and_symlink_members() {
        use zip::write::SimpleFileOptions;
        for linked in [false, true] {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            if linked {
                writer
                    .add_symlink("link", "outside", SimpleFileOptions::default())
                    .unwrap();
            } else {
                for name in ["bin/tool.exe", "bin/TOOL.exe"] {
                    writer
                        .start_file(name, SimpleFileOptions::default())
                        .unwrap();
                    writer.write_all(b"fixture").unwrap();
                }
            }
            let bytes = writer.finish().unwrap().into_inner();
            let root = tempfile::tempdir().unwrap();
            assert!(extract(&bytes, root.path()).is_err());
        }
    }
}
