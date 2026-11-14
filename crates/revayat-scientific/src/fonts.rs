//! Static Western-digit Vazirmatn delivery with verified identity and provenance.
use crate::{identity, images::plain_path, publication};
use anyhow::{Context, Result, ensure};
use clap::Parser;
use read_fonts::TableProvider;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
pub const MAX_FONT: u64 = 20 * 1024 * 1024;
pub const MAX_ARCHIVE: u64 = 100 * 1024 * 1024;
pub const FILES: [(&str, u16); 2] = [("Vazirmatn-Regular.ttf", 400), ("Vazirmatn-Bold.ttf", 700)];
pub const LICENSE: &str = "OFL.txt";
pub const PROVENANCE: &str = "font-provenance.json";

fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    plain_path(path)?;
    let before = identity::file_identity(path, Some(max))?;
    let mut data = Vec::new();
    fs::File::open(path)?.take(max + 1).read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= max && before == identity::file_identity(path, Some(max))?,
        "font bundle changed during bounded reading"
    );
    Ok(data)
}
pub fn font_identity(path: &Path, weight: u16, version: &str) -> Result<Value> {
    let data = read_bounded(path, MAX_FONT)?;
    ensure!(
        data.len() >= 12 && data[..4] == [0, 1, 0, 0],
        "expected a static TrueType font"
    );
    let count = u16::from_be_bytes([data[4], data[5]]) as usize;
    ensure!(
        count <= 256 && 12 + count * 16 <= data.len(),
        "invalid TrueType directory"
    );
    let mut tags = std::collections::HashSet::new();
    for row in data[12..12 + count * 16].as_chunks::<16>().0 {
        let tag = &row[..4];
        let off = u32::from_be_bytes(row[8..12].try_into()?) as usize;
        let len = u32::from_be_bytes(row[12..16].try_into()?) as usize;
        ensure!(
            tags.insert(tag.to_vec()) && off.checked_add(len).is_some_and(|end| end <= data.len()),
            "invalid TrueType table bounds"
        );
    }
    ensure!(!tags.contains(b"fvar".as_slice()), "static font required");
    let face = read_fonts::FontRef::new(&data).context("invalid TrueType font")?;
    let _ = face.head()?;
    let hhea = face.hhea()?;
    let hmtx = face.hmtx()?;
    let glyphs = usize::from(face.maxp()?.num_glyphs());
    let metrics = usize::from(hhea.number_of_h_metrics());
    // These table views are lazy: parsing hmtx alone also succeeds for an
    // empty table. Require the records needed by every declared glyph.
    ensure!(
        metrics > 0
            && metrics <= glyphs
            && hmtx.h_metrics().len() == metrics
            && hmtx.left_side_bearings().len() >= glyphs - metrics,
        "font has incomplete horizontal glyph metrics"
    );
    ensure!(
        face.os2()?.us_weight_class() == weight,
        "font weight does not match its requested role"
    );
    let mut names: BTreeMap<u16, Vec<String>> = BTreeMap::new();
    let table = face.name()?;
    for name in table.name_record() {
        let id = name.name_id().to_u16();
        if matches!(id, 1 | 2 | 5 | 6 | 16 | 17) && name.is_unicode() {
            let value = name.string(table.string_data())?.to_string();
            ensure!(!value.contains('\u{fffd}'), "invalid Unicode font name");
            names.entry(id).or_default().push(value);
        }
    }
    let family = names
        .get(&16)
        .or_else(|| names.get(&1))
        .context("font family is missing")?
        .join(" ");
    let all_names = names
        .values()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    let fd = regex::Regex::new(r"(?i)(?:^|[\s_-])FD(?:$|[\s_-])|Farsi.*Digit")?;
    ensure!(
        family.to_lowercase().contains("vazirmatn") && !fd.is_match(&all_names),
        "font is not the Western-digit Vazirmatn family"
    );
    let version_pattern = regex::Regex::new(&format!(
        r"(?:^|[^0-9.]){}(?:$|[^0-9.])",
        regex::escape(version)
    ))?;
    ensure!(
        names
            .get(&5)
            .is_some_and(|v| v.iter().any(|s| version_pattern.is_match(s))),
        "font version differs from requested release"
    );
    ensure!(
        "0123456789".chars().all(|c| face
            .cmap()
            .is_ok_and(|cmap| cmap.map_codepoint(c).is_some())),
        "font lacks required numeral glyphs"
    );
    Ok(json!({"family":family,"weight":weight,"version":version,"sha256":digest(&data)}))
}
pub fn validate_bundle(
    directory: &Path,
    version: &str,
    require_provenance: bool,
) -> Result<BTreeMap<String, Value>> {
    let mut records = BTreeMap::new();
    for (name, weight) in FILES {
        records.insert(
            name.to_owned(),
            font_identity(&directory.join(name), weight, version)?,
        );
    }
    let raw = read_bounded(&directory.join(LICENSE), 100_000)?;
    let text = std::str::from_utf8(&raw)?;
    ensure!(
        [
            "Vazirmatn",
            "Copyright",
            "SIL OPEN FONT LICENSE",
            "Version 1.1",
            "PERMISSION & CONDITIONS",
            "DISCLAIMER"
        ]
        .iter()
        .all(|t| text.contains(t)),
        "corresponding complete Vazirmatn OFL.txt is required"
    );
    records.insert(LICENSE.to_owned(), json!({"sha256":digest(&raw)}));
    if require_provenance {
        let raw = read_bounded(&directory.join(PROVENANCE), 100_000)?;
        let metadata: Value = serde_json::from_slice(&raw)?;
        ensure!(
            metadata.is_object()
                && metadata.get("schema") == Some(&json!(1))
                && metadata.get("version") == Some(&json!(version))
                && metadata.get("files") == Some(&serde_json::to_value(&records)?),
            "font provenance does not match the delivered files"
        );
    }
    Ok(records)
}
pub fn cache_directory(version: &str) -> Result<PathBuf> {
    let base = std::env::var_os(if cfg!(windows) {
        "LOCALAPPDATA"
    } else {
        "XDG_CACHE_HOME"
    })
    .map(PathBuf::from)
    .or_else(|| {
        std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .map(|p| PathBuf::from(p).join(".cache"))
    })
    .context("no native cache directory configured")?;
    Ok(base.join("fa-fonts").join(version))
}
pub fn extract_bundle(archive: &Path, stage: &Path) -> Result<()> {
    let file = fs::File::open(archive)?;
    ensure!(
        file.metadata()?.len() <= MAX_ARCHIVE,
        "font archive exceeds size limit"
    );
    let mut package = zip::ZipArchive::new(file)?;
    let mut outputs = Vec::new();
    for name in FILES.iter().map(|(name, _)| *name).chain([LICENSE]) {
        let mut matches = Vec::new();
        for i in 0..package.len() {
            let entry = package.by_index(i)?;
            let entry_name = entry.name()?;
            if entry_name.rsplit('/').next() == Some(name) {
                matches.push(i);
            }
        }
        ensure!(
            matches.len() == 1,
            "font archive is incomplete or ambiguous"
        );
        let mut entry = package.by_index(matches[0])?;
        ensure!(
            entry.is_file()
                && entry.size() <= MAX_FONT
                && entry
                    .unix_mode()
                    .is_none_or(|mode| mode & 0o170000 != 0o120000),
            "font archive entry invalid or oversized"
        );
        let mut bytes = Vec::new();
        entry.by_ref().take(MAX_FONT + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_FONT && bytes.len() as u64 == entry.size(),
            "font archive entry exceeds bound"
        );
        outputs.push((stage.join(name), bytes));
    }
    for (path, bytes) in outputs {
        fs::write(path, bytes)?;
    }
    Ok(())
}
fn copy_bundle(source: &Path, stage: &Path) -> Result<()> {
    for name in FILES.iter().map(|(name, _)| *name).chain([LICENSE]) {
        fs::write(
            stage.join(name),
            read_bounded(&source.join(name), MAX_FONT)?,
        )?;
    }
    Ok(())
}
fn installed_bundle(stage: &Path, version: &str) -> Result<bool> {
    let mut candidates = Vec::new();
    for variable in ["WINDIR", "LOCALAPPDATA"] {
        if let Some(base) = std::env::var_os(variable) {
            candidates.push(PathBuf::from(base).join("Fonts"));
        }
    }
    for style in ["Regular", "Bold"] {
        let mut command = crate::runtime::CommandSpec::new("fc-match").args([
            "-f",
            "%{file}\n",
            &format!("Vazirmatn:style={style}"),
        ]);
        command.timeout = Duration::from_secs(5);
        command.max_output = 64 * 1024;
        let result = match crate::runtime::run(&command) {
            Ok(result) => result,
            Err(error) if crate::runtime::is_missing_executable(&error) => continue,
            Err(error) => return Err(error.context("installed font discovery failed")),
        };
        if result.success() {
            let paths =
                std::str::from_utf8(&result.stdout).context("fontconfig paths are not UTF-8")?;
            for path in paths.lines() {
                if let Some(parent) = Path::new(path).parent() {
                    candidates.extend(parent.ancestors().take(3).map(Path::to_owned));
                }
            }
        }
    }
    installed_from_candidates(stage, version, &candidates)
}
pub fn installed_from_candidates(
    stage: &Path,
    version: &str,
    candidates: &[PathBuf],
) -> Result<bool> {
    for candidate in candidates {
        if validate_bundle(candidate, version, false).is_ok() {
            copy_bundle(candidate, stage)?;
            return Ok(true);
        }
    }
    Ok(false)
}
/// Fetch never publishes one weight without its companion license and provenance.
/// The explicit cache argument makes offline delivery reproducible in CI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    Delivery(publication::Boundary),
    Cache(publication::Boundary),
}
pub fn fetch_with_cache(
    destination: &Path,
    version: &str,
    offline: bool,
    cache: &Path,
) -> Result<()> {
    fetch_with_cache_observed(destination, version, offline, cache, |_, _| Ok(()))
}
pub fn fetch_with_cache_observed(
    destination: &Path,
    version: &str,
    offline: bool,
    cache: &Path,
    mut observe: impl FnMut(Boundary, &Path) -> Result<()>,
) -> Result<()> {
    ensure!(
        regex::Regex::new(r"^[0-9]+(?:\.[0-9]+){1,2}$")?.is_match(version),
        "font version must be a numeric stable release"
    );
    for name in FILES
        .iter()
        .map(|(name, _)| *name)
        .chain([LICENSE, PROVENANCE])
    {
        publication::validate_destination(&destination.join(name), &[])?;
    }
    if validate_bundle(destination, version, true).is_ok() {
        return Ok(());
    }
    fs::create_dir_all(destination)?;
    let stage = tempfile::Builder::new()
        .prefix(".revayat-fonts-")
        .tempdir_in(destination)?;
    let mut kind = None;
    for (candidate, label) in [
        (destination, "existing"),
        (cache, "cache"),
        (
            cache.parent().context("cache parent missing")?,
            "legacy-cache",
        ),
    ] {
        if validate_bundle(candidate, version, false).is_ok() {
            copy_bundle(candidate, stage.path())?;
            kind = Some(label);
            break;
        }
    }
    if kind.is_none() && version == "33.003" {
        // The same licensed static release used for native form shaping is a
        // complete offline font source, with ordinary identity validation.
        fs::write(stage.path().join(FILES[0].0), crate::pdf_font::REGULAR)?;
        fs::write(stage.path().join(FILES[1].0), crate::pdf_font::BOLD)?;
        fs::write(stage.path().join(LICENSE), crate::pdf_font::LICENSE)?;
        validate_bundle(stage.path(), version, false)?;
        kind = Some("bundled");
    }
    if kind.is_none() && installed_bundle(stage.path(), version)? {
        kind = Some("installed");
    }
    if kind.is_none() {
        ensure!(
            !offline,
            "no complete validated font pair and OFL available offline"
        );
        let url = format!(
            "https://github.com/rastikerdar/vazirmatn/releases/download/v{version}/vazirmatn-v{version}.zip"
        );
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(90))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;
        let mut response = client.get(url).send()?.error_for_status()?;
        ensure!(
            response.content_length().is_none_or(|n| n <= MAX_ARCHIVE),
            "font download exceeds size limit"
        );
        let mut raw = Vec::new();
        response
            .by_ref()
            .take(MAX_ARCHIVE + 1)
            .read_to_end(&mut raw)?;
        ensure!(
            raw.len() as u64 <= MAX_ARCHIVE,
            "font download exceeds size limit"
        );
        let archive = stage.path().join("release.zip");
        fs::write(&archive, raw)?;
        extract_bundle(&archive, stage.path())?;
        kind = Some("release");
    }
    let records = validate_bundle(stage.path(), version, false)?;
    fs::write(
        stage.path().join(PROVENANCE),
        serde_json::to_vec_pretty(
            &json!({"schema":1,"version":version,"source":kind.unwrap(),"release":format!("https://github.com/rastikerdar/vazirmatn/releases/tag/v{version}"),"files":records}),
        )?,
    )?;
    validate_bundle(stage.path(), version, true)?;
    let entries: Vec<_> = FILES
        .iter()
        .map(|(name, _)| *name)
        .chain([LICENSE, PROVENANCE])
        .map(|name| (stage.path().join(name), destination.join(name)))
        .collect();
    publication::publish_observed(&entries, &[], Some(MAX_FONT), |b, p| {
        observe(Boundary::Delivery(b), p)
    })?;
    // Cache population is a separate complete validated batch. Existing good
    // cache bytes survive any failure preparing a new delivery.
    if destination != cache {
        let cache_result: Result<()> = (|| {
            plain_path(cache)?;
            fs::create_dir_all(cache)?;
            let cache_stage = tempfile::Builder::new()
                .prefix(".revayat-font-cache-")
                .tempdir_in(cache)?;
            let mut cache_entries = Vec::new();
            for name in FILES
                .iter()
                .map(|(name, _)| *name)
                .chain([LICENSE, PROVENANCE])
            {
                fs::copy(destination.join(name), cache_stage.path().join(name))?;
                cache_entries.push((cache_stage.path().join(name), cache.join(name)));
            }
            validate_bundle(cache_stage.path(), version, true)?;
            let protected = entries.iter().map(|(_, p)| p.clone()).collect::<Vec<_>>();
            publication::publish_observed(&cache_entries, &protected, Some(MAX_FONT), |b, p| {
                observe(Boundary::Cache(b), p)
            })?;
            Ok(())
        })();
        if cache_result.is_err() {
            eprintln!("font-fetch: optional validated cache write failed");
        }
    }
    Ok(())
}
pub fn fetch(destination: &Path, version: &str, offline: bool) -> Result<()> {
    fetch_with_cache(destination, version, offline, &cache_directory(version)?)
}
#[derive(Parser)]
#[command(name = "font-fetch")]
struct Args {
    #[arg(default_value = "fonts")]
    destination: PathBuf,
    #[arg(long)]
    version: Option<String>,
    #[arg(long)]
    offline: bool,
}
pub fn cli(args: &[String]) -> Result<i32> {
    let a =
        Args::try_parse_from(std::iter::once("font-fetch".to_owned()).chain(args.iter().cloned()))?;
    let version = a
        .version
        .or_else(|| std::env::var("VAZIRMATN_VERSION").ok())
        .unwrap_or_else(|| "33.003".to_owned());
    fetch(
        &a.destination,
        &version,
        a.offline || std::env::var("REVAYAT_FONT_OFFLINE").is_ok_and(|v| v == "1"),
    )?;
    Ok(0)
}
