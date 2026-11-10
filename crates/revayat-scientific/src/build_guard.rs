//! Checked-input records and exact-byte guarded delivery.
use super::{MAX_FILE_BYTES, MAX_FILES, MAX_RECORD_BYTES, file_hash};
use crate::{
    identity::{Fingerprint, file_identity, is_link, path_object_id},
    publication::validate_destination,
};
use anyhow::{Context, Result, ensure};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
fn unique_map<'de, D: de::Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<PathBuf, String>, D::Error> {
    struct Unique;
    impl<'de> Visitor<'de> for Unique {
        type Value = BTreeMap<PathBuf, String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a bounded unique fingerprint map")
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((path, digest)) = map.next_entry::<PathBuf, String>()? {
                if result.len() >= MAX_FILES || result.insert(path, digest).is_some() {
                    return Err(de::Error::custom(
                        "duplicate or excessive build fingerprint",
                    ));
                }
            }
            Ok(result)
        }
    }
    d.deserialize_map(Unique)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildGuard {
    pub schema: u8,
    #[serde(deserialize_with = "unique_map")]
    pub inputs: BTreeMap<PathBuf, String>,
    pub outputs: Vec<PathBuf>,
    #[serde(deserialize_with = "unique_map")]
    pub rendered: BTreeMap<PathBuf, String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryBoundary {
    BeforeCopy,
    AfterCopy,
    BeforePublication,
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn destinations(outputs: &[PathBuf], sources: &[PathBuf]) -> Result<()> {
    ensure!(
        (2..=5).contains(&outputs.len()),
        "build needs two PDF outputs and at most three previews"
    );
    let mut keys = BTreeSet::new();
    let mut ids = Vec::new();
    let mut preview_names = BTreeSet::new();
    for (index, path) in outputs.iter().enumerate() {
        ensure!(path.is_absolute(), "build output paths must be absolute");
        let selected = validate_destination(path, sources)?;
        ensure!(
            keys.insert(selected.to_string_lossy().to_lowercase()),
            "build output paths collide"
        );
        if selected.try_exists()? {
            let id = path_object_id(&selected)?;
            ensure!(!ids.contains(&id), "build output paths alias each other");
            ids.push(id);
        }
        if index >= 2 {
            ensure!(
                preview_names.insert(
                    path.file_name()
                        .context("preview has no basename")?
                        .to_string_lossy()
                        .to_lowercase()
                ),
                "build preview basenames must be unique"
            );
        }
    }
    Ok(())
}
impl BuildGuard {
    pub fn create(path: &Path, inputs: &[PathBuf], outputs: &[PathBuf]) -> Result<Self> {
        ensure!(
            !inputs.is_empty() && inputs.len() <= MAX_FILES,
            "invalid bounded build input count"
        );
        let mut snapshots = BTreeMap::new();
        for input in inputs {
            let input = input.canonicalize()?;
            snapshots.insert(input.clone(), file_hash(&input)?);
        }
        let outputs = outputs
            .iter()
            .map(std::path::absolute)
            .collect::<std::io::Result<Vec<_>>>()?;
        let guard = Self {
            schema: 1,
            inputs: snapshots,
            outputs,
            rendered: BTreeMap::new(),
        };
        guard.validate(path)?;
        guard.save(path, true)?;
        Self::check(path, None)
    }
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_with_limit(path, MAX_RECORD_BYTES)
    }
    pub fn load_with_limit(path: &Path, max_bytes: u64) -> Result<Self> {
        ensure!(
            max_bytes > 0 && max_bytes <= MAX_RECORD_BYTES,
            "record byte limit cannot exceed production budget"
        );
        validate_destination(path, &[])?;
        let raw = crate::resource::bounded_read(path, max_bytes as usize)?;
        ensure!(
            raw.len() as u64 <= MAX_RECORD_BYTES,
            "build record grew beyond 4 MiB"
        );
        let guard: Self = serde_json::from_slice(&raw).context("invalid build record")?;
        guard.validate(path)?;
        Ok(guard)
    }
    pub fn validate(&self, path: &Path) -> Result<()> {
        ensure!(
            self.schema == 1 && !self.inputs.is_empty() && self.inputs.len() <= MAX_FILES,
            "invalid build record schema"
        );
        ensure!(self.rendered.len() <= 1, "invalid rendered artifact count");
        for (name, digest) in self.inputs.iter().chain(&self.rendered) {
            ensure!(
                name.is_absolute() && valid_hash(digest),
                "invalid build path or fingerprint"
            );
        }
        let mut protected = vec![std::path::absolute(path)?];
        protected.extend(self.inputs.keys().cloned());
        destinations(&self.outputs, &protected)?;
        ensure!(
            self.rendered
                .keys()
                .all(|p| Some(p) == self.outputs.first()),
            "invalid rendered artifact identity"
        );
        Ok(())
    }
    fn save(&self, path: &Path, new: bool) -> Result<()> {
        validate_destination(path, &[])?;
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "build record exceeds 4 MiB"
        );
        if new {
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            return Ok(());
        }
        let pending = path.with_file_name(format!(
            "{}.pending",
            path.file_name()
                .context("guard filename missing")?
                .to_string_lossy()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&pending, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&pending);
        }
        result
    }
    pub fn check(path: &Path, resources: Option<&BTreeMap<PathBuf, String>>) -> Result<Self> {
        let mut guard = Self::load(path)?;
        let before = guard.inputs.len();
        if let Some(resources) = resources {
            ensure!(resources.len() <= MAX_FILES, "invalid resource map");
            for (name, digest) in resources {
                ensure!(
                    name.is_absolute() && valid_hash(digest),
                    "invalid resource identity"
                );
                if let Some(previous) = guard.inputs.get(name) {
                    ensure!(
                        previous == digest,
                        "renderer consumed a different checked input revision"
                    );
                } else {
                    guard.inputs.insert(name.clone(), digest.clone());
                }
            }
        }
        guard.validate(path)?;
        for (name, digest) in guard.inputs.iter().chain(&guard.rendered) {
            ensure!(
                file_hash(name)? == *digest,
                "checked build input or rendered artifact changed; rerun all build checks"
            );
        }
        if guard.inputs.len() != before {
            guard.save(path, false)?;
        }
        Ok(guard)
    }
    pub fn seal(path: &Path, output: &Path, digest: &str) -> Result<()> {
        let mut guard = Self::check(path, None)?;
        let output = std::path::absolute(output)?;
        ensure!(
            Some(&output) == guard.outputs.first() && valid_hash(digest),
            "renderer output differs from planned working PDF"
        );
        ensure!(
            file_hash(&output)? == digest,
            "working PDF changed during renderer publication"
        );
        guard.rendered.insert(output, digest.into());
        guard.save(path, false)?;
        Self::check(path, None)?;
        Ok(())
    }
    pub fn protected(&self, path: &Path) -> Vec<PathBuf> {
        let mut result = vec![path.to_path_buf()];
        result.extend(self.inputs.keys().cloned());
        result
    }
    pub fn deliver(path: &Path) -> Result<()> {
        Self::deliver_observed(path, |_, _, _| Ok(()))
    }
    pub fn deliver_observed(
        path: &Path,
        boundary: impl FnMut(DeliveryBoundary, &Path, &Path) -> Result<()>,
    ) -> Result<()> {
        Self::deliver_with_identity(path, MAX_FILE_BYTES, boundary, file_identity)
    }
    pub fn deliver_with_identity(
        path: &Path,
        max_bytes: u64,
        mut boundary: impl FnMut(DeliveryBoundary, &Path, &Path) -> Result<()>,
        mut inspect: impl FnMut(&Path, Option<u64>) -> Result<Fingerprint>,
    ) -> Result<()> {
        ensure!(
            max_bytes > 0 && max_bytes <= MAX_FILE_BYTES,
            "delivery byte limit cannot exceed production budget"
        );
        let guard = Self::check(path, None)?;
        let working = &guard.outputs[0];
        let target = &guard.outputs[1];
        let original = inspect(working, Some(max_bytes))?;
        let digest = original.sha256;
        ensure!(
            guard.rendered.get(working) == Some(&digest),
            "working PDF has not been sealed by renderer"
        );
        fs::create_dir_all(target.parent().context("delivery parent missing")?)?;
        let directory = tempfile::Builder::new()
            .prefix(".revayat-delivery-")
            .tempdir_in(target.parent().unwrap())?;
        let stage = directory.path().join("document.pdf");
        boundary(DeliveryBoundary::BeforeCopy, working, &stage)?;
        use std::io::Read;
        let mut input = fs::File::open(working)?.take(original.size.saturating_add(1));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stage)?;
        ensure!(
            std::io::copy(&mut input, &mut output)? == original.size,
            "PDF changed during bounded delivery copy"
        );
        output.sync_all()?;
        drop(output);
        drop(input);
        boundary(DeliveryBoundary::AfterCopy, working, &stage)?;
        ensure!(
            inspect(working, Some(max_bytes))?.sha256 == digest
                && inspect(&stage, Some(max_bytes))?.sha256 == digest,
            "PDF changed during delivery staging"
        );
        Self::check(path, None)?;
        boundary(DeliveryBoundary::BeforePublication, working, &stage)?;
        ensure!(
            inspect(&stage, Some(max_bytes))?.sha256 == digest,
            "delivery staging changed before publication"
        );
        crate::publication::publish_with_identity(
            &[(stage, target.clone())],
            &guard.protected(path),
            Some(max_bytes),
            |_, _| Ok(()),
            &mut inspect,
        )?;
        ensure!(
            inspect(target, Some(max_bytes))?.sha256 == digest,
            "published PDF differs from sealed renderer output"
        );
        Ok(())
    }
    pub fn publish_previews(path: &Path, staged: &[PathBuf]) -> Result<()> {
        Self::publish_previews_observed(path, staged, |_, _| Ok(()))
    }
    pub fn publish_previews_observed(
        path: &Path,
        staged: &[PathBuf],
        boundary: impl FnMut(crate::publication::Boundary, &Path) -> Result<()>,
    ) -> Result<()> {
        Self::publish_previews_with_limits(path, staged, 128 * 1024 * 1024, 50_000_000, boundary)
    }
    pub fn publish_previews_with_limits(
        path: &Path,
        staged: &[PathBuf],
        max_bytes: usize,
        max_pixels: u64,
        boundary: impl FnMut(crate::publication::Boundary, &Path) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            max_bytes > 0
                && max_bytes <= 128 * 1024 * 1024
                && max_pixels > 0
                && max_pixels <= 50_000_000,
            "preview limits cannot exceed production budgets"
        );
        let guard = Self::check(path, None)?;
        ensure!(
            !guard.rendered.is_empty(),
            "preview publication requires a sealed rendered PDF"
        );
        ensure!(
            staged.len() == guard.outputs.len() - 2 && !staged.is_empty(),
            "preview batch must contain every planned role"
        );
        let mut entries = vec![];
        for (input, output) in staged.iter().zip(&guard.outputs[2..]) {
            ensure!(
                std::path::absolute(input)?.parent() == std::path::absolute(path)?.parent()
                    && input.file_name() == output.file_name(),
                "unexpected or outside verification sample"
            );
            ensure!(
                !is_link(input)? && input.is_file(),
                "preview staging must be a regular file"
            );
            let bytes = crate::resource::bounded_read(input, max_bytes)?;
            let reader = || {
                let mut reader = image::ImageReader::with_format(
                    std::io::Cursor::new(&bytes),
                    image::ImageFormat::Png,
                );
                let mut limits = image::Limits::default();
                limits.max_image_width = Some(max_pixels.min(u64::from(u32::MAX)) as u32);
                limits.max_image_height = limits.max_image_width;
                reader.limits(limits);
                reader
            };
            let (width, height) = reader()
                .into_dimensions()
                .context("preview PNG dimensions invalid")?;
            ensure!(
                width > 0 && height > 0 && u64::from(width) * u64::from(height) <= max_pixels,
                "empty or oversized preview"
            );
            reader().decode().context("preview is not a complete PNG")?;
            entries.push((input.clone(), output.clone()));
        }
        crate::publication::publish_observed(
            &entries,
            &guard.protected(path),
            Some(max_bytes as u64),
            boundary,
        )
    }
}
