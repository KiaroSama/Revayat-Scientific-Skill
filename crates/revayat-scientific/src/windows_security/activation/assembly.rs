//! Fixed activation assembly query contracts with bounded native-pointer projection.
use crate::windows_security::sxs::ordinal_path_equal;
use anyhow::{Result, ensure};
fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(|| anyhow::anyhow!("short activation assembly field"))?
            .try_into()?,
    ))
}
pub fn assembly_count(bytes: &[u8], returned: usize) -> Result<u32> {
    ensure!(
        (64..=65536).contains(&returned) && returned <= bytes.len(),
        "activation count allocation exceeds bound"
    );
    let count = u32_at(bytes, 8)?;
    ensure!(
        (1..=3).contains(&count),
        "activation assembly count exceeds fixed profile"
    );
    Ok(count)
}
pub fn decode_path(
    bytes: &[u8],
    start: u64,
    returned: usize,
    pointer: u64,
    length: u32,
) -> Result<String> {
    ensure!(
        (104..=65536).contains(&returned)
            && returned <= bytes.len()
            && (2..=2048).contains(&length)
            && length.is_multiple_of(2)
            && pointer >= start
            && pointer - start >= 104
            && pointer - start <= returned as u64
            && u64::from(length) + 2 <= returned as u64 - (pointer - start),
        "activation manifest path exceeds returned allocation"
    );
    let offset = (pointer - start) as usize;
    let end = offset + length as usize;
    ensure!(
        bytes[end..end + 2] == [0, 0],
        "activation manifest path lacks terminator"
    );
    let mut units = bytes[offset..end]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect::<Vec<_>>();
    let path = String::from_utf16(&units)
        .map_err(|_| anyhow::anyhow!("activation manifest path encoding differs"));
    units.fill(0);
    let path = path?;
    ensure!(
        !path.contains('\0'),
        "activation manifest path contains embedded terminator"
    );
    Ok(path)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssemblyLabel {
    Root,
    CommonControls,
    CommonControlsResources,
}
fn canonical(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..3] == *b":\\"
        && path[3..].split('\\').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with([' ', '.'])
                && !part.contains([':', '/', '\0'])
                && !part.chars().any(char::is_control)
        })
}
pub fn qualify_path(path: &str, root: &str, windows: &str, index: u32) -> Result<AssemblyLabel> {
    ensure!(
        canonical(path) && canonical(root) && canonical(windows),
        "activation manifest path is not canonical"
    );
    if index == 1 && ordinal_path_equal(path, root)? {
        return Ok(AssemblyLabel::Root);
    }
    ensure!(matches!(index, 2 | 3), "activation manifest index differs");
    let (directory, name) = path
        .rsplit_once('\\')
        .ok_or_else(|| anyhow::anyhow!("activation manifest directory missing"))?;
    ensure!(
        ordinal_path_equal(directory, &format!("{windows}\\WinSxS\\Manifests"))?
            && name.len() <= 240
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
            && name.to_ascii_lowercase().ends_with(".manifest"),
        "activation manifest is outside fixed system directory"
    );
    let name = name.to_ascii_lowercase();
    if name.starts_with("amd64_microsoft.windows.common-controls_6595b64144ccf1df_") {
        Ok(AssemblyLabel::CommonControls)
    } else if name.starts_with("amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_") {
        Ok(AssemblyLabel::CommonControlsResources)
    } else {
        anyhow::bail!("activation manifest family differs")
    }
}
pub fn require_profile(labels: &[AssemblyLabel], count: usize) -> Result<()> {
    ensure!(
        (1..=3).contains(&count) && labels.len() == count && labels[0] == AssemblyLabel::Root,
        "activation assembly root profile differs"
    );
    for (index, label) in labels.iter().enumerate() {
        ensure!(
            !labels[..index].contains(label),
            "activation assembly family is duplicated"
        );
    }
    ensure!(
        (count < 2 || labels.contains(&AssemblyLabel::CommonControls))
            && (count < 3 || labels.contains(&AssemblyLabel::CommonControlsResources)),
        "activation assembly profile is incomplete"
    );
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AssemblyInfo {
    pub flags: u32,
    pub identity_bytes: u32,
    pub path_type: u32,
    pub path_bytes: u32,
    pub manifest_time: i64,
    pub policy_type: u32,
    pub policy_bytes: u32,
    pub policy_time: i64,
    pub satellite: u32,
    pub manifest_major: u32,
    pub manifest_minor: u32,
    pub policy_major: u32,
    pub policy_minor: u32,
    pub directory_bytes: u32,
    pub identity: usize,
    pub path: usize,
    pub policy: usize,
    pub directory: usize,
    pub files: u32,
}
pub fn require_size(returned: usize, minimum: usize) -> Result<usize> {
    ensure!(
        (minimum..=65536).contains(&returned),
        "activation query returned size exceeds fixed buffer"
    );
    Ok(returned)
}
pub fn require_path_type(kind: u32) -> Result<()> {
    ensure!(kind == 2, "activation manifest is not a Win32 file");
    Ok(())
}
/// Preserve qualified count metadata before rejecting an out-of-profile count, as in ReadCount.
pub fn read_count(bytes: &[u8], returned: usize, lines: &mut Vec<String>) -> Result<u32> {
    require_size(returned, 64)?;
    ensure!(
        returned <= bytes.len(),
        "activation count allocation exceeds bound"
    );
    let count = u32_at(bytes, 8)?;
    lines.push(format!("WINDOWS_ACTIVATION_QUERY context=host class=2 returned_bytes={returned} assembly_count={count} cause_claimed=False"));
    assembly_count(bytes, returned)
}
impl AssemblyLabel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Root => "python-root",
            Self::CommonControls => "common-controls-manifest",
            Self::CommonControlsResources => "common-controls-resources-manifest",
        }
    }
    pub fn from_label(label: &str) -> Result<Self> {
        match label {
            "python-root" => Ok(Self::Root),
            "common-controls-manifest" => Ok(Self::CommonControls),
            "common-controls-resources-manifest" => Ok(Self::CommonControlsResources),
            _ => anyhow::bail!("activation assembly family differs"),
        }
    }
}
pub fn require_profile_names(labels: &[&str], count: usize) -> Result<()> {
    let labels = labels
        .iter()
        .map(|label| AssemblyLabel::from_label(label))
        .collect::<Result<Vec<_>>>()?;
    require_profile(&labels, count)
}
fn family(path: &str, prefix: &str) -> bool {
    let name = path.rsplit('\\').next().unwrap_or(path);
    name.len() <= 240
        && name.to_ascii_lowercase().starts_with(prefix)
        && name.to_ascii_lowercase().ends_with(".manifest")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
}
/// Fixed predicates describe a refused path without disclosing its text or granting qualification.
pub fn path_metadata(
    path: &str,
    root: &str,
    windows: &str,
    index: u32,
    returned: usize,
    kind: u32,
) -> Result<String> {
    let boolean = |value| if value { "True" } else { "False" };
    let directory = path
        .rsplit_once('\\')
        .map(|(directory, _)| directory)
        .unwrap_or("");
    Ok(format!(
        "WINDOWS_ACTIVATION_ASSEMBLY context=host class=3 index={index} returned_bytes={returned} path_type={kind} canonical={} python_root={} system_manifests={} common_controls={} common_controls_resources={} cause_claimed=False",
        boolean(canonical(path)),
        boolean(ordinal_path_equal(path, root)?),
        boolean(ordinal_path_equal(
            directory,
            &format!("{windows}\\WinSxS\\Manifests")
        )?),
        boolean(family(
            path,
            "amd64_microsoft.windows.common-controls_6595b64144ccf1df_"
        )),
        boolean(family(
            path,
            "amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_"
        ))
    ))
}
/// Complete independent release attempts, preserving an operation error before cleanup errors.
pub fn release<T>(
    operation: Result<T>,
    actions: Vec<Box<dyn FnMut() -> Result<()> + '_>>,
) -> Result<T> {
    let mut errors = Vec::new();
    for mut action in actions {
        if let Err(error) = action() {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        return operation;
    }
    if let Err(primary) = operation {
        errors.insert(0, primary);
    }
    Err(super::Failures { errors }.into())
}
#[path = "assembly_validation.rs"]
mod validation;
pub use validation::check_assembly_contract;
pub(crate) use validation::check_cleanup_validation;
