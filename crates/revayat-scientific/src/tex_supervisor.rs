//! Host-only receipts allow a surviving owner to reap a killed controller's TeX.
use crate::{
    identity::is_link,
    tex_container::{RuntimeConfig, cleanup, validate_endpoint},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const DIRECTORY_ENV: &str = "REVAYAT_TEX_OWNER_DIR";
pub const TOKEN_ENV: &str = "REVAYAT_TEX_OWNER_TOKEN";
pub fn valid_token(token: &str) -> bool {
    token.len() == 32
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn new_token() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS randomness unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn regular_path(path: &Path) -> Result<PathBuf> {
    let path = std::path::absolute(path)?;
    for ancestor in path.ancestors() {
        ensure!(
            !is_link(ancestor)?,
            "container ownership paths must not contain links"
        );
    }
    Ok(path)
}
fn read_json(path: &Path, limit: u64) -> Result<serde_json::Value> {
    let path = regular_path(path)?;
    ensure!(
        fs::metadata(&path)?.is_file() && fs::metadata(&path)?.len() <= limit,
        "invalid bounded container ownership record"
    );
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "container ownership record grew beyond limit"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn validate_scope(directory: &Path, token: &str) -> Result<PathBuf> {
    let directory = regular_path(directory)?;
    ensure!(
        valid_token(token)
            && directory
                .file_name()
                .is_some_and(|n| n == format!(".revayat-tex-owner-{token}").as_str())
            && directory.is_dir()
            && read_json(&directory.join("scope.json"), 4096)? == json!({"token":token}),
        "container ownership scope identity mismatch"
    );
    Ok(directory)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub token: String,
    pub run_id: String,
    pub staging: PathBuf,
    pub config: RuntimeConfig,
}

pub fn register(config: &RuntimeConfig, staging: &Path, run_id: &str) -> Result<Option<PathBuf>> {
    let directory = std::env::var_os(DIRECTORY_ENV).filter(|s| !s.is_empty());
    let token = std::env::var(TOKEN_ENV).unwrap_or_default();
    if directory.is_none() && token.is_empty() {
        return Ok(None);
    }
    let owner = validate_scope(
        Path::new(&directory.context("owner directory missing")?),
        &token,
    )?;
    ensure!(valid_token(run_id), "invalid run identity");
    let staging = regular_path(staging)?;
    ensure!(
        staging
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with(".revayat-tex-"))
            && staging.is_dir(),
        "invalid owned staging directory"
    );
    let record = Receipt {
        token: token.clone(),
        run_id: run_id.into(),
        staging: staging.clone(),
        config: config.clone(),
    };
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staging.join("owner.json"))?;
    marker.write_all(serde_json::to_string(&json!({"token":token,"run_id":run_id}))?.as_bytes())?;
    marker.sync_all()?;
    let path = owner.join(format!("container-{run_id}.json"));
    let pending = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(&serde_json::to_vec(&record)?)?;
    file.sync_all()?;
    drop(file);
    fs::rename(pending, &path)?;
    Ok(Some(path))
}
pub fn acknowledge(path: Option<&Path>) -> Result<()> {
    if let Some(path) = path {
        fs::remove_file(regular_path(path)?)?;
    }
    Ok(())
}

fn collect(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = regular_path(&entry?.path())?;
        if path.is_dir() {
            collect(&path, paths)?;
        } else if path.file_name().is_some_and(|n| {
            n.to_string_lossy().starts_with("container-") && n.to_string_lossy().ends_with(".json")
        }) {
            paths.push(path);
            ensure!(
                paths.len() <= 256,
                "container ownership receipt limit exceeded"
            );
        }
    }
    Ok(())
}
pub fn records(directory: &Path, token: &str) -> Result<Vec<(PathBuf, Receipt)>> {
    let root = validate_scope(directory, token)?;
    let mut paths = vec![];
    collect(&root, &mut paths)?;
    paths.sort();
    let mut records = vec![];
    for path in paths {
        let bytes = read_json(&path, 65536)?;
        let record: Receipt = serde_json::from_value(bytes)?;
        validate_scope(path.parent().unwrap(), &record.token)?;
        ensure!(
            valid_token(&record.run_id)
                && path
                    .file_name()
                    .is_some_and(|n| n == format!("container-{}.json", record.run_id).as_str()),
            "container receipt run identity mismatch"
        );
        let staging = regular_path(&record.staging)?;
        ensure!(
            staging
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(".revayat-tex-"))
                && staging.is_dir()
                && read_json(&staging.join("owner.json"), 4096)?
                    == json!({"token":record.token,"run_id":record.run_id}),
            "container staging ownership mismatch"
        );
        validate_config(&record.config)?;
        records.push((path, record));
    }
    Ok(records)
}
fn validate_config(config: &RuntimeConfig) -> Result<()> {
    ensure!(
        config
            .base
            .first()
            .is_some_and(|p| Path::new(p).is_absolute()
                && Path::new(p).is_file()
                && Path::new(p)
                    .file_stem()
                    .is_some_and(|s| s.to_string_lossy().eq_ignore_ascii_case(&config.kind)))
            && (config.kind == "docker" || config.kind == "podman"),
        "invalid recovery runtime identity"
    );
    if config.kind == "docker" {
        ensure!(
            config.base.len() == 3 && config.base[1] == "--host",
            "invalid Docker recovery endpoint"
        );
        validate_endpoint(&config.base[2], "docker")?;
    } else if config.base[1..] != ["--remote=false"] {
        ensure!(
            (config.base.len() == 3 || config.base.len() == 5)
                && config.base[1] == "--url"
                && (config.base.len() != 5 || config.base[3] == "--identity"),
            "invalid Podman recovery endpoint"
        );
        validate_endpoint(&config.base[2], "podman")?;
    }
    let id = config
        .image
        .strip_prefix("sha256:")
        .unwrap_or(&config.image);
    ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid recovery image identity"
    );
    Ok(())
}
pub fn sweep(directory: &Path, token: &str) -> Result<()> {
    let planned = records(directory, token)?;
    for (receipt, record) in planned {
        cleanup(&record.config, &record.staging, &record.run_id, true)?;
        fs::remove_dir_all(regular_path(&record.staging)?)?;
        acknowledge(Some(&receipt))?;
    }
    ensure!(
        records(directory, token)?.is_empty(),
        "owned container receipts remain after cleanup"
    );
    Ok(())
}

pub struct ContainerScope {
    pub directory: PathBuf,
    pub token: String,
    finished: bool,
}
impl ContainerScope {
    pub fn create(base: &Path) -> Result<Self> {
        let inherited = std::env::var_os(DIRECTORY_ENV).filter(|s| !s.is_empty());
        let inherited_token = std::env::var(TOKEN_ENV).unwrap_or_default();
        let base = if inherited.is_some() || !inherited_token.is_empty() {
            validate_scope(
                Path::new(&inherited.context("inherited owner directory missing")?),
                &inherited_token,
            )?
        } else {
            regular_path(base)?
        };
        let token = new_token();
        let directory = base.join(format!(".revayat-tex-owner-{token}"));
        fs::create_dir(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        fs::write(
            directory.join("scope.json"),
            serde_json::to_vec(&json!({"token":token}))?,
        )?;
        Ok(Self {
            directory,
            token,
            finished: false,
        })
    }
    pub fn environment(&self) -> [(std::ffi::OsString, std::ffi::OsString); 2] {
        [
            (DIRECTORY_ENV.into(), self.directory.as_os_str().into()),
            (TOKEN_ENV.into(), self.token.clone().into()),
        ]
    }
    pub fn finish(&mut self) -> Result<()> {
        sweep(&self.directory, &self.token).with_context(|| {
            format!(
                "container cleanup unverified; retained ownership evidence: {}",
                self.directory.display()
            )
        })?;
        fs::remove_dir_all(validate_scope(&self.directory, &self.token)?)?;
        self.finished = true;
        Ok(())
    }
}
impl Drop for ContainerScope {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish();
        }
    }
}
