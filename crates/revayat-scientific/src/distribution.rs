//! Native, bounded skill payloads and recoverable multi-host installation.
use crate::distribution_paths::{directory_path, distinct_targets, key, protected_location};
use crate::identity::{Fingerprint, ObjectId, file_identity, is_link, path_object_id};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_TREE_BYTES: u64 = 512 * 1024 * 1024;
pub const NAME: &str = "revayat-scientific";
pub const AGENTS: &[(&str, &str, &str)] = &[
    ("claude", ".claude/skills", ".claude/skills"),
    ("codex", ".agents/skills", ".agents/skills"),
    ("cursor", ".cursor/skills", ".cursor/skills"),
    ("kiro", ".kiro/skills", ".kiro/skills"),
    ("cline", ".cline/skills", ".cline/skills"),
    ("hermes", ".hermes/skills", ".hermes/skills"),
    ("opencode", ".config/opencode/skills", ".opencode/skills"),
    ("antigravity", ".gemini/config/skills", ".agents/skills"),
];
#[derive(Clone, Debug)]
pub struct PayloadFile {
    pub source: PathBuf,
    pub relative: PathBuf,
    pub fingerprint: Fingerprint,
}
#[derive(Clone, Debug)]
pub struct Payload {
    pub files: Vec<PayloadFile>,
}
pub fn skill_identity(path: &Path) -> Result<()> {
    let bytes = fs::read(path.join("SKILL.md"))?;
    ensure!(bytes.len() <= 128 * 1024, "skill identity exceeds 128 KiB");
    let decoded = std::str::from_utf8(&bytes)?;
    let text = decoded
        .strip_prefix('\u{feff}')
        .unwrap_or(decoded)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let rest = text
        .strip_prefix("---\n")
        .context("skill identity frontmatter is missing")?;
    let front = rest
        .split_once("\n---\n")
        .map(|p| p.0)
        .or_else(|| rest.strip_suffix("\n---"))
        .context("skill identity frontmatter is incomplete")?;
    let mut names = Vec::new();
    let mut continuation = false;
    for line in front
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
    {
        if line.starts_with(char::is_whitespace) {
            ensure!(continuation, "ambiguous indented skill identity");
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .context("invalid skill frontmatter key")?;
        let key = key.trim_end_matches([' ', '\t']);
        ensure!(
            !key.is_empty()
                && key.chars().enumerate().all(|(i, c)| c.is_ascii_alphabetic()
                    || i > 0 && (c.is_ascii_digit() || c == '_' || c == '-')),
            "ambiguous skill frontmatter key"
        );
        if key == "name" {
            names.push(value.trim());
        }
        continuation =
            key != "name" && ["", "|", ">", "|-", ">-", "|+", ">+"].contains(&value.trim());
    }
    ensure!(
        names.len() == 1
            && [NAME, "'revayat-scientific'", "\"revayat-scientific\""].contains(&names[0]),
        "source or destination is not an identified revayat-scientific skill"
    );
    Ok(())
}
impl Payload {
    pub fn collect(source: &Path, binary: Option<&Path>) -> Result<Self> {
        let source = directory_path(source)?;
        skill_identity(&source)?;
        let mut pending = vec![source.clone()];
        let mut files = Vec::new();
        let mut total = 0;
        let mut entries = 0;
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory)? {
                let path = entry?.path();
                entries += 1;
                ensure!(entries <= 100_000, "payload tree exceeds 100000 entries");
                ensure!(
                    !is_link(&path)?,
                    "distributable skill contains a link or reparse point"
                );
                let relative = path.strip_prefix(&source)?.to_owned();
                if relative.components().any(|p| {
                    let p = p.as_os_str().to_string_lossy();
                    p.starts_with('.')
                        || [
                            "logs",
                            "fonts",
                            "__pycache__",
                            "AGENTS.md",
                            "CLAUDE.md",
                            "secrets.md",
                            "explain-AI.md",
                        ]
                        .contains(&p.as_ref())
                }) {
                    continue;
                }
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                ensure!(path.is_file(), "payload contains a nonregular file");
                let top = relative
                    .components()
                    .next()
                    .context("empty payload address")?
                    .as_os_str();
                let allowed = ["SKILL.md", "LICENSE", "NOTICE.md"]
                    .iter()
                    .any(|name| relative == Path::new(name))
                    || ["references", "assets", "agents", "bin"]
                        .iter()
                        .any(|name| top == *name);
                if binary.is_some() && top == "bin" {
                    continue;
                }
                if !allowed
                    || ["py", "pyc", "ps1", "sh", "cs", "c", "log"].contains(
                        &path
                            .extension()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .as_ref(),
                    )
                {
                    continue;
                }
                let fingerprint = file_identity(&path, Some(MAX_PAYLOAD_BYTES))?;
                total += fingerprint.size;
                ensure!(
                    total <= MAX_PAYLOAD_BYTES && files.len() < 10_000,
                    "payload exceeds 64 MiB or 10000 files"
                );
                files.push(PayloadFile {
                    source: path,
                    relative,
                    fingerprint,
                });
            }
        }
        if let Some(binary) = binary {
            ensure!(
                !is_link(binary)?,
                "distribution executable must be a real file"
            );
            let fingerprint = file_identity(binary, Some(MAX_PAYLOAD_BYTES))?;
            total += fingerprint.size;
            ensure!(total <= MAX_PAYLOAD_BYTES, "payload exceeds 64 MiB");
            files.retain(|f| !f.relative.starts_with("bin"));
            files.push(PayloadFile {
                source: binary.to_owned(),
                relative: PathBuf::from("bin").join(if cfg!(windows) {
                    "revayat-scientific.exe"
                } else {
                    "revayat-scientific"
                }),
                fingerprint,
            });
        }
        let mut names = HashSet::new();
        ensure!(
            files.iter().all(|f| names.insert(key(&f.relative))),
            "duplicate or case-colliding payload entries"
        );
        files.sort_by(|a, b| a.relative.cmp(&b.relative));
        ensure!(
            files.iter().any(|f| f.relative == Path::new("SKILL.md")),
            "SKILL.md is missing"
        );
        Ok(Self { files })
    }
    pub fn verify(&self) -> Result<()> {
        for row in &self.files {
            ensure!(
                !is_link(&row.source)?
                    && file_identity(&row.source, Some(MAX_PAYLOAD_BYTES))? == row.fingerprint,
                "source payload changed during distribution"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TreeSnapshot {
    pub identity: ObjectId,
    pub files: BTreeMap<PathBuf, Option<Fingerprint>>,
    pub directories: BTreeMap<PathBuf, (ObjectId, std::time::SystemTime)>,
}
pub fn snapshot(path: &Path) -> Result<Option<TreeSnapshot>> {
    directory_path(path)?;
    if !path.exists() {
        return Ok(None);
    }
    let mut files = BTreeMap::new();
    let mut directories = BTreeMap::new();
    let mut pending = vec![path.to_owned()];
    let mut total = 0;
    while let Some(parent) = pending.pop() {
        for entry in fs::read_dir(parent)? {
            let child = entry?.path();
            ensure!(
                !is_link(&child)?,
                "installation tree contains a link, junction or reparse point"
            );
            let value = if child.is_dir() {
                ensure!(
                    !child
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .eq_ignore_ascii_case(".git"),
                    "installation tree contains Git administration"
                );
                directories.insert(
                    child.strip_prefix(path)?.to_owned(),
                    (path_object_id(&child)?, fs::metadata(&child)?.modified()?),
                );
                pending.push(child.clone());
                None
            } else {
                ensure!(
                    child.is_file(),
                    "installation tree contains a nonregular entry"
                );
                let fp = file_identity(&child, Some(MAX_TREE_BYTES))?;
                total += fp.size;
                Some(fp)
            };
            ensure!(
                total <= MAX_TREE_BYTES && files.len() < 100_000,
                "installation tree exceeds snapshot limits"
            );
            files.insert(child.strip_prefix(path)?.to_owned(), value);
        }
    }
    Ok(Some(TreeSnapshot {
        identity: path_object_id(path)?,
        files,
        directories,
    }))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallBoundary {
    BeforeCopy(usize),
    AfterCopy(usize),
    Staged(usize),
    BeforeJournal,
    AfterJournal,
    BeforeActivate(usize),
    AfterActivate(usize),
    BeforeRestore(usize),
    AfterRestore(usize),
    BeforeCleanup,
    BeforeStageCleanup(usize),
}
#[derive(Serialize)]
struct Target {
    destination: PathBuf,
    stage: PathBuf,
    backup: PathBuf,
    old: Option<TreeSnapshot>,
    prepared: Option<TreeSnapshot>,
    stage_identity: Option<ObjectId>,
    lock: PathBuf,
    lock_identity: ObjectId,
    #[serde(skip)]
    _handle: File,
}
fn mkdirs(path: &Path, created: &mut Vec<(PathBuf, ObjectId)>) -> Result<()> {
    directory_path(path)?;
    let mut missing = Vec::new();
    let mut current = path;
    while !current.exists() {
        missing.push(current.to_owned());
        current = current.parent().context("missing filesystem root")?;
    }
    for path in missing.iter().rev() {
        directory_path(path)?;
        fs::create_dir(path)?;
        created.push((path.clone(), path_object_id(path)?));
    }
    Ok(())
}
fn lock_path(destination: &Path) -> PathBuf {
    let hash = format!("{:x}", Sha256::digest(key(destination).as_bytes()));
    destination
        .parent()
        .unwrap()
        .join(format!(".revayat-install-{}.lock", &hash[..24]))
}
fn same(path: &Path, expected: &Option<TreeSnapshot>) -> bool {
    snapshot(path).ok().as_ref() == Some(expected)
}
fn journal(path: &Path, targets: &[Target]) -> Result<()> {
    let mut journal = OpenOptions::new().create_new(true).write(true).open(path)?;
    serde_json::to_writer_pretty(
        &mut journal,
        &serde_json::json!({"version":1,"operation":"recoverable-skill-install","instruction":"Stop other installers. Compare every destination, stage, backup and lock before restoring. Retain this complete plan until all targets are resolved.","targets":targets}),
    )?;
    journal.write_all(b"\n")?;
    journal.sync_all()?;
    Ok(())
}
pub fn install_targets(
    destinations: &[PathBuf],
    force: bool,
    source: &Path,
    repository: &Path,
    payload: &Payload,
) -> Result<Vec<PathBuf>> {
    install_observed(destinations, force, source, repository, payload, |_, _| {
        Ok(())
    })
}
pub fn install_observed(
    destinations: &[PathBuf],
    force: bool,
    source: &Path,
    repository: &Path,
    payload: &Payload,
    mut observe: impl FnMut(InstallBoundary, &Path) -> Result<()>,
) -> Result<Vec<PathBuf>> {
    ensure!(
        !destinations.is_empty(),
        "no installation destinations selected"
    );
    payload.verify()?;
    let destinations: Vec<_> = destinations
        .iter()
        .map(|d| protected_location(d, repository, source, true))
        .collect::<Result<_>>()?;
    distinct_targets(&destinations)?;
    let mut previous = Vec::new();
    for dest in &destinations {
        let old = snapshot(dest)?;
        ensure!(
            force || old.is_none(),
            "skill exists; use --force to retain a backup and replace it"
        );
        if old.as_ref().is_some_and(|s| !s.files.is_empty()) {
            skill_identity(dest)?;
        }
        previous.push(old);
    }
    let run = tempfile::Builder::new().prefix("revayat-id-").tempfile()?;
    let run_id = run
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .replace('.', "-");
    let mut targets: Vec<Target> = Vec::new();
    let mut created = Vec::new();
    let mut recovery = None;
    let attempt = (|| -> Result<()> {
        for (index, (dest, old)) in destinations.iter().zip(previous).enumerate() {
            let parent = dest.parent().context("destination lacks parent")?;
            mkdirs(parent, &mut created)?;
            let backup_parent = if parent
                .file_name()
                .is_some_and(|s| s.to_string_lossy().eq_ignore_ascii_case("skills"))
            {
                parent.parent().unwrap()
            } else {
                parent
            };
            let backup_root = protected_location(
                &backup_parent.join("skill-backups"),
                repository,
                source,
                true,
            )?;
            mkdirs(&backup_root, &mut created)?;
            let lock = lock_path(dest);
            let mut handle = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock)?;
            handle.write_all(run_id.as_bytes())?;
            handle.sync_all()?;
            let lock_identity = path_object_id(&lock)?;
            let stage = parent.join(format!(".revayat-scientific-stage-{run_id}-{index}"));
            let backup = backup_root.join(format!("{NAME}-{run_id}-{index}"));
            targets.push(Target {
                destination: dest.clone(),
                stage,
                backup,
                old,
                prepared: None,
                stage_identity: None,
                lock,
                lock_identity,
                _handle: handle,
            });
        }
        let root = targets[0]
            .destination
            .parent()
            .unwrap()
            .join(format!(".revayat-install-recovery-{run_id}"));
        fs::create_dir(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        recovery = Some(root.clone());
        for target in &mut targets {
            fs::create_dir(&target.stage)?;
            target.stage_identity = Some(path_object_id(&target.stage)?);
            target.prepared = snapshot(&target.stage)?;
            target._handle.set_len(0)?;
            target._handle.seek(SeekFrom::Start(0))?;
            target
                ._handle
                .write_all(root.join("recovery.json").to_string_lossy().as_bytes())?;
            target._handle.sync_all()?;
        }
        journal(&root.join("recovery.json"), &targets)?;
        observe(InstallBoundary::BeforeJournal, &root)?;
        for (index, target) in targets.iter_mut().enumerate() {
            for (count, row) in payload.files.iter().enumerate() {
                observe(InstallBoundary::BeforeCopy(count), &target.stage)?;
                let dest = target.stage.join(&row.relative);
                fs::create_dir_all(dest.parent().unwrap())?;
                fs::copy(&row.source, &dest)?;
                ensure!(
                    file_identity(&dest, Some(MAX_PAYLOAD_BYTES))?.same_bytes(&row.fingerprint),
                    "staged payload differs from source"
                );
                observe(InstallBoundary::AfterCopy(count), &dest)?;
            }
            for row in &payload.files {
                ensure!(
                    file_identity(&target.stage.join(&row.relative), Some(MAX_PAYLOAD_BYTES))?
                        .same_bytes(&row.fingerprint),
                    "staged payload differs from the checked source"
                );
            }
            target.prepared = snapshot(&target.stage)?;
            observe(InstallBoundary::Staged(index), &target.stage)?;
        }
        payload.verify()?;
        journal(&root.join("prepared.json"), &targets)?;
        fs::rename(root.join("prepared.json"), root.join("recovery.json"))?;
        observe(InstallBoundary::AfterJournal, &root)?;
        for (index, target) in targets.iter().enumerate() {
            observe(InstallBoundary::BeforeActivate(index), &target.destination)?;
            protected_location(&target.destination, repository, source, true)?;
            directory_path(target.backup.parent().unwrap())?;
            ensure!(
                same(&target.destination, &target.old),
                "installation target changed during staging"
            );
            ensure!(
                path_object_id(&target.lock)? == target.lock_identity,
                "installation lock ownership changed"
            );
            ensure!(
                same(&target.stage, &target.prepared),
                "installation stage changed before activation"
            );
            if target.old.is_some() {
                fs::rename(&target.destination, &target.backup)?;
            }
            fs::rename(&target.stage, &target.destination)?;
            observe(InstallBoundary::AfterActivate(index), &target.destination)?;
        }
        observe(InstallBoundary::BeforeCleanup, &targets[0].destination)?;
        for target in &targets {
            ensure!(
                path_object_id(&target.lock)? == target.lock_identity,
                "installation recovery required: lock ownership changed"
            );
        }
        Ok(())
    })();
    if let Err(error) = attempt {
        let mut unresolved = false;
        for (index, target) in targets.iter().enumerate().rev() {
            let restored = (|| -> Result<()> {
                observe(InstallBoundary::BeforeRestore(index), &target.destination)?;
                directory_path(&target.destination)?;
                directory_path(&target.stage)?;
                directory_path(&target.backup)?;
                if target.prepared.is_some() && same(&target.destination, &target.prepared) {
                    ensure!(!target.stage.exists(), "stage occupied during rollback");
                    fs::rename(&target.destination, &target.stage)?;
                }
                if target.old.is_some() && !same(&target.destination, &target.old) {
                    ensure!(
                        !target.destination.exists() && same(&target.backup, &target.old),
                        "cannot safely restore previous installation"
                    );
                    fs::rename(&target.backup, &target.destination)?;
                }
                observe(InstallBoundary::AfterRestore(index), &target.destination)?;
                ensure!(
                    same(&target.destination, &target.old),
                    "installation rollback incomplete"
                );
                Ok(())
            })();
            if restored.is_err() && !same(&target.destination, &target.old) {
                unresolved = true;
            }
        }
        for target in &targets {
            if path_object_id(&target.lock).ok() != Some(target.lock_identity) {
                unresolved = true;
            }
        }
        if unresolved {
            bail!(
                "installation recovery required; preserved complete journal, backups, stages and locks at {}: {error}",
                recovery.as_ref().map_or_else(
                    || "installation target parents".into(),
                    |p| p.display().to_string()
                )
            );
        }
        for (index, target) in targets.iter().enumerate() {
            observe(InstallBoundary::BeforeStageCleanup(index), &target.stage)?;
        }
        cleanup(&targets, recovery.as_deref(), &created)?;
        return Err(error);
    }
    let backups = targets
        .iter()
        .filter(|t| t.old.is_some())
        .map(|t| t.backup.clone())
        .collect();
    for (index, target) in targets.iter().enumerate() {
        observe(InstallBoundary::BeforeStageCleanup(index), &target.stage)?;
    }
    cleanup(&targets, recovery.as_deref(), &[])?;
    Ok(backups)
}
fn cleanup(
    targets: &[Target],
    recovery: Option<&Path>,
    created: &[(PathBuf, ObjectId)],
) -> Result<()> {
    for target in targets {
        if target.stage.exists() {
            ensure!(
                path_object_id(&target.stage).ok() == target.stage_identity,
                "stage ownership changed; recovery required"
            );
            fs::remove_dir_all(&target.stage)?;
        }
        ensure!(
            path_object_id(&target.lock)? == target.lock_identity,
            "lock ownership changed; recovery required"
        );
        fs::remove_file(&target.lock)?;
    }
    if let Some(root) = recovery {
        fs::remove_dir_all(root)?;
    }
    for (path, id) in created.iter().rev() {
        if path_object_id(path).ok() == Some(*id) {
            let _ = fs::remove_dir(path);
        }
    }
    Ok(())
}
pub fn repository_root() -> Result<PathBuf> {
    if let Some(root) = std::env::var_os("REVAYAT_REPOSITORY") {
        return Ok(PathBuf::from(root));
    }
    let current = std::env::current_dir()?;
    for path in current.ancestors() {
        if path.join("skills/revayat-scientific/SKILL.md").is_file() {
            return Ok(path.to_owned());
        }
    }
    bail!("run this development command from the repository, or set REVAYAT_REPOSITORY")
}
pub fn cli_install(args: &[String]) -> Result<i32> {
    use clap::Parser;
    #[derive(Parser)]
    struct Options {
        #[arg(long, default_value = "all")]
        agent: String,
        #[arg(long,default_value="user",value_parser=["user","project"])]
        scope: String,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        dest: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    }
    let opts =
        Options::try_parse_from(std::iter::once("install".to_owned()).chain(args.iter().cloned()))?;
    ensure!(
        opts.scope != "project" || opts.path.is_some(),
        "--scope project requires --path"
    );
    let (repository, source) = if let Ok(repository) = repository_root() {
        let source = repository.join("skills").join(NAME);
        (repository, source)
    } else {
        let executable = std::env::current_exe()?;
        let source = executable
            .parent()
            .and_then(Path::parent)
            .context("installed skill source is unavailable")?
            .to_owned();
        skill_identity(&source)?;
        let repository = source
            .parent()
            .context("skill source lacks parent")?
            .to_owned();
        (repository, source)
    };
    let binary = std::env::current_exe()?;
    let payload = Payload::collect(&source, Some(&binary))?;
    let destinations = if let Some(dest) = opts.dest {
        vec![dest]
    } else {
        let base = directory_path(&if opts.scope == "project" {
            opts.path.unwrap()
        } else {
            std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                .map(PathBuf::from)
                .context("user home is unavailable")?
        })?;
        ensure!(base.is_dir(), "user or project root does not exist");
        ensure!(
            opts.agent == "all" || AGENTS.iter().any(|a| a.0 == opts.agent),
            "unknown agent"
        );
        let mut dests = Vec::new();
        for (name, user, project) in AGENTS {
            let parent = base.join(if opts.scope == "project" {
                project
            } else {
                user
            });
            if (opts.agent == "all"
                && (parent.parent().is_some_and(Path::is_dir)
                    || *name == "codex" && base.join(".codex").is_dir()))
                || opts.agent == *name
            {
                let dest = parent.join(NAME);
                if !dests.contains(&dest) {
                    dests.push(dest);
                }
            }
        }
        dests
    };
    install_targets(&destinations, opts.force, &source, &repository, &payload)?;
    for dest in destinations {
        println!("Installed revayat-scientific: {}", dest.display());
    }
    Ok(0)
}
pub use crate::distribution_package::{cli_package, package};
