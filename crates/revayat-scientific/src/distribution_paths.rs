//! Distribution path admission and Git administration discovery.
use crate::identity::{is_link, path_object_id};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashSet,
    fs,
    path::{Component, Path, PathBuf},
    time::Duration,
};

pub fn key(path: &Path) -> String {
    let value = path.to_string_lossy().replace('\\', "/");
    let value = if let Some(unc) = value.strip_prefix("//?/UNC/") {
        format!("//{unc}")
    } else {
        value.strip_prefix("//?/").unwrap_or(&value).to_owned()
    };
    value.to_lowercase().replace('ß', "ss").replace('ς', "σ")
}
pub fn absolute(path: &Path) -> Result<PathBuf> {
    ensure!(
        !path.components().any(|p| p == Component::ParentDir),
        "distribution paths must not contain parent traversal"
    );
    Ok(std::path::absolute(path)?)
}
pub fn overlaps(left: &Path, right: &Path) -> bool {
    let (a, b) = (key(left), key(right));
    a == b
        || a.starts_with(&(b.trim_end_matches('/').to_owned() + "/"))
        || b.starts_with(&(a.trim_end_matches('/').to_owned() + "/"))
}
pub fn directory_path(path: &Path) -> Result<PathBuf> {
    let path = absolute(path)?;
    for part in path.ancestors() {
        ensure!(
            !is_link(part)?,
            "distribution path contains a link, junction or reparse point"
        );
        ensure!(
            !part.try_exists()? || part.is_dir(),
            "distribution path is not a directory"
        );
        if let Some(parent) = part.parent().filter(|p| p.is_dir()) {
            for sibling in fs::read_dir(parent)? {
                let sibling = sibling?.path();
                ensure!(
                    key(&sibling) != key(part) || sibling.file_name() == part.file_name(),
                    "case-colliding distribution path"
                );
            }
        }
    }
    Ok(path)
}
pub(crate) fn git_result(anchor: &Path, args: &[&str]) -> Result<crate::runtime::CommandOutput> {
    let mut spec = crate::runtime::CommandSpec::new("git").args(args.iter().copied());
    spec.cwd = Some(anchor.to_owned());
    spec.timeout = Duration::from_secs(20);
    spec.max_output = 8 * 1024 * 1024;
    crate::runtime::run(&spec)
        .context("Git is required to protect detected repository administration")
}
/// Parse the exact rev-parse response, retaining no relative or extra rows.
/// The optional shared-index row is either empty or an absolute path.
pub fn parse_git_paths(raw: &[u8]) -> Result<Vec<PathBuf>> {
    let raw = std::str::from_utf8(raw).context("Git administration paths are not UTF-8")?;
    let values: Vec<_> = raw.lines().collect();
    ensure!(
        (5..=6).contains(&values.len())
            && values[..5]
                .iter()
                .all(|s| !s.is_empty() && Path::new(s).is_absolute())
            && values
                .get(5)
                .is_none_or(|s| s.is_empty() || Path::new(s).is_absolute()),
        "ambiguous Git administration paths"
    );
    Ok(values
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect())
}
/// Protect worktree markers, private/common directories, redirected object/index
/// storage, configured hooks and critical hardlinked files. Discovery fails closed.
pub fn git_paths(anchor: &Path) -> Result<Vec<PathBuf>> {
    let mut anchor = absolute(anchor)?;
    while !anchor.is_dir() {
        anchor = anchor
            .parent()
            .context("no existing distribution ancestor")?
            .to_owned();
    }
    let marker = anchor
        .ancestors()
        .map(|p| p.join(".git"))
        .find(|p| p.exists() || is_link(p).unwrap_or(true));
    let bare = anchor
        .ancestors()
        .any(|p| p.join("HEAD").is_file() && p.join("objects").is_dir());
    let selected = [
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some());
    if marker.is_none() && !bare && !selected {
        return Ok(Vec::new());
    }
    let raw = git_result(
        &anchor,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-dir",
            "--git-common-dir",
            "--git-path",
            "objects",
            "--git-path",
            "hooks",
            "--git-path",
            "index",
            "--shared-index-path",
        ],
    )?;
    ensure!(raw.success(), "cannot resolve Git administration");
    let mut paths = parse_git_paths(&raw.stdout)?;
    // Git can silently walk past a damaged nested repository and discover an
    // ancestor checkout. Such fallback must not turn broken discovery into a
    // smaller protected set.
    let expected = if let Some(selected) = std::env::var_os("GIT_DIR") {
        let selected = PathBuf::from(selected);
        Some(if selected.is_absolute() {
            selected
        } else {
            anchor.join(selected)
        })
    } else if let Some(marker) = &marker {
        if marker.is_dir() {
            Some(marker.clone())
        } else {
            ensure!(
                fs::metadata(marker)?.len() <= 16 * 1024,
                "Git marker exceeds its size limit"
            );
            let text = fs::read_to_string(marker)?;
            let value = text
                .trim_end_matches(['\r', '\n'])
                .strip_prefix("gitdir: ")
                .context("invalid Git worktree marker")?
                .to_owned();
            ensure!(
                !value.is_empty() && !value.contains(['\r', '\n']),
                "ambiguous Git worktree marker"
            );
            let path = PathBuf::from(value);
            Some(if path.is_absolute() {
                path
            } else {
                marker.parent().unwrap().join(path)
            })
        }
    } else {
        None
    };
    if let Some(expected) = expected {
        ensure!(
            fs::canonicalize(expected)? == fs::canonicalize(&paths[0])?,
            "Git administration discovery escaped the detected repository"
        );
    }
    if let Some(marker) = marker {
        paths.push(marker);
    }
    let hooks = git_result(&anchor, &["config", "--path", "--get", "core.hooksPath"])?;
    if hooks.success() {
        let value = String::from_utf8(hooks.stdout)?;
        let value = value.trim_end_matches(['\r', '\n']);
        ensure!(
            !value.is_empty() && !value.contains(['\r', '\n']),
            "ambiguous Git hooks path"
        );
        let path = PathBuf::from(value);
        paths.push(if path.is_absolute() {
            path
        } else {
            anchor.join(path)
        });
    } else {
        ensure!(hooks.code == 1, "cannot resolve configured Git hooks");
    }
    // Include critical files so their hardlink aliases are protected too.
    for root in paths.clone().iter().filter(|p| p.is_dir()) {
        for name in [
            "HEAD",
            "index",
            "config",
            "packed-refs",
            "commondir",
            "gitdir",
        ] {
            paths.push(root.join(name));
        }
    }
    for path in paths.clone() {
        if let Ok(canonical) = fs::canonicalize(&path) {
            paths.push(canonical);
        } else if let Some(parent) = path.parent()
            && let (Ok(parent), Some(name)) = (fs::canonicalize(parent), path.file_name())
        {
            paths.push(parent.join(name));
        }
    }
    Ok(paths)
}
pub fn protected_location(
    destination: &Path,
    repository: &Path,
    source: &Path,
    directory: bool,
) -> Result<PathBuf> {
    let destination = if directory {
        directory_path(destination)?
    } else {
        let dest = absolute(destination)?;
        directory_path(dest.parent().context("destination has no parent")?)?;
        ensure!(!is_link(&dest)?, "distribution output cannot be linked");
        dest
    };
    ensure!(
        destination.parent().is_some(),
        "filesystem root is not a distribution destination"
    );
    ensure!(
        !destination
            .components()
            .any(|p| p.as_os_str().to_string_lossy().eq_ignore_ascii_case(".git")),
        "output overlaps Git administration"
    );
    let mut protected = vec![
        source.to_owned(),
        repository.join("install"),
        repository.join("tools"),
        repository.join("crates"),
    ];
    protected.extend(git_paths(repository)?);
    protected.extend(git_paths(&destination)?);
    for path in protected {
        ensure!(
            !overlaps(&destination, &path),
            "distribution output overlaps source or Git administration"
        );
        if destination.is_file() && path.is_file() {
            ensure!(
                path_object_id(&destination)? != path_object_id(&path)?,
                "distribution output hardlinks protected metadata"
            );
        }
    }
    Ok(destination)
}
pub fn distinct_targets(targets: &[PathBuf]) -> Result<()> {
    let mut seen = HashSet::new();
    for (position, target) in targets.iter().enumerate() {
        ensure!(
            seen.insert(key(target)),
            "duplicate or case-colliding installation targets"
        );
        ensure!(
            targets[..position].iter().all(|p| !overlaps(p, target)),
            "nested installation targets"
        );
        ensure!(
            !target.components().any(|p| {
                let n = p.as_os_str().to_string_lossy();
                n.eq_ignore_ascii_case("skill-backups")
                    || n.starts_with(".revayat-install-")
                    || n.starts_with(".revayat-scientific-stage-")
            }),
            "installation overlaps reserved recovery storage"
        );
    }
    Ok(())
}
