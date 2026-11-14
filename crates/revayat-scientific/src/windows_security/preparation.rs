//! Runtime preparation and bootstrap operations shared by the controller and its checks.
//!
//! Errors retain their original owners through reporting and recovery. Tree traversal
//! is lazy: a rejected entry is never followed by
//! another producer request.
use std::{
    error::Error,
    fmt,
    fs::{self, Metadata, ReadDir},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

pub type SharedError = Arc<dyn Error + Send + Sync>;
pub type PreparationResult<T> = Result<T, SharedError>;

/// Preserve a reporting error and its shared identity at the anyhow controller boundary.
#[derive(Debug)]
struct ReportingFailure(SharedError);
impl fmt::Display for ReportingFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl Error for ReportingFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
pub fn controller_error(error: SharedError) -> anyhow::Error {
    anyhow::Error::new(ReportingFailure(error))
}

/// Controller diagnostics use stderr so the authority's two-record stdout stays machine readable.
pub fn bootstrap_progress(phase: &str, state: &str, index: i32) -> anyhow::Result<()> {
    write_bootstrap_progress(&mut io::stderr(), phase, state, index).map_err(controller_error)
}

pub fn runtime_progress(phase: &str, state: &str, count: i64) -> anyhow::Result<()> {
    write_preparation_progress(
        &mut |message| {
            let mut log = io::stderr();
            writeln!(log, "{message}").map_err(io_error)?;
            log.flush().map_err(io_error)
        },
        &mut io::stderr(),
        phase,
        state,
        count,
    )
    .map_err(controller_error)
}

#[derive(Debug)]
struct Refusal(&'static str);
impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl Error for Refusal {}
fn refusal(message: &'static str) -> SharedError {
    Arc::new(Refusal(message))
}
fn io_error(error: io::Error) -> SharedError {
    Arc::new(error)
}

#[cfg(windows)]
pub const NEWLINE: &str = "\r\n";
#[cfg(not(windows))]
pub const NEWLINE: &str = "\n";

pub fn write_bootstrap_progress(
    output: &mut impl Write,
    phase: &str,
    state: &str,
    index: i32,
) -> PreparationResult<()> {
    if ![
        "prerequisite",
        "compile",
        "managed",
        "recovery-compile",
        "recovery",
    ]
    .contains(&phase)
        || !["before", "after"].contains(&state)
        || !(0..=64).contains(&index)
    {
        return Err(refusal("Invalid bootstrap progress metadata"));
    }
    write!(
        output,
        "WINDOWS_BOOTSTRAP phase={phase} state={state} index={index}{NEWLINE}"
    )
    .map_err(io_error)?;
    output.flush().map_err(io_error)
}

pub fn invoke_bootstrap_stage<T, E>(
    phase: &str,
    index: i32,
    mut marker: impl FnMut(&str, &str, i32) -> Result<(), E>,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    marker(phase, "before", index)?;
    let value = operation()?;
    marker(phase, "after", index)?;
    Ok(value)
}

/// The portable shared-error checks and the production anyhow controller expose
/// the same retained original cause through the aggregate's standard error chain.
pub trait RecoveryCause: fmt::Debug {
    fn cause(&self) -> &(dyn Error + 'static);
}
impl RecoveryCause for SharedError {
    fn cause(&self) -> &(dyn Error + 'static) {
        self.as_ref()
    }
}
impl RecoveryCause for anyhow::Error {
    fn cause(&self) -> &(dyn Error + 'static) {
        self.as_ref()
    }
}

#[derive(Debug)]
pub struct RecoveryFailure<E: RecoveryCause = SharedError> {
    pub errors: Vec<E>,
}
impl<E: RecoveryCause> fmt::Display for RecoveryFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bootstrap recovery operation/reporting failed")
    }
}
impl<E: RecoveryCause> Error for RecoveryFailure<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.errors.first().map(RecoveryCause::cause)
    }
}

pub fn invoke_bootstrap_recovery<E: RecoveryCause>(
    mut marker: impl FnMut(&str, &str, i32) -> Result<(), E>,
    compile: impl FnOnce() -> Result<(), E>,
    recover: impl FnOnce() -> Result<(), E>,
) -> Result<(), RecoveryFailure<E>> {
    let mut errors = Vec::new();
    let mut mark = |phase, state| {
        if let Err(error) = marker(phase, state, 0) {
            errors.push(error);
        }
    };
    let operation = (|| {
        mark("recovery-compile", "before");
        compile()?;
        mark("recovery-compile", "after");
        mark("recovery", "before");
        recover()?;
        mark("recovery", "after");
        Ok(())
    })();
    if let Err(error) = operation {
        errors.insert(0, error);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(RecoveryFailure { errors })
    }
}

pub fn write_preparation_progress(
    log: &mut impl FnMut(&str) -> PreparationResult<()>,
    output: &mut impl Write,
    phase: &str,
    state: &str,
    count: i64,
) -> PreparationResult<()> {
    if ![
        "leaf-plan",
        "leaf-check",
        "python-dlls",
        "python-lib",
        "powershell-tree",
        "copy-python-leaves",
        "copy-python-trees",
        "copy-powershell",
        "copy-authority",
    ]
    .contains(&phase)
        || !["before", "validated", "copied", "after"].contains(&state)
        || !(0..=i64::from(i32::MAX)).contains(&count)
    {
        return Err(refusal("Invalid runtime preparation progress metadata"));
    }
    log(&format!(
        "runtime preparation phase={phase} state={state} count={count}"
    ))?;
    write!(
        output,
        "WINDOWS_RUNTIME_PREPARATION phase={phase} state={state} count={count}{NEWLINE}"
    )
    .map_err(io_error)?;
    output.flush().map_err(io_error)
}

fn reparse(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

/// Resolve to an absolute path without following any selected link. Retain parent
/// components so an existing protected-path check cannot be bypassed with link/../leaf.
pub fn assert_source_path(path: &Path) -> PreparationResult<()> {
    // GetFullPathNameW (used by absolute on Windows) removes parent components.
    // Inspect the supplied prefixes first so junction/../leaf cannot erase the
    // junction before the reparse check sees it.
    assert_plain_ancestors(path)?;
    let absolute = std::path::absolute(path).map_err(io_error)?;
    if absolute != path {
        assert_plain_ancestors(&absolute)?;
    }
    Ok(())
}
fn assert_plain_ancestors(path: &Path) -> PreparationResult<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if reparse(&metadata) => {
                return Err(refusal(
                    "Prepared copy source or ancestor is a reparse point",
                ));
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct SourceEntry {
    pub path: PathBuf,
    pub is_directory: bool,
    pub is_reparse_point: bool,
}
impl SourceEntry {
    fn read(path: PathBuf) -> PreparationResult<Self> {
        let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
        Ok(Self {
            path,
            is_directory: metadata.is_dir(),
            is_reparse_point: reparse(&metadata),
        })
    }
}

/// No collection, sorting, or lookahead: descend only on the next request.
struct SourceEntries {
    stack: Vec<ReadDir>,
    descend: Option<PathBuf>,
    failed: bool,
}
impl SourceEntries {
    fn new(path: &Path) -> PreparationResult<Self> {
        Ok(Self {
            stack: vec![fs::read_dir(path).map_err(io_error)?],
            descend: None,
            failed: false,
        })
    }
}
impl Iterator for SourceEntries {
    type Item = PreparationResult<SourceEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        if let Some(path) = self.descend.take() {
            match fs::read_dir(path) {
                Ok(entries) => self.stack.push(entries),
                Err(error) => {
                    self.failed = true;
                    return Some(Err(io_error(error)));
                }
            }
        }
        loop {
            match self.stack.last_mut()?.next() {
                Some(Ok(entry)) => {
                    let entry = SourceEntry::read(entry.path());
                    match &entry {
                        Ok(item) if item.is_directory && !item.is_reparse_point => {
                            self.descend = Some(item.path.clone());
                        }
                        Err(_) => self.failed = true,
                        _ => {}
                    }
                    return Some(entry);
                }
                Some(Err(error)) => {
                    self.failed = true;
                    return Some(Err(io_error(error)));
                }
                None => {
                    self.stack.pop();
                }
            }
        }
    }
}

pub fn assert_source_tree_stream<I>(
    path: &Path,
    phase: &str,
    entries: impl FnOnce() -> PreparationResult<I>,
    mut progress: impl FnMut(&str, &str, i64) -> PreparationResult<()>,
) -> PreparationResult<()>
where
    I: IntoIterator<Item = PreparationResult<SourceEntry>>,
{
    progress(phase, "before", 0)?;
    assert_source_path(path)?;
    let mut completed = 0;
    for entry in entries()? {
        if entry?.is_reparse_point {
            return Err(refusal(
                "Prepared runtime copy source contains a reparse point",
            ));
        }
        completed += 1;
        if completed % 256 == 0 {
            progress(phase, "validated", completed)?;
        }
    }
    progress(phase, "after", completed)
}

pub fn assert_source_tree(
    path: &Path,
    phase: &str,
    progress: impl FnMut(&str, &str, i64) -> PreparationResult<()>,
) -> PreparationResult<()> {
    assert_source_tree_stream(path, phase, || SourceEntries::new(path), progress)
}

/// Each value denotes an already completed copy. Directories do not advance the count.
pub fn measure_runtime_copy<E>(
    phase: &str,
    items: impl IntoIterator<Item = Result<SourceEntry, E>>,
    mut progress: impl FnMut(&str, &str, i64) -> Result<(), E>,
) -> Result<(), E> {
    let mut completed = 0;
    for item in items {
        if !item?.is_directory {
            completed += 1;
            if completed % 256 == 0 {
                progress(phase, "copied", completed)?;
            }
        }
    }
    progress(phase, "after", completed)
}

/// Copy a directory under an existing destination, retaining its original basename.
/// Completion progress is fed by successful filesystem copies, never a precomputed plan.
pub fn copy_runtime_tree(
    source: &Path,
    destination: &Path,
    phase: &str,
    progress: impl FnMut(&str, &str, i64) -> PreparationResult<()>,
) -> PreparationResult<()> {
    assert_source_path(source)?;
    assert_source_path(destination)?;
    let name = source
        .file_name()
        .ok_or_else(|| refusal("Runtime source has no directory name"))?;
    let target = destination.join(name);
    assert_source_path(&target)?;
    fs::create_dir(&target).map_err(io_error)?;
    let entries = SourceEntries::new(source)?;
    let copied = entries.map(|entry| {
        let entry = entry?;
        if entry.is_reparse_point {
            return Err(refusal(
                "Prepared runtime copy source contains a reparse point",
            ));
        }
        let relative = entry
            .path
            .strip_prefix(source)
            .map_err(|_| refusal("Runtime copy entry escaped its source"))?;
        let output = target.join(relative);
        assert_source_path(&entry.path)?;
        assert_source_path(&output)?;
        if entry.is_directory {
            fs::create_dir(output).map_err(io_error)?;
        } else {
            fs::copy(&entry.path, output).map_err(io_error)?;
        }
        Ok(entry)
    });
    measure_runtime_copy(phase, copied, progress)
}
