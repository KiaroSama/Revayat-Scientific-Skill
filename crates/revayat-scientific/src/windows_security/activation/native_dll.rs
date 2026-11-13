//! Actual fixed resource-ID2 file call against a held, bounded, identity-checked module.
//! Its host result is never evidence of original Python, child equivalence, or a reset cache.
use super::*;
use crate::windows_security::{
    activation::dll::{self, DllIo, ManifestIdentity, Outcome},
    image::{PeImage, sha256},
};
use std::sync::atomic::{AtomicBool, Ordering};
static OBSERVED: AtomicBool = AtomicBool::new(false);
struct Held {
    python: File,
    module: File,
    python_id: identity::ObjectId,
    module_id: identity::ObjectId,
    python_length: usize,
    python_digest: String,
}
fn close_file(file: File) -> Result<()> {
    let handle = file.into_raw_handle();
    // SAFETY: one owned File transfers its handle for one explicit close attempt.
    let success = unsafe { CloseHandle(handle) };
    let error = if success == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    ensure!(
        success != 0,
        "fixed DLL held-file close failed winerror={error:?}"
    );
    Ok(())
}
fn finish<T>(operation: Result<T>, errors: Vec<anyhow::Error>) -> Result<T> {
    if errors.is_empty() {
        return operation;
    }
    let mut errors = errors;
    if let Err(error) = operation {
        errors.insert(0, error);
    }
    Err(Failures { errors }.into())
}
fn no_overrides(path: &Path) -> Result<()> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("fixed DLL path is not Unicode"))?;
    for sidecar in [
        std::path::PathBuf::from(format!("{text}.manifest")),
        path.with_extension("manifest"),
        std::path::PathBuf::from(format!("{text}.config")),
        path.with_extension("config"),
    ] {
        // Check the parent first; inspect the sidecar itself without following dangling links.
        existing_plain(
            sidecar
                .parent()
                .ok_or_else(|| anyhow::anyhow!("fixed sidecar parent missing"))?,
        )?;
        match std::fs::symlink_metadata(sidecar) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_failure("sidecar-attributes", error)),
            Ok(_) => anyhow::bail!("fixed DLL external override collision"),
        }
    }
    Ok(())
}
fn open(path: &Path) -> Result<File> {
    existing_plain(path)?;
    OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(path)
        .map_err(|error| io_failure("fixed-dll-open", error))
}
fn read(file: &mut File) -> Result<Vec<u8>> {
    let length = file
        .metadata()
        .map_err(|error| io_failure("fixed-dll-metadata", error))?
        .len();
    ensure!(
        (1..=16_777_216).contains(&length),
        "fixed DLL held input exceeds bound"
    );
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_failure("fixed-dll-seek", error))?;
    let mut bytes = Vec::new();
    let operation = (|| {
        file.take(16_777_217)
            .read_to_end(&mut bytes)
            .map_err(|error| io_failure("fixed-dll-read", error))?;
        ensure!(
            bytes.len() as u64 == length,
            "fixed DLL held input changed or truncated"
        );
        Ok(())
    })();
    if let Err(error) = operation {
        bytes.fill(0);
        return Err(error);
    }
    Ok(bytes)
}
fn manifest(file: &mut File) -> Result<ManifestIdentity> {
    let mut bytes = read(file)?;
    let operation = (|| {
        let image = PeImage::parse(&bytes, 1)?;
        let payload = image.module_manifest(false)?;
        Ok(ManifestIdentity {
            language: payload.language,
            length: payload.bytes.len(),
            image_length: bytes.len(),
            digest: sha256(payload.bytes),
            image_digest: sha256(&bytes),
        })
    })();
    bytes.fill(0);
    operation
}
struct Observation<'a> {
    python: &'a Path,
    path: std::path::PathBuf,
    call: crate::windows_security::activation::FixedPathCall,
    identity: Option<ManifestIdentity>,
    line: Option<String>,
    clock: Instant,
}
impl Observation<'_> {
    fn require(&self, held: &Held) -> Result<()> {
        require_host()?;
        existing_plain(self.python)?;
        existing_plain(&self.path)?;
        no_overrides(self.python)?;
        no_overrides(&self.path)?;
        ensure!(
            identity::object_id(&held.python)? == held.python_id
                && identity::path_object_id(self.python)? == held.python_id
                && identity::object_id(&held.module)? == held.module_id
                && identity::path_object_id(&self.path)? == held.module_id,
            "fixed DLL held object identity changed"
        );
        Ok(())
    }
}
impl DllIo for Observation<'_> {
    type Held = Held;
    fn acquire(&mut self) -> Result<Held> {
        require_host()?;
        no_overrides(self.python)?;
        no_overrides(&self.path)?;
        let mut python = Some(open(self.python)?);
        let mut module = None;
        let operation = (|| {
            module = Some(open(&self.path)?);
            let python_id = identity::object_id(python.as_ref().unwrap())?;
            let module_id = identity::object_id(module.as_ref().unwrap())?;
            let mut bytes = read(python.as_mut().unwrap())?;
            let qualification = PeImage::parse(&bytes, 1).map(|_| (bytes.len(), sha256(&bytes)));
            bytes.fill(0);
            let (python_length, python_digest) = qualification?;
            Ok((python_id, module_id, python_length, python_digest))
        })();
        match operation {
            Ok((python_id, module_id, python_length, python_digest)) => Ok(Held {
                python: python.take().unwrap(),
                module: module.take().unwrap(),
                python_id,
                module_id,
                python_length,
                python_digest,
            }),
            Err(error) => {
                let mut errors = Vec::new();
                if let Some(module) = module
                    && let Err(error) = close_file(module)
                {
                    errors.push(error);
                }
                if let Some(python) = python
                    && let Err(error) = close_file(python)
                {
                    errors.push(error);
                }
                finish(Err(error), errors)
            }
        }
    }
    fn qualify(&mut self, held: &mut Held) -> Result<()> {
        self.require(held)?;
        self.identity = Some(manifest(&mut held.module)?);
        self.require(held)
    }
    fn create(&mut self) -> Result<(usize, u32)> {
        require_host()?;
        let context = self.call.context();
        // SAFETY: exact resource-ID2 ACTCTX and all source backing storage are retained by self.
        let handle = unsafe { CreateActCtxW(&context) };
        let error = if handle as usize == usize::MAX {
            unsafe { GetLastError() }
        } else {
            0
        };
        Ok((handle as usize, error))
    }
    fn release(&mut self, handle: usize) -> Result<()> {
        // SAFETY: execute transfers this one valid context to a single release attempt.
        unsafe { ReleaseActCtx(handle as *mut c_void) };
        Ok(())
    }
    fn readback(&mut self, held: &mut Held) -> Result<()> {
        self.require(held)?;
        let later = manifest(&mut held.module)?;
        dll::require_same(
            self.identity
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("DLL manifest was not qualified"))?,
            &later,
        )?;
        let mut bytes = read(&mut held.python)?;
        let same = bytes.len() == held.python_length && sha256(&bytes) == held.python_digest;
        bytes.fill(0);
        ensure!(same, "fixed DLL containing runtime image changed");
        self.require(held)
    }
    fn close(&mut self, held: Held) -> Result<()> {
        let module = close_file(held.module);
        finish(module, close_file(held.python).err().into_iter().collect())
    }
    fn deadline(&mut self) -> Result<()> {
        super::deadline(self.clock)
    }
    fn emit(&mut self, value: Outcome) -> Result<()> {
        self.line = Some(dll::metadata(
            self.identity
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("DLL manifest identity missing"))?,
            value,
        )?);
        Ok(())
    }
}
#[derive(Debug)]
pub struct DllObservation {
    pub outcome: Outcome,
    pub metadata: String,
}
/// One attempt per controller, from the fixed prepared Python/DLLs/_ctypes.pyd layout only. The
/// operation holds both files and checks complete module manifest and image identities before/after.
/// This owner does not claim the separate historical RegistryLoaderFixture runtime bundle proof.
pub fn observe_fixed_dll(python: &Path) -> Result<DllObservation> {
    let operation = (|| {
        ensure!(
            OBSERVED
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "fixed DLL activation was already attempted"
        );
        super::super::check_startup_activation_validation()?;
        require_host()?;
        ensure!(
            python.is_absolute()
                && python
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case("python.exe")),
            "fixed DLL operation requires prepared Python identity"
        );
        let path = python
            .parent()
            .ok_or_else(|| anyhow::anyhow!("fixed DLL runtime parent missing"))?
            .join("DLLs")
            .join("_ctypes.pyd");
        let call = crate::windows_security::activation::FixedPathCall::new(
            CallRole::HostDll,
            path.to_str()
                .ok_or_else(|| anyhow::anyhow!("fixed DLL source is not Unicode"))?,
            0,
        )?;
        let mut io = Observation {
            python,
            path,
            call,
            identity: None,
            line: None,
            clock: Instant::now(),
        };
        let outcome = dll::execute(&mut io)?;
        Ok(DllObservation {
            outcome,
            metadata: io
                .line
                .ok_or_else(|| anyhow::anyhow!("DLL final metadata was not emitted"))?,
        })
    })();
    operation.map_err(dll::sanitize)
}

/// Run only the fixed sibling Rust explicit-ID2 fixture through the bounded owned-process runtime.
/// A success is latched after natural/process-tree completion, held-image readback, and file close.
pub fn observe_explicit_host_fixture() -> Result<String> {
    use crate::{
        runtime::{self, CommandSpec},
        windows_security::activation::self_result::{self, SelfRole},
    };
    use std::cell::{Cell, RefCell};
    let operation = (|| {
        require_host()?;
        let executable = std::env::current_exe()?;
        let parent = executable
            .parent()
            .ok_or_else(|| anyhow::anyhow!("fixed host controller parent missing"))?;
        let folder = if parent.file_name().is_some_and(|name| name == "deps") {
            parent
                .parent()
                .ok_or_else(|| anyhow::anyhow!("fixed host fixture parent missing"))?
        } else {
            parent
        };
        let path = folder.join("startup-explicit-id2.exe");
        no_overrides(&path)?;
        let file = open(&path)?;
        let held = RefCell::new(Some(file));
        let accepted = Cell::new(false);
        let retained = RefCell::new(None);
        self_result::complete_host(
            SelfRole::ExplicitId2,
            || {
                let mut bytes = read(held.borrow_mut().as_mut().unwrap())?;
                let expected = (bytes.len(), sha256(&bytes));
                let qualification =
                    PeImage::parse(&bytes, 1).and_then(|image| image.qualify_explicit_id2());
                bytes.fill(0);
                qualification?;
                let id = identity::object_id(held.borrow().as_ref().unwrap())?;
                let mut spec = CommandSpec::new(path.as_os_str());
                spec.cwd = Some(folder.to_owned());
                spec.timeout = Duration::from_secs(10);
                spec.max_output = 256;
                let mut output = runtime::run(&spec)?;
                let result = (|| {
                    let text = std::str::from_utf8(&output.stdout)?;
                    let errors = std::str::from_utf8(&output.stderr)?;
                    self_result::policy_result(
                        output.code as u32,
                        text,
                        errors,
                        SelfRole::ExplicitId2,
                        true,
                    )
                })();
                output.stdout.fill(0);
                output.stderr.fill(0);
                let value = result?;
                let mut bytes = read(held.borrow_mut().as_mut().unwrap())?;
                let same = bytes.len() == expected.0 && sha256(&bytes) == expected.1;
                bytes.fill(0);
                ensure!(
                    same && identity::object_id(held.borrow().as_ref().unwrap())? == id
                        && identity::path_object_id(&path)? == id,
                    "fixed host image identity changed"
                );
                *retained.borrow_mut() = Some(value.clone());
                Ok(value)
            },
            || close_file(held.borrow_mut().take().unwrap()),
            || {
                accepted.set(true);
                Ok(())
            },
        )?;
        ensure!(
            accepted.get(),
            "fixed host positive was not accepted after cleanup"
        );
        retained
            .into_inner()
            .ok_or_else(|| anyhow::anyhow!("fixed host completed result missing"))
    })();
    operation.map_err(dll::sanitize)
}
