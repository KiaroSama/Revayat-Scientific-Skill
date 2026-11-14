//! Actual hosted full CPython3.11 source; the independent std-ID2 control is never selected.
use super::*;
use crate::{
    identity::{self, Fingerprint},
    windows_security::{
        activation::native_pass::{self, PreparedRuntime},
        image::PeImage,
        preparation,
    },
};
#[path = "python_copy.rs"]
mod copy;
pub struct PythonProvenance {
    pub provider: &'static str,
    pub version: String,
    pub images: [(PathBuf, Fingerprint); 3],
}
pub struct DiscoveredPythonBase {
    python: PathBuf,
    pins: Pins,
    provenance: PythonProvenance,
}
pub struct PreparedPythonBase {
    runtime: PreparedRuntime,
    provenance: PythonProvenance,
}
impl PreparedPythonBase {
    pub fn runtime(&self) -> &PreparedRuntime {
        &self.runtime
    }
    pub fn runtime_mut(&mut self) -> &mut PreparedRuntime {
        &mut self.runtime
    }
    pub fn provenance(&self) -> &PythonProvenance {
        &self.provenance
    }
    pub fn python(&self) -> &Path {
        self.runtime.identity().python()
    }
}
impl DiscoveredPythonBase {
    pub fn python(&self) -> &Path {
        &self.python
    }
    pub fn provenance(&self) -> &PythonProvenance {
        &self.provenance
    }
    pub fn close(mut self) -> Result<()> {
        self.pins.close()
    }
    pub fn discover(state: &Path) -> Result<Self> {
        let mut pins = Pins::new();
        let result = (|| {
            crate::windows_security::activation::native::require_host()?;
            let state = pins.path(state)?;
            let system = pins.path(&windows::system_root()?)?;
            let (provider, candidate) = candidate(&mut pins)?;
            let python = pins.file(&candidate)?;
            let root = python.parent().unwrap();
            for folder in [root.join("Lib"), root.join("DLLs")] {
                let folder = pins.path(&folder)?;
                ensure!(folder.is_dir(), "full Python base directory is missing");
            }
            for name in ["Lib/os.py", "Lib/site.py", "Lib/encodings/__init__.py"] {
                pins.file(&root.join(name))?;
            }
            super::super::python_startup::overrides(root)?;
            io::missing(&root.join("python311._pth"))?;
            io::missing(&root.parent().unwrap().join("pyvenv.cfg"))?;
            let mut buffers = Vec::new();
            let qualify = (|| {
                for (name, role) in
                    native_pass::IMAGES
                        .into_iter()
                        .zip(["python-exe", "python311", "vcruntime140"])
                {
                    let image = pins.file(&root.join(name))?;
                    io::no_overrides(&image)?;
                    buffers.push(pins.read(&image, 16 * 1024 * 1024)?);
                    PeImage::parse(buffers.last().unwrap(), 1)?.qualify_python_imports(role)?;
                }
                let exe = PeImage::parse(&buffers[0], 1)?;
                let exe = exe.manifest(1, false)?;
                let dll = PeImage::parse(&buffers[1], 1)?;
                let dll = dll.module_manifest(false)?;
                ensure!(
                    exe.language == dll.language && exe.bytes == dll.bytes,
                    "actual Python3.11 default/module manifest differs"
                );
                Ok::<_, anyhow::Error>(())
            })();
            for bytes in &mut buffers {
                bytes.fill(0)
            }
            qualify?;
            let version = command(&python, &["--version".into()], &state, &system, &[])?;
            let version = version
                .trim()
                .strip_prefix("Python ")
                .ok_or_else(|| anyhow::anyhow!("actual interpreter version response differs"))?;
            let parsed = super::version(version)?;
            ensure!(
                parsed[0] == 3 && parsed[1] == 11 && version.split('.').count() == 3,
                "prepared interpreter is not actual Python3.11"
            );
            let mut images = Vec::new();
            for name in native_pass::IMAGES {
                let path = root.join(name);
                images.push((path.clone(), pins.fingerprint(&path)?));
            }
            pins.verify()?;
            Ok((
                python,
                PythonProvenance {
                    provider,
                    version: version.into(),
                    images: images
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Python source image count differs"))?,
                },
            ))
        })()
        .context("full hosted Python3.11 discovery failed; private_cause_retained=True");
        match result {
            Ok((python, provenance)) => Ok(Self {
                python,
                pins,
                provenance,
            }),
            Err(error) => runtime::with_cleanup(Err(error), pins.close()),
        }
    }
    /// The caller owns the fresh security-windows-<run> state and seals its tree
    /// read-only before any subject is resumed. Partial output remains owned by that caller.
    pub fn provision(mut self, run: &str, state: &Path) -> Result<PreparedPythonBase> {
        let result = self
            .copy(run, state)
            .context("full Python3.11 preparation failed; private_cause_retained=True");
        runtime::with_cleanup(result, self.pins.close())
    }
    fn copy(&mut self, run: &str, state: &Path) -> Result<PreparedPythonBase> {
        self.pins.verify()?;
        let state = self.pins.path(state)?;
        let destination = native_pass::runtime_path(run, &state)?;
        io::missing(&destination)?;
        fs::create_dir(&destination)?;
        let source = self.python.parent().unwrap();
        preparation::runtime_progress("leaf-plan", "before", 0)?;
        let mut leaves = vec![self.python.clone()];
        // Match the immutable original leaf plan before qualifying entries:
        // hosted python3.exe is an excluded alias, not a selected copy input.
        let mut scanned = 0;
        for entry in fs::read_dir(source)? {
            scanned += 1;
            ensure!(scanned <= 256, "full Python root entry count exceeds bound");
            let path = entry?.path();
            if path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| {
                    ["dll", "zip", "_pth"]
                        .iter()
                        .any(|expected| extension.eq_ignore_ascii_case(expected))
                })
            {
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.is_dir() {
                    continue;
                }
                io::plain(&path, false)?;
                ensure!(metadata.is_file(), "selected Python leaf is not a file");
                leaves.push(path);
            }
        }
        leaves.sort();
        leaves.dedup();
        preparation::runtime_progress("leaf-plan", "after", leaves.len() as i64)?;
        preparation::runtime_progress("leaf-check", "before", 0)?;
        for path in &leaves {
            preparation::assert_source_path(path).map_err(preparation::controller_error)?;
        }
        preparation::runtime_progress("leaf-check", "after", leaves.len() as i64)?;
        for (name, phase) in [("DLLs", "python-dlls"), ("Lib", "python-lib")] {
            copy::validate(&source.join(name), phase)?;
        }
        let mut budget = copy::Budget::new();
        preparation::runtime_progress("copy-python-leaves", "before", 0)?;
        for path in leaves {
            budget.copy_file(&path, &destination.join(path.file_name().unwrap()))?;
        }
        preparation::runtime_progress("copy-python-leaves", "after", budget.count())?;
        preparation::runtime_progress("copy-python-trees", "before", 0)?;
        for name in ["DLLs", "Lib"] {
            budget.tree(&source.join(name), &destination.join(name))?;
        }
        preparation::runtime_progress("copy-python-trees", "after", budget.count())?;
        for (source, expected) in &self.provenance.images {
            let copied = identity::file_identity(
                &destination.join(source.file_name().unwrap()),
                Some(16 * 1024 * 1024),
            )?;
            ensure!(
                copied.same_bytes(expected),
                "copied Python subject differs from held actual source"
            );
        }
        self.pins.verify()?;
        let runtime = PreparedRuntime::prepare(run, &state)?;
        // Never start the prepared subject here: even a version request would
        // run it ahead of the frozen cache-sensitive diagnostic order. Its
        // version follows from exact held-source/copy bytes, independently
        // requalified above; real execution belongs to the native coordinator.
        Ok(PreparedPythonBase {
            runtime,
            provenance: PythonProvenance {
                provider: self.provenance.provider,
                version: self.provenance.version.clone(),
                images: self.provenance.images.clone(),
            },
        })
    }
}
fn candidate(pins: &mut Pins) -> Result<(&'static str, PathBuf)> {
    if let Some(home) = std::env::var_os("pythonLocation") {
        let root = pins.path(Path::new(&home))?;
        // setup-python's selected version must genuinely be3.11; admission below
        // verifies the executable/DLL import roles, manifests and actual version.
        let version = root
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .and_then(|name| super::version(name).ok());
        if version.is_some_and(|value| value[0] == 3 && value[1] == 11) {
            return Ok(("setup-python", root.join("python.exe")));
        }
    }
    let cache = std::env::var_os("RUNNER_TOOL_CACHE")
        .ok_or_else(|| anyhow::anyhow!("full hosted Python3.11 provider is unavailable"))?;
    let root = pins.path(&PathBuf::from(cache).join("Python"))?;
    let mut selected = Vec::new();
    for path in super::entries(&root, 64)? {
        let Some(version) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| super::version(name).ok())
        else {
            continue;
        };
        if version[0] == 3 && version[1] == 11 && path.is_dir() {
            let image = path.join("x64").join("python.exe");
            io::plain(&image, true)?;
            if image.try_exists()? {
                selected.push((version, image));
            }
        }
    }
    selected.sort_by_key(|value| std::cmp::Reverse(value.0));
    ensure!(
        !selected.is_empty(),
        "full hosted Python3.11 provider is unavailable"
    );
    if selected.len() > 1 {
        ensure!(
            selected[0].0 != selected[1].0,
            "hosted Python3.11 source selection is ambiguous"
        );
    }
    Ok(("hosted-toolcache", selected.remove(0).1))
}
