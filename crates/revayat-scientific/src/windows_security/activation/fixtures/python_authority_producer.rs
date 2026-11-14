//! Genuine Python subject owner. Preparation alone never attests native admission/execution.
//! The extra module contains the Rust body; the visible, exactly pinned glue only imports/dispatches.
use super::*;
#[path = "python_authority_sources.rs"]
mod pins;
use crate::windows_security::activation::fixtures::source;
pub use pins::{GLUE_SHA256, check_source_validation};

pub struct CompiledPythonAuthority<'a> {
    loader: &'a CompiledRegistryLoader,
    python: PathBuf,
    image: PathBuf,
    script: PathBuf,
    inputs: Vec<Snapshot>,
}
pub struct HeldPythonAuthority {
    python: PathBuf,
    image: PathBuf,
    script: PathBuf,
    loader: HeldRegistryLoader,
    inputs: Lease<HeldFile>,
}
impl<'a> CompiledPythonAuthority<'a> {
    /// No caller-provided command/source/qualifier or successful closure can seal this token.
    pub fn build(
        tools: &mut DiscoveredRustTools,
        base: &PreparedPythonBase,
        loader: &'a CompiledRegistryLoader,
        run: &str,
        state: &Path,
    ) -> Result<Self> {
        require_runtime(base, run, state)?;
        ensure!(
            loader.python == base.python(),
            "authority loader belongs to another runtime"
        );
        let mut loader_held = loader.hold(base.python())?;
        let mut inputs = Inputs::new();
        let result = (|| {
            pins::check_source_validation()?;
            tools.verify()?;
            let root = state.join("python-authority-rust-build");
            owned::directory(&root)?;
            let body = root.join("python-authority");
            owned::directory(&body)?;
            let folder = body.join("src");
            owned::directory(&folder)?;
            // Preserve the raw crate's fixed relative include; it can resolve only
            // to this new private tree containing the reviewed shared memory/probe sources.
            let shared = root.join("activation-fixture");
            owned::directory(&shared)?;
            let shared = shared.join("src");
            owned::directory(&shared)?;
            let shared = shared.join("native");
            owned::directory(&shared)?;
            pins::body(&mut inputs, &folder)?;
            for name in ["builtins.rs", "stack_probe.rs"] {
                let (text, digest) = source::pinned(name)?;
                let path = source::owned_directory().join(name);
                inputs.open(&path, 65536)?;
                let bytes = Bytes(inputs.bytes(&path)?);
                let actual = std::str::from_utf8(&bytes.0)?.replace("\r\n", "\n");
                ensure!(
                    actual == text.replace("\r\n", "\n")
                        && !actual.contains('\r')
                        && io::digest(actual.as_bytes()) == digest,
                    "authority compiler shared source differs"
                );
                inputs.create(&shared.join(name), actual.as_bytes(), 65536)?;
            }
            let library = python_sdk::qualify(base, &mut inputs)?;
            let runtime = base.python().parent().unwrap();
            let image = runtime.join("DLLs").join("_registry_authority.pyd");
            let script = runtime.join("RegistryAuthorityProbe.py");
            inputs.open(base.python(), 16 * 1024 * 1024)?;
            compile(
                tools,
                &mut inputs,
                &folder,
                &image,
                LinkRole::PythonAuthority(&library),
            )?;
            let bytes = Bytes(inputs.bytes(&image)?);
            image::qualify_python_authority(&bytes.0)?;
            pins::glue(&mut inputs, &script)?;
            inputs.verify()?;
            tools.verify()?;
            let snapshots = inputs.snapshots();
            ensure!(
                snapshots.len() <= 96,
                "authority retained input count exceeds fixed bound"
            );
            Ok(Self {
                loader,
                python: base.python().into(),
                image,
                script,
                inputs: snapshots,
            })
        })();
        let result = inputs.finish(result);
        runtime::with_cleanup(result, loader_held.close())
    }
    pub fn python(&self) -> &Path {
        &self.python
    }
    pub fn image(&self) -> &Path {
        &self.image
    }
    pub fn script(&self) -> &Path {
        &self.script
    }
    /// Public admission is primary-only. Only the Rust body constructs its fixed descendant argv.
    pub fn arguments(&self) -> Result<Vec<String>> {
        fixed_arguments(&self.script)
    }
    pub fn hold(&self, python: &Path) -> Result<HeldPythonAuthority> {
        ensure!(
            python == self.python,
            "Python authority held runtime differs"
        );
        io::no_overrides(&self.python)?;
        io::no_overrides(&self.image)?;
        io::no_overrides(&self.script)?;
        let mut loader = self.loader.hold(python)?;
        let opens = self
            .inputs
            .iter()
            .map(|snapshot| {
                Box::new(move || HeldFile::open(&snapshot.path, snapshot.maximum))
                    as Box<dyn FnOnce() -> Result<HeldFile> + '_>
            })
            .collect();
        let held = lease::acquire(opens, CloseOrder::Reverse, |files| {
            for (file, snapshot) in files.iter_mut().zip(&self.inputs) {
                let bytes = Bytes(file.bytes()?);
                io::require_identity(&bytes.0, snapshot.length, &snapshot.digest)?;
                if file.path() == self.image {
                    image::qualify_python_authority(&bytes.0)?;
                }
            }
            Ok(())
        });
        match held {
            Ok(inputs) => Ok(HeldPythonAuthority {
                python: self.python.clone(),
                image: self.image.clone(),
                script: self.script.clone(),
                loader,
                inputs,
            }),
            Err(primary) => runtime::with_cleanup(Err(primary), loader.close()),
        }
    }
}
fn fixed_arguments(script: &Path) -> Result<Vec<String>> {
    let script = script
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("fixed authority script path is not Unicode"))?;
    Ok(["-I", "-B", "-X", "utf8", script].map(str::to_owned).into())
}
impl HeldPythonAuthority {
    pub fn python(&self) -> &Path {
        &self.python
    }
    pub fn image(&self) -> &Path {
        &self.image
    }
    pub fn script(&self) -> &Path {
        &self.script
    }
    pub fn arguments(&self) -> Result<Vec<String>> {
        fixed_arguments(&self.script)
    }
    pub(crate) fn python_file(&mut self) -> Result<&mut HeldFile> {
        self.inputs
            .resources()
            .iter_mut()
            .find(|file| file.path() == self.python)
            .ok_or_else(|| anyhow::anyhow!("authority selected Python image is not retained"))
    }
    pub fn verify(&mut self) -> Result<()> {
        // Native admission consumes this exact selected image. Require its owned
        // descriptor explicitly, then verify every other source/tool/module pin.
        self.python_file()?.verify()?;
        for file in self.inputs.resources() {
            if file.path() != self.python {
                file.verify()?;
            }
        }
        let image = self
            .inputs
            .resources()
            .iter_mut()
            .find(|file| file.path() == self.image)
            .ok_or_else(|| anyhow::anyhow!("authority module image is not retained"))?;
        let bytes = Bytes(image.bytes()?);
        image::qualify_python_authority(&bytes.0)
    }
    fn retire(&mut self) -> Result<()> {
        let inputs = self.inputs.close();
        runtime::with_cleanup(inputs, self.loader.close())
    }
    /// Consuming close prevents a second call from laundering a first close uncertainty.
    pub fn close(mut self) -> Result<()> {
        self.retire()
    }
}
impl Drop for HeldPythonAuthority {
    fn drop(&mut self) {
        let _ = self.retire();
    }
}
