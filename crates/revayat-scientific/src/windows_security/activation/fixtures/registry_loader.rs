//! The direct registry-loader fixture validator and retained prebuilt bundle ownership.
//! Capturing these bytes does not claim a compiler run, helper execution or LPAC admission.
use super::{
    child,
    io::{self, HeldFile},
    lease::{self, CloseOrder, Lease, Resource},
    prepared::Snapshot,
};
use crate::windows_security::{
    activation::native_pass::{HeldRuntime, RuntimeIdentity},
    image,
};
use anyhow::{Result, ensure};
use std::path::{Component, Path};
pub const NAMES: [&str; 3] = ["_registry_loader.pyd", "_ctypes.pyd", "libffi-8.dll"];
fn canonical(path: &str) -> bool {
    let native = Path::new(path);
    if native.is_absolute() {
        return native
            .components()
            .collect::<std::path::PathBuf>()
            .as_os_str()
            == native.as_os_str()
            && !native
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir));
    }
    let bytes = path.as_bytes();
    let rooted = bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1..3] == *b":\\";
    let tail = if rooted {
        &path[3..]
    } else if let Some(tail) = path.strip_prefix("\\\\") {
        if tail.split('\\').count() < 3 {
            return false;
        }
        tail
    } else {
        return false;
    };
    !path.contains('/')
        && tail
            .split('\\')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
/// Rust source-format counterpart of the original numeric wchar_t header.
pub fn header(path: &str) -> Result<String> {
    let units = path.encode_utf16().collect::<Vec<_>>();
    ensure!(
        canonical(path) && units.len() < 512 && !units.contains(&0),
        "fixed registry loader header path differs"
    );
    Ok(format!(
        "pub static REGISTRY_LOADER_PATH: &[u16] = &[{}];\n",
        child::numeric(&units)?
    ))
}
struct Prepared {
    runtime: RuntimeIdentity,
    images: [Snapshot; 3],
}
#[derive(Default)]
pub struct RegistryLoader {
    prepared: Option<Prepared>,
}
enum Held {
    Runtime(Option<HeldRuntime>),
    Image(HeldFile),
}
impl Resource for Held {
    fn close(&mut self) -> Result<()> {
        match self {
            Self::Runtime(held) => held.take().map_or(Ok(()), HeldRuntime::close),
            Self::Image(held) => held.close(),
        }
    }
}
pub struct HeldRegistryLoader {
    held: Lease<Held>,
}
impl HeldRegistryLoader {
    pub fn close(&mut self) -> Result<()> {
        self.held.close()
    }
}
impl RegistryLoader {
    /// Record a genuinely held, already compiled bundle. The original compiler/SDK build step
    /// remains a separate producer; this API does not substitute synthetic bytes for that step.
    pub fn capture_prebuilt(&mut self, runtime: &RuntimeIdentity) -> Result<()> {
        ensure!(self.prepared.is_none(), "registry loader already prepared");
        let mut runtime_held = Some(runtime.hold(runtime.python())?);
        let directory = runtime.python().parent().unwrap().join("DLLs");
        if let Err(primary) = io::no_overrides(&directory.join(NAMES[0])) {
            return crate::runtime::with_cleanup(
                Err(primary),
                runtime_held.take().unwrap().close(),
            );
        }
        let opens = NAMES
            .iter()
            .map(|name| {
                let path = directory.join(name);
                Box::new(move || HeldFile::open(&path, 16_777_216))
                    as Box<dyn FnOnce() -> Result<HeldFile>>
            })
            .collect();
        let mut images = None;
        let captured = lease::acquire(opens, CloseOrder::Reverse, |held| {
            let mut snapshots = Vec::new();
            for (index, held) in held.iter_mut().enumerate() {
                let mut bytes = held.bytes()?;
                let result = if index == 0 {
                    image::qualify_registry_loader(&bytes)
                } else {
                    Ok(())
                };
                bytes.fill(0);
                result?;
                snapshots.push(Snapshot::capture(held, 16_777_216)?);
            }
            images = Some(
                snapshots
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("registry loader image count differs"))?,
            );
            Ok(())
        });
        let captured = match captured {
            Ok(mut held) => held.close(),
            Err(error) => Err(error),
        };
        let closed = runtime_held.take().unwrap().close();
        crate::runtime::with_cleanup(captured, closed)?;
        self.prepared = Some(Prepared {
            runtime: runtime.clone(),
            images: images.unwrap(),
        });
        Ok(())
    }
    pub fn hold(&self, python: &Path) -> Result<HeldRegistryLoader> {
        let prepared = self
            .prepared
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("registry loader is not prepared"))?;
        ensure!(
            python == prepared.runtime.python(),
            "registry loader runtime differs"
        );
        let mut opens: Vec<Box<dyn FnOnce() -> Result<Held> + '_>> = vec![Box::new(|| {
            prepared
                .runtime
                .hold(python)
                .map(|held| Held::Runtime(Some(held)))
        })];
        for image in &prepared.images {
            opens.push(Box::new(|| {
                HeldFile::open(&image.path, image.maximum).map(Held::Image)
            }));
        }
        let held = lease::acquire(opens, CloseOrder::Reverse, |held| {
            ensure!(held.len() == 4, "registry loader held input count differs");
            for (index, image) in prepared.images.iter().enumerate() {
                let Held::Image(held) = &mut held[index + 1] else {
                    anyhow::bail!("registry loader held image kind differs")
                };
                let mut bytes = held.bytes()?;
                let result: Result<()> = (|| {
                    io::require_identity(&bytes, image.length, &image.digest)?;
                    if index == 0 {
                        image::qualify_registry_loader(&bytes)?;
                    }
                    Ok(())
                })();
                bytes.fill(0);
                result?;
            }
            Ok(())
        })?;
        Ok(HeldRegistryLoader { held })
    }
}
/// Complete frozen direct RegistryLoaderFixture.CheckValidation assertions.
pub fn check_validation() -> Result<()> {
    image::check_registry_loader_validation()?;
    ensure!(
        header(r"C:\owned space\python\DLLs\_ctypes.pyd")?.starts_with(
            "pub static REGISTRY_LOADER_PATH: &[u16] = &[67,58,92,111,119,110,101,100,32"
        ),
        "registry loader numeric UTF-16 header differs"
    );
    let fixture = RegistryLoader::default();
    ensure!(
        fixture.prepared.is_none(),
        "registry loader validation found prepared state"
    );
    Ok(())
}
