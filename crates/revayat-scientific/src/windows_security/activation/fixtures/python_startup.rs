//! Byte-identical diagnostic clone; this never substitutes for the genuine Python subject.
//! Frozen PythonStartupFixture.cs:12–114, invoked separately at Run-WindowsSecurity.ps1:359.
use super::{
    io::{self, HeldFile},
    lease::{self, CloseOrder, Lease},
    source,
};
use anyhow::{Result, ensure};
use std::{fs, path::Path};

pub use super::super::native_pass::runtime_path as runtime;
const MAXIMUM: usize = 16 * 1024 * 1024;

struct Bytes(Vec<u8>);
impl Drop for Bytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Refuse all executable sidecars and process-local Python path overrides before copying/opening.
pub fn overrides(runtime: &Path) -> Result<()> {
    for image in ["python.exe", "startup-python.exe"] {
        let image = runtime.join(image);
        io::no_overrides(&image)?;
        for extension in ["_pth", "zip"] {
            io::missing(&image.with_extension(extension))?;
        }
    }
    for name in ["pyvenv.cfg", "pybuilddir.txt"] {
        io::missing(&runtime.join(name))?;
    }
    Ok(())
}

fn equal(source: &mut HeldFile, clone: &mut HeldFile) -> Result<()> {
    let expected = Bytes(source.bytes()?);
    let actual = Bytes(clone.bytes()?);
    ensure!(
        expected.0.len() == actual.0.len() && io::digest(&expected.0) == io::digest(&actual.0),
        "fixed Python clone bytes or length differ"
    );
    Ok(())
}

/// Create-new, durable write/readback and reopened comparison while the original remains held.
pub fn prepare(run: &str, state: &Path) -> Result<()> {
    let runtime = runtime(run, state)?;
    let destination = runtime.join("startup-python.exe");
    overrides(&runtime)?;
    io::missing(&destination)?;
    let mut source = HeldFile::open(&runtime.join("python.exe"), MAXIMUM)?;
    let operation = (|| {
        let bytes = Bytes(source.bytes()?);
        // The shared creator owns exclusive create-new, sync_all, exact held-byte readback,
        // explicit writer close and identity-checked read-only reopen.
        let mut clone = io::create(&destination, &bytes.0, MAXIMUM)?;
        let comparison = equal(&mut source, &mut clone);
        crate::runtime::with_cleanup(comparison, clone.close())
    })();
    crate::runtime::with_cleanup(operation, source.close())
}

/// Keep both real images read-only and deny replacement until reverse-order explicit release.
pub fn hold(run: &str, state: &Path) -> Result<Lease<HeldFile>> {
    let runtime = runtime(run, state)?;
    overrides(&runtime)?;
    lease::acquire(
        vec![
            Box::new(|| HeldFile::open(&runtime.join("python.exe"), MAXIMUM)),
            Box::new(|| HeldFile::open(&runtime.join("startup-python.exe"), MAXIMUM)),
        ],
        CloseOrder::Reverse,
        |held| {
            let (source, clone) = held.split_at_mut(1);
            equal(&mut source[0], &mut clone[0])
        },
    )
}

// The original Refuse catches contract failures, not arbitrary filesystem or close failures.
fn refuse(result: Result<()>) -> Result<()> {
    let error = result
        .err()
        .ok_or_else(|| anyhow::anyhow!("fixed Python clone refusal fixture was accepted"))?;
    ensure!(
        error.downcast_ref::<std::io::Error>().is_none()
            && [
                "fixed Python clone bytes or length differ",
                "fixed Python runtime run binding differs",
                "fixed activation output or override already exists",
                "native fixture selected input/ancestor is a reparse point",
            ]
            .contains(&error.to_string().as_str()),
        "Python clone fixture failed outside its expected contract refusal"
    );
    Ok(())
}

fn remove_fixture_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            if crate::identity::is_link(path)? {
                source::remove_directory_link(path)
            } else {
                ensure!(
                    metadata.is_file(),
                    "Python clone cleanup found a foreign directory"
                );
                fs::remove_file(path)?;
                Ok(())
            }
        }
    }
}

/// Original tiny filesystem assertions. Neither the original nor clone is ever executed.
pub fn check_validation(work: &Path) -> Result<()> {
    io::plain(work, false)?;
    let run = "d".repeat(32);
    let state = work.join(format!("security-windows-{run}"));
    io::missing(&state)?;
    // Atomic creation preserves the original absence condition without adopting another tree.
    fs::create_dir(&state)?;
    let runtime = state.join("python");
    let original = runtime.join("python.exe");
    let clone = runtime.join("startup-python.exe");
    let sidecar = runtime.join("startup-python._pth");
    let mut state_id = None;
    let mut runtime_id = None;
    let operation = (|| {
        state_id = Some(crate::identity::path_object_id(&state)?);
        fs::create_dir(&runtime)?;
        runtime_id = Some(crate::identity::path_object_id(&runtime)?);
        let bytes = [0, 1, 2, 127, 128, 255];
        io::create(&original, &bytes, MAXIMUM)?.close()?;
        prepare(&run, &state)?;
        let mut held = hold(&run, &state)?;
        let exact = (|| {
            ensure!(
                fs::read(&original)? == bytes && fs::read(&clone)? == bytes,
                "Python clone changed original or copied bytes"
            );
            let (source_files, clone_files) = held.resources().split_at_mut(1);
            let source_bytes = Bytes(source_files[0].bytes()?);
            let clone_bytes = Bytes(clone_files[0].bytes()?);
            ensure!(
                source_bytes.0.as_slice() == bytes.as_slice()
                    && clone_bytes.0.as_slice() == bytes.as_slice(),
                "Python clone held bytes differ from the original assertion"
            );
            #[cfg(windows)]
            for path in [source_files[0].path(), clone_files[0].path()] {
                use std::os::windows::fs::OpenOptionsExt;
                ensure!(
                    fs::OpenOptions::new()
                        .write(true)
                        .share_mode(3)
                        .open(path)
                        .is_err(),
                    "writer acquired a held Python clone image"
                );
            }
            Ok(())
        })();
        crate::runtime::with_cleanup(exact, held.close())?;
        refuse(prepare(&run, &state))?;
        fs::write(&clone, [0, 1, 2, 127, 128, 254])?;
        refuse(hold(&run, &state).and_then(|mut held| held.close()))?;
        fs::write(&clone, bytes)?;
        io::create(&sidecar, b"fixture", MAXIMUM)?.close()?;
        refuse(hold(&run, &state).and_then(|mut held| held.close()))?;
        ensure!(
            fs::read(&sidecar)? == b"fixture",
            "Python clone deleted an existing override"
        );
        refuse(hold(&"e".repeat(32), &state).and_then(|mut held| held.close()))?;
        fs::remove_file(&sidecar)?;
        fs::remove_file(&clone)?;
        source::directory_link(&runtime.join("absent-owned-fixture"), &clone)?;
        refuse(prepare(&run, &state))?;
        ensure!(
            crate::identity::is_link(&clone)?,
            "Python clone did not preserve dangling-link collision"
        );
        source::remove_directory_link(&clone)
    })();
    let cleanup = (|| {
        io::plain(&state, false)?;
        ensure!(
            state_id == Some(crate::identity::path_object_id(&state)?),
            "Python clone validation state identity changed"
        );
        if runtime_id.is_none() && !runtime.try_exists()? {
            fs::remove_dir(&state)?;
            return Ok(());
        }
        io::plain(&runtime, false)?;
        ensure!(
            runtime_id == Some(crate::identity::path_object_id(&runtime)?),
            "Python clone validation runtime identity changed"
        );
        let files = lease::finish(
            None,
            vec![
                Box::new(|| remove_fixture_file(&sidecar)),
                Box::new(|| remove_fixture_file(&clone)),
                Box::new(|| remove_fixture_file(&original)),
            ],
        );
        // Remove only our now-empty exact directories; unknown children are retained.
        let directories = (|| {
            fs::remove_dir(&runtime)?;
            fs::remove_dir(&state)?;
            Ok(())
        })();
        crate::runtime::with_cleanup(files, directories)
    })();
    crate::runtime::with_cleanup(operation, cleanup)
}
