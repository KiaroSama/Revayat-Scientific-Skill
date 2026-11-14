use super::*;
use std::{cell::RefCell, rc::Rc};
pub fn check_validation(work: &Path) -> Result<()> {
    crate::windows_security::image::check_python_dispatch_identity()?;
    csr::check_python_validation()?;
    identity(work)?;
    let runtime =
        std::env::current_dir()?.join(format!("security-windows-{}/python", "a".repeat(32)));
    let python = runtime.join("python.exe");
    require_path(&python, &python)?;
    require_launch(
        &python,
        Some(&["-I", "-B", "-c", "pass"]),
        &runtime,
        &python,
    )?;
    for path in [
        runtime.join("startup-python.exe"),
        runtime.join("pythonw.exe"),
        runtime.parent().unwrap().join("other/python.exe"),
        PathBuf::from("python.exe"),
    ] {
        ensure!(
            require_path(&path, &python).is_err(),
            "original Python path role changed"
        );
    }
    for (arguments, cwd) in [
        (
            Some(&["-I", "-B", "-c", "private-sentinel"][..]),
            runtime.clone(),
        ),
        (
            Some(&["-I", "-B", "-c", "pass", "extra"][..]),
            runtime.clone(),
        ),
        (None, runtime.clone()),
        (
            Some(&["-I", "-B", "-c", "pass"][..]),
            runtime.parent().unwrap().to_path_buf(),
        ),
    ] {
        let error = require_launch(&python, arguments, &cwd, &python).unwrap_err();
        ensure!(
            !error.to_string().contains("private-sentinel"),
            "Python launch leaked argument"
        );
    }
    let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    require_bytes(b"abc", 3, hash)?;
    ensure!(
        require_bytes(b"abc", 4, hash).is_err()
            && require_bytes(b"abd", 3, hash).is_err()
            && require_bytes(b"", 0, hash).is_err(),
        "Python held bytes length/digest contract differs"
    );
    ensure!(
        host_transport(0, "", "")? == csr::HOST_PASS,
        "Python host transport differs"
    );
    for code in [1, 121, 0xc0150002, u32::MAX] {
        ensure!(
            host_transport(code, "", "").is_err(),
            "Python host positive accepted failed pass"
        );
    }
    ensure!(
        host_transport(0, "private-sentinel", "").is_err()
            && host_transport(0, "", "private-sentinel").is_err(),
        "Python host positive accepted output"
    );
    acquisition()?;
    super::super::launch_roles::check_python_roles()?;
    Ok(())
}
fn acquisition() -> Result<()> {
    for mode in 0..4 {
        let order = Rc::new(RefCell::new(Vec::new()));
        let closed = order.clone();
        let result = pass_resources::acquire(
            3,
            |index| {
                ensure!(mode != 1 || index != 2, "fixed identity");
                Ok(index)
            },
            |values| {
                ensure!(values.len() == 3, "fixed resource count differs");
                ensure!(mode != 2 && mode != 3, "fixed identity");
                Ok(())
            },
            move |index| {
                closed.borrow_mut().push(index);
                ensure!(mode != 3, "fixed close");
                Ok(())
            },
        );
        match result {
            Ok((mut resources, ())) => {
                ensure!(
                    mode == 0 && order.borrow().is_empty(),
                    "premature identity close"
                );
                resources.close()?;
                resources.close()?;
            }
            Err(error) => {
                ensure!(mode != 0, "identity positive refused");
                if mode == 3 {
                    let errors = &error
                        .downcast_ref::<super::super::Failures>()
                        .unwrap()
                        .errors;
                    ensure!(
                        errors.len() == 4 && errors[0].to_string() == "fixed identity",
                        "identity/close failure precedence differs"
                    );
                }
            }
        }
        ensure!(
            order.borrow().as_slice()
                == if mode == 1 {
                    &[1, 0][..]
                } else {
                    &[2, 1, 0][..]
                },
            "identity acquisition reverse cleanup differs"
        );
    }
    Ok(())
}
fn identity(work: &Path) -> Result<()> {
    let owner = tempfile::Builder::new()
        .prefix("python-csr-validation-")
        .tempdir_in(work)?;
    let run = "c".repeat(32);
    let state = owner.path().join(format!("security-windows-{run}"));
    let runtime = state.join("python");
    std::fs::create_dir_all(&runtime)?;
    let python = runtime.join("python.exe");
    let mut bytes = crate::windows_security::image::python_dispatch_validation_fixtures();
    let operation = (|| {
        for (name, data) in IMAGES.into_iter().zip(&bytes) {
            std::fs::write(runtime.join(name), data)?;
        }
        let identity = RuntimeIdentity::capture(&python)?;
        ensure!(
            identity.python == python && identity.language == 1033 && identity.manifest_length == 3,
            "prepared Python identity fields differ"
        );
        let held = identity.hold(&python)?;
        #[cfg(windows)]
        for name in IMAGES {
            use std::os::windows::fs::OpenOptionsExt;
            ensure!(
                OpenOptions::new()
                    .write(true)
                    .share_mode(3)
                    .open(runtime.join(name))
                    .is_err(),
                "writer acquired a held original Python image"
            );
        }
        held.close()?;
        for index in 0..3 {
            let path = runtime.join(IMAGES[index]);
            let mut changed = bytes[index].clone();
            let last = changed.len() - 1;
            changed[last] ^= 1;
            std::fs::write(&path, &changed)?;
            ensure!(
                identity.hold(&python).is_err(),
                "changed held Python image accepted"
            );
            changed.fill(0);
            std::fs::write(path, &bytes[index])?;
        }
        let mut different = bytes[1].clone();
        different[0x580] ^= 1;
        std::fs::write(runtime.join(IMAGES[1]), &different)?;
        ensure!(
            HeldRuntime::acquire(&python, None).is_err(),
            "different default/module manifest accepted during capture"
        );
        different.fill(0);
        std::fs::write(runtime.join(IMAGES[1]), &bytes[1])?;
        for name in [
            "python.exe.config",
            "python311.dll.manifest",
            "vcruntime140.dll.config",
            "python._pth",
            "python311._pth",
            "pyvenv.cfg",
        ] {
            let sidecar = runtime.join(name);
            std::fs::write(&sidecar, b"unchanged")?;
            ensure!(
                identity.hold(&python).is_err() && std::fs::read(&sidecar)? == b"unchanged",
                "Python sidecar was accepted or mutated"
            );
            std::fs::remove_file(sidecar)?;
        }
        ensure!(
            runtime_path(&run, &state)? == runtime
                && runtime_path(&"d".repeat(32), &state).is_err(),
            "Python owned run binding differs"
        );
        identity.hold(&python)?.close()?;
        Ok(())
    })();
    for data in &mut bytes {
        data.fill(0);
    }
    ensure!(
        bytes.iter().all(|data| data.iter().all(|v| *v == 0)),
        "Python fixture buffers not cleared"
    );
    operation
}
