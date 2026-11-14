//! DefaultActivationFixture.CheckValidation, immutable source lines42–142.
use super::*;
use std::{cell::Cell, fs, sync::Arc};
pub fn check_default_validation(work: &Path) -> Result<()> {
    require_role(true, &[false; 7])?;
    for index in 0..8 {
        let mut role = [false; 7];
        if index > 0 {
            role[index - 1] = true;
        }
        ensure!(
            require_role(index != 0, &role).is_err(),
            "default activation role overlap accepted"
        );
    }
    ensure!(
        resource_script(1033) == "LANGUAGE 9,1\n1 24 \"default-activation-payload.bin\"\n"
            && resource_script(0) == "LANGUAGE 0,0\n1 24 \"default-activation-payload.bin\"\n",
        "default resource language script differs"
    );
    let sdk = work.join("fixed-sdk");
    let library = sdk.join("Lib/10.0.1.0/um/x64/kernel32.lib");
    ensure!(
        resource_compiler(&library)? == sdk.join("bin/10.0.1.0/x64/rc.exe"),
        "fixed resource compiler mapping differs"
    );
    for invalid in [
        library.with_file_name("other.lib"),
        sdk.join("Lib/10.0.1.0/um/x86/kernel32.lib"),
        sdk.join("Lib/unknown/um/x64/kernel32.lib"),
    ] {
        ensure!(
            resource_compiler(&invalid).is_err(),
            "unrelated SDK resource compiler accepted"
        );
    }
    let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    require_identity(b"abc", 3, hash)?;
    ensure!(
        require_identity(b"abc", 4, hash).is_err() && require_identity(b"abd", 3, hash).is_err(),
        "default fixture identity drift accepted"
    );
    ensure!(
        result(0, Some(ENTRY), Some(""))? == "entry_observed=True exit=0x00000000"
            && result(0xc0150002, Some(""), Some(""))? == "entry_observed=False exit=0xC0150002",
        "default entry/exit literal differs"
    );
    for exit in [0, 1, 121, 0x7fffffff, 0xc0000022] {
        for text in [
            "".to_owned(),
            ENTRY.into(),
            "private-sentinel".into(),
            ENTRY.repeat(2),
        ] {
            if exit == 0 && text == ENTRY || exit & 0x80000000 != 0 && text.is_empty() {
                continue;
            }
            ensure!(
                result(exit, Some(&text), Some("")).is_err(),
                "default unrelated entry/exit transport accepted"
            );
        }
    }
    ensure!(
        result(0, Some(ENTRY), Some(" ")).is_err()
            && result(0xc0000022, Some(""), Some("private-sentinel")).is_err(),
        "default stderr accepted"
    );
    ensure!(
        condition("modified", Some(&result(0, Some(ENTRY), Some(""))?))?
            .contains("condition=modified entry_observed=True")
            && condition("original", Some(&result(0xc0000022, Some(""), Some(""))?))?
                .contains("entry_observed=False exit=0xC0000022"),
        "default condition metadata differs"
    );
    for (phase, value) in [
        ("private-sentinel", "entry_observed=True exit=0x00000000"),
        ("original", "private-sentinel"),
        ("original", "entry_observed=False exit=0xc0000022"),
        ("original", "entry_observed=False exit=0x00000079"),
        ("original", "entry_observed=False exit=0xC0000022\n"),
    ] {
        ensure!(
            condition(phase, Some(value)).is_err(),
            "malformed default condition accepted"
        );
    }
    lease::check_default_lease_validation()?;
    let primary = Arc::new(std::io::Error::other("fixed operation"));
    let cleanup = Arc::new(std::io::Error::other("fixed cleanup"));
    let attempts = Cell::new(0);
    #[derive(Debug)]
    struct Id(Arc<std::io::Error>);
    impl std::fmt::Display for Id {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fixed default fixture failure")
        }
    }
    impl std::error::Error for Id {}
    let error = finish(
        Some(Id(primary.clone()).into()),
        vec![
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                Err(Id(cleanup.clone()).into())
            }),
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                Ok(())
            }),
        ],
    )
    .unwrap_err();
    let group = error
        .downcast_ref::<crate::windows_security::activation::Failures>()
        .unwrap();
    ensure!(
        attempts.get() == 2
            && group.errors.len() == 2
            && Arc::ptr_eq(&group.errors[0].downcast_ref::<Id>().unwrap().0, &primary)
            && Arc::ptr_eq(&group.errors[1].downcast_ref::<Id>().unwrap().0, &cleanup),
        "default finish lost ordered failures or cleanup attempt"
    );
    let directory = tempfile::Builder::new()
        .prefix("default-activation-validation-")
        .tempdir_in(work)?;
    let path = directory.path().join("owned.txt");
    io::create(&path, b"unchanged", 65536)?.close()?;
    ensure!(
        io::create(&path, b"replacement", 65536).is_err() && fs::read(&path)? == b"unchanged",
        "default collision changed sentinel"
    );
    let image = directory.path().join("startup-default-activation.exe");
    let sidecar = directory
        .path()
        .join("startup-default-activation.exe.manifest");
    fs::write(&sidecar, b"unchanged")?;
    ensure!(
        io::no_overrides(&image).is_err() && fs::read(&sidecar)? == b"unchanged",
        "default override collision changed sentinel"
    );
    fs::remove_file(&sidecar)?;
    super::super::source::directory_link(&directory.path().join("absent"), &sidecar)?;
    ensure!(
        io::no_overrides(&image).is_err() && crate::identity::is_link(&sidecar)?,
        "default dangling override accepted or changed"
    );
    super::super::source::remove_directory_link(&sidecar)
}
