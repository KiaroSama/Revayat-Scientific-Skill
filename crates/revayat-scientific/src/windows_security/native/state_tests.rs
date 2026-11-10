//! Durable profile intent and private state contracts. Native execution is hosted only.
use super::*;

fn native_private_child(parent: &Pin, name: &str, user: &str) -> Result<()> {
    use registry_authority::native::{Attributes, Unicode};
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct IoStatus {
        status: usize,
        information: usize,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            handle: *mut Handle,
            access: u32,
            attributes: *const Attributes,
            io: *mut IoStatus,
            allocation: Handle,
            flags: u32,
            share: u32,
            disposition: u32,
            options: u32,
            ea: Handle,
            ea_length: u32,
        ) -> i32;
    }
    parent.require()?;
    let path = parent.path.join(name);
    let name = wide(name);
    let text = Unicode {
        length: ((name.len() - 1) * 2) as u16,
        maximum: (name.len() * 2) as u16,
        buffer: name.as_ptr(),
    };
    let mut descriptor = Descriptor::new(&private_sddl(user, true)?)?;
    let attributes = Attributes {
        length: size_of::<Attributes>() as u32,
        root: parent.file.as_ref().unwrap().as_raw_handle(),
        name: &text,
        flags: 0x1040,
        descriptor: descriptor.0,
        qos: null_mut(),
    };
    let mut raw = null_mut();
    let mut io = IoStatus {
        status: usize::MAX,
        information: 0,
    };
    let returned = unsafe {
        NtCreateFile(
            &mut raw,
            0x120080,
            &attributes,
            &mut io,
            null_mut(),
            0x80,
            3,
            2,
            0x200021,
            null_mut(),
            0,
        )
    };
    if returned == 0x103 {
        std::process::abort();
    }
    let result = (|| {
        ensure!(
            returned == 0
                && io.status as u32 == 0
                && io.information == 2
                && !raw.is_null()
                && raw as isize != -1,
            "native private child returned={:08X} completed={:08X} information={}",
            returned as u32,
            io.status as u32,
            io.information
        );
        let pin = Pin::open(&path, true)?;
        private(pin.file.as_ref().unwrap(), user, true)
    })();
    let cleanup = if raw.is_null() || raw as isize == -1 || unsafe { CloseHandle(raw) } != 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("native private child handle close failed"))
    };
    finish(finish(result, cleanup), descriptor.close())
}

#[test]
fn original_intent_is_exact_three_utf8_lines_and_run_sid_bound() {
    let run = "0123456789abcdef0123456789abcdef";
    let name = format!("Scientific.Security.{run}");
    let sid = "S-1-15-2-1-2-3-4-5-6-7";
    let text = intent_text(&name, sid).unwrap();
    assert_eq!(text, format!("{name}\n{sid}\nintent\n"));
    require_intent(text.as_bytes(), &name, sid).unwrap();
    for bad in [
        Vec::new(),
        text.replace("intent", "unknown").into_bytes(),
        text.replace(sid, "S-1-15-2-9-2-3-4-5-6-7").into_bytes(),
        [vec![0xef, 0xbb, 0xbf], text.as_bytes().to_vec()].concat(),
        (text.clone() + "extra\n").into_bytes(),
    ] {
        assert!(require_intent(&bad, &name, sid).is_err());
    }
    for bad in [
        "",
        "A123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef0",
        "private-sentinel",
    ] {
        assert!(identifier(bad, 32).is_err());
    }
    assert!(identifier(&"a".repeat(64), 64).is_ok());
    assert!(identifier(&"A".repeat(64), 64).is_err());
    let identity = ObjectId {
        volume: 0x11223344,
        index: 0x0123456789abcdef,
    };
    assert_eq!(identity_text(identity), "0000000011223344:0123456789abcdef");
    assert_eq!(parse_identity(&identity_text(identity)).unwrap(), identity);
    for bad in [
        "0:1",
        "0000000011223344:0123456789ABCDEF",
        "0000000011223344:0123456789abcdefx",
    ] {
        assert!(parse_identity(bad).is_err());
    }
}

#[test]
fn real_private_state_exists_before_worker_and_refuses_tampered_locator_or_receipt() {
    use std::os::windows::fs::OpenOptionsExt;

    let root = tempfile::tempdir().unwrap();
    let mut owner = NativeRunOwner::create(root.path()).unwrap();
    assert_eq!(owner.run_id().len(), 32);
    assert_eq!(owner.recovery_binding().len(), 64);
    assert_eq!(
        owner.state_path().file_name().unwrap(),
        format!("security-windows-{}", owner.run_id()).as_str()
    );
    let args = owner.worker_arguments();
    let view = NativeRunView::from_arguments(&args).unwrap();
    assert_eq!(view.run_id(), owner.run_id());
    assert_eq!(view.state_identity(), owner.state_identity());
    assert_eq!(
        view.profile_name(),
        format!("Scientific.Security.{}", owner.run_id())
    );
    assert_eq!(view.package_sid(), owner.manifest.package);
    assert_eq!(
        fs::read(owner.state_path().join("profile.receipt")).unwrap(),
        intent_text(&view.profile_name(), view.package_sid())
            .unwrap()
            .as_bytes()
    );
    for index in 1..4 {
        let mut wrong = args.clone();
        wrong[index] = "invalid".into();
        assert!(NativeRunView::from_arguments(&wrong).is_err());
    }
    assert!(NativeRunView::from_arguments(&args[..3]).is_err());
    let mut extra = args.clone();
    extra.push("extra".into());
    assert!(NativeRunView::from_arguments(&extra).is_err());
    let receipt = owner.state_path().join("profile.receipt");
    assert!(fs::OpenOptions::new().write(true).open(&receipt).is_err());
    assert!(fs::remove_file(&receipt).is_err());
    for path in [
        owner.state_path().to_owned(),
        owner.state_path().join("owner.json"),
        receipt,
    ] {
        for access in [0x40000, 0x80000] {
            let error = fs::OpenOptions::new()
                .access_mode(access)
                .custom_flags(0x02200000)
                .open(&path)
                .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(5));
        }
    }
    drop(view);
    let state = owner.state_path().to_path_buf();
    owner.close().unwrap();
    assert!(
        state.is_dir(),
        "closing an owner cannot erase unrecovered state"
    );
    drop(owner);
    fs::remove_dir_all(state).unwrap(); // Disposable test state, never a profile was created.
}

#[test]
fn missing_spawn_cannot_recover_or_erase_actual_native_state() {
    let root = tempfile::tempdir().unwrap();
    let owner = NativeRunOwner::create(root.path()).unwrap();
    let state = owner.state_path().to_owned();
    let called = std::cell::Cell::new(false);
    let error = crate::runtime::run_with_recovery(
        &crate::runtime::CommandSpec::new(state.join("missing-worker.exe")),
        owner.recovery_binding(),
        |_| {
            called.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(crate::runtime::is_missing_executable(&error));
    assert!(!called.get() && state.join("profile.receipt").is_file());
    drop(owner);
    assert!(state.join("profile.receipt").is_file());
    fs::remove_dir_all(state).unwrap(); // This test never creates a native profile.
}

#[test]
fn actual_runtime_finalization_recovers_absence_and_flushed_profile_creation_intent() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = NativeRunOwner::create(root.path()).unwrap();
    let state = owner.state_path().to_owned();
    let binding = owner.recovery_binding().to_owned();
    let mut command = crate::runtime::CommandSpec::new(
        PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe"),
    )
    .args(["/d", "/c", "exit", "7"]);
    command.timeout = std::time::Duration::from_secs(5);
    let output =
        crate::runtime::run_with_recovery(&command, &binding, |proof| owner.recover(proof))
            .unwrap();
    assert_eq!(output.code, 7);
    assert!(owner.recovered && state.join("profile.receipt").is_file());
    drop(owner);
    fs::remove_dir_all(state).unwrap();
    let mut owner = NativeRunOwner::create(root.path()).unwrap();
    let state = owner.state_path().to_owned();
    owner.view.begin_profile().unwrap(); // Simulate crash before native result, not a profile creation.
    let binding = owner.recovery_binding().to_owned();
    crate::runtime::run_with_recovery(&command, &binding, |proof| owner.recover(proof)).unwrap();
    assert!(owner.recovered && state.join("profile.receipt").is_file());
    drop(owner);
    fs::remove_dir_all(state).unwrap();
}

#[test]
fn malformed_or_conflicting_profile_phase_retains_private_state() {
    let root = tempfile::tempdir().unwrap();
    let owner = NativeRunOwner::create(root.path()).unwrap();
    owner.view.begin_profile().unwrap();
    owner.view.profile_result(0).unwrap();
    owner.view.profile_result(1).unwrap();
    assert!(owner.view.recovery_disposition().is_err());
    let state = owner.state_path().to_owned();
    drop(owner);
    assert!(state.join("profile.receipt").is_file());
    fs::remove_dir_all(state).unwrap();
}

#[test]
fn private_state_ownership_never_delegates_to_package_or_inherited_acl() {
    let user = "S-1-5-21-1-2-3-500";
    let text = private_sddl(user, true).unwrap();
    assert!(text.starts_with(&format!("O:{user}D:P")));
    assert!(text.contains("(A;OICI;0x001F01FF;;;S-1-5-18)"));
    assert!(text.contains(&format!("(A;OICI;0x001F01FF;;;{user})")));
    assert!(!text.contains("S-1-15-") && !text.contains(";;;WD)") && !text.contains(";;;BA)"));
    assert!(private_sddl("S-1-05-21", true).is_err());
    let root = tempfile::tempdir().unwrap();
    let host = current_user_sid().unwrap();
    let parent = root.path().join("private-parent");
    create_private(&parent, &host).unwrap();
    let policy = (|| {
        let pin = Pin::open(&parent, true)?;
        private(pin.file.as_ref().unwrap(), &host, true)
    })();
    let before = create_private(&parent.join("before-pins"), &host);
    let pins = anchors(&parent.join("during-pins")).unwrap();
    let during = create_private(&parent.join("during-pins"), &host);
    let native = native_private_child(pins.last().unwrap(), "native-pins", &host);
    drop(pins);
    let after = create_private(&parent.join("after-pins"), &host);
    assert!(
        policy.is_ok() && before.is_ok() && during.is_ok() && native.is_ok() && after.is_ok(),
        "private child creation parent_policy={policy:?} before={before:?} during={during:?} native={native:?} after={after:?}"
    );
}

#[test]
fn owned_worker_binds_intent_before_actual_profile_create_and_never_claims_outer_reaping() {
    let source = include_str!("authority.rs");
    let owned = source
        .split_once("fn new_owned(")
        .unwrap()
        .1
        .split_once("fn sid_text")
        .unwrap()
        .0;
    assert!(
        owned.find("view.require()").unwrap() < owned.find("CreateAppContainerProfile(").unwrap()
    );
    assert!(owned.contains("outer_recovery: true"));
    let state = include_str!("state.rs");
    assert!(
        state.find("write_private(\"profile.receipt\"").unwrap() < state.find("Ok(owner)").unwrap()
    );
    let recovery = include_str!("recovery.rs")
        .split_once("pub fn recover_profile(")
        .unwrap()
        .1;
    assert!(
        recovery.find("proof.require_binding(").unwrap()
            < recovery.find("DeleteAppContainerProfile(").unwrap()
    );
    assert!(!state.contains("ReapedProcessTree {") && !recovery.contains("ReapedProcessTree {"));
}
