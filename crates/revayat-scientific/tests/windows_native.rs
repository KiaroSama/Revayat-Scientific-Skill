//! Required native Windows gate. This target contains no ignored or opt-in cases.
#![cfg(windows)]
use revayat_scientific::windows_security::native::{
    process_exited, protect_scratch, run_registry_authority, spawn_owned,
};
use revayat_scientific::windows_security::{JobLimits, plain_path};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
#[path = "support/windows_junction.rs"]
mod windows_junction;

fn authority_image() -> PathBuf {
    let executable = std::env::current_exe().unwrap();
    let target = revayat_scientific::executable_paths::binary_directory(&executable)
        .unwrap()
        .join("registry-authority.exe");
    assert!(
        target.is_file(),
        "required native authority is missing; build the complete workspace before tests"
    );
    target
}

#[test]
fn actual_lpac_primary_and_descendant_attest_registry_and_token_controls() {
    let proof = run_registry_authority(&authority_image())
        .expect("native LPAC containment gate must attest both process generations");
    let rows = proof.lines().collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    assert!(rows[0].contains("\"role\":\"primary\""));
    assert!(rows[1].contains("\"role\":\"descendant\""));
    for row in rows {
        assert!(row.contains("\"scope\":\"owned-fixture\""));
        assert!(row.contains("\"network_denied\":true"));
        assert!(row.contains("\"scratch_write\":true"));
        assert!(row.contains("\"accessible\":0,"));
        assert!(row.contains("\"capabilities\":0,"));
        assert!(row.contains("\"lpac\":true,"));
    }
}

#[test]
fn host_process_cannot_substitute_for_native_lpac_authority() {
    let output = Command::new(authority_image())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.len() <= 512);
    assert!(
        output
            .stderr
            .starts_with(b"REGISTRY_AUTHORITY_FAILURE role=primary ")
    );
}

#[test]
fn job_owned_native_child_returns_exact_oracle_bytes() {
    let mut command = Command::new(authority_image());
    command
        .arg("--oracle")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (child, mut owner) = spawn_owned(&mut command, JobLimits::default()).unwrap();
    let output = child.wait_with_output().unwrap();
    owner.finish().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        registry_authority::oracle::generate().as_bytes()
    );
}

#[test]
fn actual_process_lifetime_observer_does_not_report_live_host_as_reaped() {
    assert!(!process_exited(std::process::id()).unwrap());
    assert!(process_exited(0).is_err());
}

#[test]
fn actual_reparse_ancestor_is_refused_before_file_access() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("sentinel"), b"outside").unwrap();
    let link = directory.path().join("junction");
    windows_junction::create(&link, &target).unwrap();
    assert!(plain_path(&link.join("sentinel")).is_err());
    assert_eq!(std::fs::read(target.join("sentinel")).unwrap(), b"outside");
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetFileSecurityW(
        path: *const u16,
        information: u32,
        descriptor: *mut c_void,
        capacity: u32,
        needed: *mut u32,
    ) -> i32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor: *const c_void,
        revision: u32,
        information: u32,
        text: *mut *mut u16,
        size: *mut u32,
    ) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

#[test]
fn actual_scratch_acl_is_protected_and_has_only_concrete_package_grant() {
    let directory = tempfile::tempdir().unwrap();
    let sid = "S-1-15-2-1-2-3-4-5-6-7";
    protect_scratch(directory.path(), sid).unwrap();
    let path = directory
        .path()
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut needed = 0;
    // SAFETY: size-only query; native API writes only the required-size scalar.
    unsafe { GetFileSecurityW(path.as_ptr(), 0x14, std::ptr::null_mut(), 0, &mut needed) };
    assert!((20..=65536).contains(&needed));
    let mut descriptor = vec![0u32; (needed as usize).div_ceil(4)];
    // SAFETY: aligned allocation spans exactly the requested native capacity.
    assert_ne!(
        unsafe {
            GetFileSecurityW(
                path.as_ptr(),
                0x14,
                descriptor.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        },
        0
    );
    let mut text = std::ptr::null_mut();
    let mut size = 0;
    // SAFETY: validated native descriptor remains live; output allocation released below.
    assert_ne!(
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.as_ptr().cast(),
                1,
                0x14,
                &mut text,
                &mut size,
            )
        },
        0
    );
    assert!((1..=4096).contains(&size));
    let sddl =
        String::from_utf16(unsafe { std::slice::from_raw_parts(text, size as usize - 1) }).unwrap();
    assert!(unsafe { LocalFree(text.cast()) }.is_null());
    assert!(sddl.starts_with("D:P"));
    assert!(sddl.contains(sid));
    assert!(!sddl.contains(";;;WD)"));
    assert!(!sddl.contains(";;;AC)"));
    assert!(sddl.contains(";;;LW)"));
}
