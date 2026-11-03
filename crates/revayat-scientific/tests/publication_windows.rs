//! Actual Win32 ACL and inherited-temporary ownership regressions.
#![cfg(windows)]
use anyhow::{Context, Result, bail, ensure};
use revayat_scientific::{
    identity::{object_id, path_object_id},
    publication::{Boundary, publish_files, publish_observed},
};
use std::{
    collections::BTreeSet,
    ffi::c_void,
    fs::{self, File, FileTimes},
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr::{null_mut, read_unaligned},
};

#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetNamedSecurityInfoW(
        name: *const u16,
        kind: u32,
        information: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn GetAclInformation(
        acl: *const c_void,
        information: *mut c_void,
        length: u32,
        class: u32,
    ) -> i32;
    fn GetAce(acl: *const c_void, index: u32, ace: *mut *mut c_void) -> i32;
    fn IsValidSid(sid: *const c_void) -> i32;
    fn GetLengthSid(sid: *const c_void) -> u32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        length: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        descriptor: *const c_void,
        present: *mut i32,
        dacl: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    fn SetNamedSecurityInfoW(
        name: *mut u16,
        kind: u32,
        information: u32,
        owner: *const c_void,
        group: *const c_void,
        dacl: *const c_void,
        sacl: *const c_void,
    ) -> u32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}
struct Descriptor(*mut c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: API-owned descriptor is allocated by LocalAlloc, freed once after all borrowed pointers expire.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
#[repr(C)]
#[derive(Default)]
struct AclSizeInformation {
    count: u32,
    used: u32,
    free: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct AceHeader {
    kind: u8,
    flags: u8,
    size: u16,
}
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}
/// Inspect each real DACL access ACE and retain its canonical binary SID.
fn principals(path: &Path) -> Result<BTreeSet<Vec<u8>>> {
    let mut descriptor = null_mut();
    let mut dacl = null_mut();
    // SAFETY: NUL-terminated UTF-16 name and output pointers remain live; descriptor owns returned ACL storage.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            1,
            4,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    ensure!(status == 0, "GetNamedSecurityInfoW failed: {status}");
    let _descriptor = Descriptor(descriptor);
    ensure!(!dacl.is_null(), "file has no explicit bounded DACL");
    let mut info = AclSizeInformation::default();
    // SAFETY: ACL points into the live security descriptor; output matches native ACL_SIZE_INFORMATION layout.
    ensure!(
        unsafe {
            GetAclInformation(
                dacl,
                (&mut info as *mut AclSizeInformation).cast(),
                size_of::<AclSizeInformation>() as u32,
                2,
            )
        } != 0,
        "GetAclInformation failed: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        info.count > 0 && info.count <= 4096,
        "ACL inspection returned no access rules or excessive rules"
    );
    let mut result = BTreeSet::new();
    for index in 0..info.count {
        let mut ace = null_mut();
        // SAFETY: native ACL contains info.count ACEs, index is bounded and pointer output is writable.
        ensure!(
            unsafe { GetAce(dacl, index, &mut ace) } != 0 && !ace.is_null(),
            "GetAce failed"
        );
        // SAFETY: a successful GetAce returns a native ACE with at least ACE_HEADER bytes.
        let header = unsafe { read_unaligned(ace.cast::<AceHeader>()) };
        ensure!(
            header.size as usize >= size_of::<AceHeader>(),
            "truncated ACE header"
        );
        let offset = match header.kind {
            0 | 1 | 9 | 10 => 8,
            5 | 6 | 11 | 12 => {
                ensure!(header.size >= 12, "truncated object ACE");
                // SAFETY: object ACE was checked to contain its flags field.
                let flags = unsafe { read_unaligned(ace.cast::<u8>().add(8).cast::<u32>()) };
                12 + usize::from(flags & 1 != 0) * 16 + usize::from(flags & 2 != 0) * 16
            }
            other => bail!("unsupported DACL access ACE type {other}"),
        };
        ensure!(offset + 8 <= header.size as usize, "truncated ACE SID");
        // SAFETY: checked SID header lies inside the live ACE; IsValidSid checks the native SID layout.
        let sid = unsafe { ace.cast::<u8>().add(offset) };
        ensure!(unsafe { IsValidSid(sid.cast()) } != 0, "invalid ACE SID");
        // SAFETY: IsValidSid accepted the live SID.
        let length = unsafe { GetLengthSid(sid.cast()) } as usize;
        ensure!(
            offset + length <= header.size as usize,
            "SID exceeds ACE storage"
        );
        // SAFETY: exact validated SID range remains in the owned descriptor.
        result.insert(unsafe { std::slice::from_raw_parts(sid, length) }.to_vec());
    }
    ensure!(!result.is_empty(), "ACL inspection returned no principals");
    Ok(result)
}
fn restrict_private_stage(path: &Path) -> Result<()> {
    // Owner Rights grants the current file owner full access, while excluding
    // every principal inherited from the destination directory.
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)".encode_utf16().chain([0]).collect();
    let mut descriptor = null_mut();
    // SAFETY: valid NUL-terminated SDDL and writable descriptor output; allocated result is owned below.
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } != 0,
        "private DACL construction failed: {}",
        std::io::Error::last_os_error()
    );
    let descriptor = Descriptor(descriptor);
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl = null_mut();
    // SAFETY: converted descriptor remains live, native boolean and ACL outputs have correct storage.
    ensure!(
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
            != 0
            && present != 0
            && !dacl.is_null(),
        "private DACL unavailable"
    );
    let mut name = wide(path);
    // SAFETY: NUL-terminated mutable filename and borrowed valid DACL; SetNamedSecurityInfo copies it before return.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_mut_ptr(),
            1,
            4 | 0x8000_0000,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    ensure!(
        status == 0,
        "setting protected private DACL failed: {status}"
    );
    Ok(())
}
#[test]
fn test_publication_inherits_destination_access_instead_of_private_stage() -> Result<()> {
    let work = tempfile::tempdir()?;
    let control = work.path().join("control");
    let output = work.path().join("output");
    fs::write(&control, b"normal inherited access")?;
    let before = principals(&control)?;
    {
        let private = tempfile::tempdir_in(work.path())?;
        let stage = private.path().join("stage");
        fs::write(&stage, b"delivered")?;
        restrict_private_stage(&stage)?;
        let private_principals = principals(&stage)?;
        assert_ne!(
            before, private_principals,
            "fixture stage must carry a genuinely private ACL"
        );
        publish_files(&[(stage, output.clone())], &[], None)?;
    }
    let delivered = principals(&output)?;
    assert!(!before.is_empty());
    assert!(!delivered.is_empty());
    assert_eq!(
        before, delivered,
        "publication lost destination access principals"
    );
    assert_eq!(fs::read(output)?, b"delivered");
    Ok(())
}
#[test]
fn test_inherited_preparation_refuses_substituted_foreign_temporary_files() -> Result<()> {
    for target in [Boundary::InheritedCandidateReady, Boundary::BackupPrepared] {
        let root = tempfile::tempdir()?;
        let stage = root.path().join("stage");
        let destination = root.path().join("dest");
        fs::write(&stage, b"candidate")?;
        fs::write(&destination, b"approved")?;
        let mut changed = None;
        let error = publish_observed(
            &[(stage.clone(), destination.clone())],
            &[],
            None,
            |event, path| {
                if event == target && changed.is_none() {
                    let original = File::open(path)?;
                    let id = object_id(&original)?;
                    let modified = original.metadata()?.modified()?;
                    drop(original);
                    let contents = fs::read(path)?;
                    let foreign = root.path().join("foreign");
                    fs::write(&foreign, &contents)?;
                    File::options()
                        .write(true)
                        .open(&foreign)?
                        .set_times(FileTimes::new().set_modified(modified))?;
                    let foreign_id = path_object_id(&foreign)?;
                    ensure!(
                        id != foreign_id,
                        "test replacement must be a distinct native file object"
                    );
                    fs::rename(&foreign, path)?;
                    changed = Some((path.to_owned(), id, foreign_id, contents));
                }
                Ok(())
            },
        )
        .unwrap_err();
        ensure!(
            error.to_string().contains("ownership"),
            "expected ownership refusal, got {error}"
        );
        let (path, original_id, foreign_id, contents) =
            changed.context("actual inherited preparation seam did not execute")?;
        assert_ne!(original_id, foreign_id);
        assert_eq!(
            path_object_id(&path)?,
            foreign_id,
            "foreign substituted temporary must remain untouched"
        );
        assert_eq!(fs::read(path)?, contents);
        assert_eq!(fs::read(stage)?, b"candidate");
        assert_eq!(fs::read(destination)?, b"approved");
    }
    Ok(())
}
