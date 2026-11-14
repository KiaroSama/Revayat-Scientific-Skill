#[cfg(windows)]
fn assert_directory_inherits_access(path: &Path) -> Result<()> {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr::null_mut};
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetNamedSecurityInfoW(
            name: *const u16, kind: u32, information: u32,
            owner: *mut *mut c_void, group: *mut *mut c_void,
            dacl: *mut *mut c_void, sacl: *mut *mut c_void,
            descriptor: *mut *mut c_void,
        ) -> u32;
        fn GetSecurityDescriptorControl(
            descriptor: *const c_void, control: *mut u16, revision: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }
    struct Descriptor(*mut c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: GetNamedSecurityInfoW allocated this descriptor; free once.
            unsafe { LocalFree(self.0); }
        }
    }
    let name = path.as_os_str().encode_wide().chain([0]).collect::<Vec<_>>();
    let mut descriptor = null_mut();
    // SAFETY: UTF-16 name is terminated and returned descriptor storage is owned.
    let status = unsafe {
        GetNamedSecurityInfoW(name.as_ptr(), 1, 4, null_mut(), null_mut(),
            null_mut(), null_mut(), &mut descriptor)
    };
    anyhow::ensure!(status == 0 && !descriptor.is_null(), "directory DACL query failed: {status}");
    let descriptor = Descriptor(descriptor);
    let (mut control, mut revision) = (0, 0);
    // SAFETY: descriptor remains live, outputs use SECURITY_DESCRIPTOR_CONTROL/DWORD.
    anyhow::ensure!(unsafe {
        GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision)
    } != 0, "directory security control query failed");
    assert_eq!(control & 0x1000, 0, "installed directory must inherit its parent DACL");
    Ok(())
}
