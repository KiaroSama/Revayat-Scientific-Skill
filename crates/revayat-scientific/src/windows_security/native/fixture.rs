//! Fresh per-run HKCU registry fixture; never changes a machine or existing key.
use super::authority::{Descriptor, wide};
use super::*;
#[path = "registry_policy.rs"]
mod registry_policy;
pub(super) use registry_policy::{
    identity_label as registry_identity, preserved as registry_preserved,
};

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegCreateKeyExW(
        parent: Handle,
        name: *const u16,
        reserved: u32,
        class: *const u16,
        options: u32,
        access: u32,
        security: Handle,
        result: *mut Handle,
        disposition: *mut u32,
    ) -> i32;
    fn RegCloseKey(key: Handle) -> i32;
    fn RegDeleteTreeW(key: Handle, name: *const u16) -> i32;
    fn GetSecurityDescriptorDacl(
        descriptor: Handle,
        present: *mut i32,
        acl: *mut Handle,
        defaulted: *mut i32,
    ) -> i32;
    fn SetSecurityInfo(
        object: Handle,
        kind: i32,
        information: u32,
        owner: Handle,
        group: Handle,
        dacl: Handle,
        sacl: Handle,
    ) -> u32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtDeleteKey(key: Handle) -> i32;
}

pub(super) struct RegistryFixture {
    root: Handle,
    pub name: String,
}
impl RegistryFixture {
    pub fn new(package: &str) -> Result<Self> {
        crate::windows_security::package_sid(package)?;
        let mut random = [0u8; 16];
        // SAFETY: exact writable nonce buffer, system RNG provider.
        ensure!(
            unsafe {
                registry_authority::native::BCryptGenRandom(null_mut(), random.as_mut_ptr(), 16, 2)
            } == 0,
            "registry fixture nonce"
        );
        let nonce = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        random.fill(0);
        let path = wide(format!("Software\\RevayatNativeAuthority-{nonce}"));
        let mut root = null_mut();
        let mut disposition = 0;
        let hkcu = (0x8000_0001u32 as i32 as isize) as Handle;
        // SAFETY: borrowed predefined HKCU; fresh unpredictable create-only key,
        // returned native key immediately owned. Existing collisions are refused.
        let status = unsafe {
            RegCreateKeyExW(
                hkcu,
                path.as_ptr(),
                0,
                null(),
                0,
                0xf003f,
                null_mut(),
                &mut root,
                &mut disposition,
            )
        };
        ensure!(
            status == 0 && !root.is_null(),
            "create owned registry fixture"
        );
        if disposition != 1 {
            unsafe { RegCloseKey(root) };
            anyhow::bail!("registry fixture already exists");
        }
        let mut owner = Self {
            root,
            name: String::new(),
        };
        owner.name = owner.native_name()?;
        ensure!(
            registry_authority::protocol::fixture_name(&owner.name),
            "owned registry fixture identity mismatch"
        );
        let private = wide("private-child");
        let mut child = null_mut();
        let mut child_disposition = 0;
        let created = unsafe {
            RegCreateKeyExW(
                root,
                private.as_ptr(),
                0,
                null(),
                0,
                0xf003f,
                null_mut(),
                &mut child,
                &mut child_disposition,
            )
        };
        if created != 0 || child.is_null() {
            anyhow::bail!("create owned private registry child");
        }
        let protected = apply_registry_acl(
            child,
            &format!("D:P(D;;KA;;;{package})(A;;KA;;;SY)(A;;KA;;;OW)"),
        );
        let closed = unsafe { RegCloseKey(child) };
        protected?;
        ensure!(
            closed == 0 && child_disposition == 1,
            "private registry child cleanup"
        );
        apply_registry_acl(
            root,
            &format!("D:P(D;;0xd0006;;;{package})(A;;KA;;;SY)(A;;KA;;;OW)(A;;KR;;;{package})"),
        )?;
        Ok(owner)
    }
    #[cfg(test)]
    pub(super) fn retained_root(&self) -> Handle {
        self.root
    }
    fn native_name(&self) -> Result<String> {
        let mut data = [0u64; 512];
        let mut returned = 0;
        // SAFETY: retained owned registry handle, aligned native output buffer.
        let status = unsafe {
            registry_authority::native::NtQueryKey(
                self.root,
                3,
                data.as_mut_ptr().cast(),
                4096,
                &mut returned,
            )
        };
        ensure!(
            status == 0 && (4..=4096).contains(&returned),
            "query owned fixture name"
        );
        let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), 4096) };
        let count = u32::from_le_bytes(bytes[..4].try_into()?) as usize;
        registry_authority::protocol::identity(0, returned as usize, bytes, count)
            .map_err(|_| anyhow::anyhow!("invalid fixture key identity"))
    }
    pub fn close(&mut self) -> Result<()> {
        if self.root.is_null() {
            return Ok(());
        }
        if !self.name.is_empty() {
            ensure!(
                self.native_name()?.eq_ignore_ascii_case(&self.name),
                "registry fixture identity changed"
            );
        }
        // Delete by retained object handle. Never reopen an untrusted pathname.
        let contents = unsafe { RegDeleteTreeW(self.root, null()) };
        let deleted = unsafe { NtDeleteKey(self.root) };
        let root = std::mem::replace(&mut self.root, null_mut());
        let closed = unsafe { RegCloseKey(root) };
        ensure!(
            contents == 0 && deleted == 0 && closed == 0,
            "owned registry fixture cleanup failed"
        );
        Ok(())
    }
}
impl Drop for RegistryFixture {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn apply_registry_acl(key: Handle, sddl: &str) -> Result<()> {
    let mut before = registry_policy::identity_label(key)?;
    let mut descriptor = Descriptor::new(sddl)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = null_mut();
    // SAFETY: live parsed native descriptor with output pointers for borrowed ACL.
    ensure!(
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
            != 0
            && present != 0
            && !dacl.is_null(),
        "owned registry ACL is missing"
    );
    // Apply DACL and protect it. Owner/group and all audit/integrity fields stay unchanged.
    let applied = unsafe {
        SetSecurityInfo(
            key,
            4,
            0x8000_0004,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    let result = if applied == 0 {
        registry_policy::preserved(&before, key)
    } else {
        Err(anyhow::anyhow!(
            "set owned registry fixture ACL failed winerror={applied}"
        ))
    };
    before.fill(0);
    let closed = descriptor.close();
    match (result, closed) {
        (result, Ok(())) => result,
        (Err(primary), Err(cleanup)) => Err(crate::windows_security::activation::Failures {
            errors: vec![primary, cleanup],
        }
        .into()),
        (Ok(()), Err(cleanup)) => Err(cleanup),
    }
}

pub(super) fn protect_foreign(path: &Path, package: &str) -> Result<()> {
    crate::windows_security::package_sid(package)?;
    plain_path(path)?;
    apply_policy(
        path,
        &format!("D:P(D;OICI;FA;;;{package})(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)S:(ML;OICI;NW;;;ME)"),
    )
}
