//! Positive read authority of this fresh fixture, independent of its default owner SID.
use super::*;
use crate::windows_security::{policy, sxs};
use registry_authority::native::{Attributes, Unicode};

#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetSecurityInfo(
        key: Handle,
        kind: i32,
        information: u32,
        owner: *mut Handle,
        group: *mut Handle,
        dacl: *mut Handle,
        sacl: *mut Handle,
        descriptor: *mut Handle,
    ) -> u32;
    fn GetSecurityDescriptorLength(descriptor: Handle) -> u32;
}

pub(super) fn root_policy(user: &str, package: &str) -> Result<String> {
    crate::windows_security::scratch::sid(user)?;
    crate::windows_security::package_sid(package)?;
    // The LUA token makes Administrators deny-only, so OWNER_RIGHTS cannot supply
    // its normal-token positive when the fresh key defaults to the administrator owner.
    // Only the fixed root receives this noninheriting concrete-user read grant.
    Ok(format!(
        "D:P(D;;0xd0006;;;{package})(A;;KA;;;SY)(A;;KA;;;OW)(A;;0x00020019;;;{user})(A;;KR;;;{package})"
    ))
}
pub(super) fn require_policy(key: Handle, user: &str, package: &str) -> Result<()> {
    let mut expected = Descriptor::new(&root_policy(user, package)?)?;
    let (mut owner, mut group, mut dacl, mut sacl, mut actual) =
        (null_mut(), null_mut(), null_mut(), null_mut(), null_mut());
    let status = unsafe {
        GetSecurityInfo(
            key,
            4,
            4,
            &mut owner,
            &mut group,
            &mut dacl,
            &mut sacl,
            &mut actual,
        )
    };
    let operation = (|| {
        ensure!(
            status == 0 && !actual.is_null(),
            "owned fixture DACL readback failed winerror={status}"
        );
        let actual_size = unsafe { GetSecurityDescriptorLength(actual) };
        let expected_size = unsafe { GetSecurityDescriptorLength(expected.0) };
        ensure!(
            (20..=65536).contains(&actual_size) && (20..=65536).contains(&expected_size),
            "owned fixture DACL exceeds bound"
        );
        let actual =
            unsafe { std::slice::from_raw_parts(actual.cast::<u8>(), actual_size as usize) };
        let expected =
            unsafe { std::slice::from_raw_parts(expected.0.cast::<u8>(), expected_size as usize) };
        ensure!(
            policy::access_matches(expected, actual)?,
            "owned fixture DACL differs from exact read policy"
        );
        Ok(())
    })();
    let allocation = if actual.is_null() || unsafe { LocalFree(actual) }.is_null() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "owned fixture DACL allocation cleanup failed"
        ))
    };
    crate::runtime::with_cleanup(
        crate::runtime::with_cleanup(operation, allocation),
        expected.close(),
    )
}
fn fresh(
    name: &str,
    mask: u32,
    allowed: bool,
    retained: Handle,
    qualify: &dyn Fn() -> Result<()>,
) -> Result<()> {
    qualify()?;
    let text = wide(name);
    ensure!(
        text.len() > 1 && text.len() <= 513,
        "owned fixture native name exceeds bound"
    );
    let name = Unicode {
        length: ((text.len() - 1) * 2) as u16,
        maximum: (text.len() * 2) as u16,
        buffer: text.as_ptr(),
    };
    let attributes = Attributes {
        length: size_of::<Attributes>() as u32,
        root: null_mut(),
        name: &name,
        flags: 0x1040,
        descriptor: null_mut(),
        qos: null_mut(),
    };
    let mut raw = null_mut();
    let status =
        unsafe { registry_authority::native::NtOpenKeyEx(&mut raw, mask, &attributes, 0) } as u32;
    let valid = !raw.is_null() && raw as isize > 0;
    let operation = (|| {
        qualify()?;
        ensure!(
            raw != retained,
            "owned fixture fresh open returned its retained alias"
        );
        ensure!(
            if allowed {
                status == 0 && valid
            } else {
                registry_authority::protocol::denied(status, raw as usize)
            },
            "owned fixture suspended access differs allowed={allowed} desired_access={mask:08X} nt_status={status:08X} handle_present={valid}"
        );
        if allowed {
            let mut basic = [0u64; 7];
            let mut returned = 0;
            let queried = unsafe {
                registry_authority::native::NtQueryObject(
                    raw,
                    0,
                    basic.as_mut_ptr().cast(),
                    56,
                    &mut returned,
                )
            } as u32;
            ensure!(
                registry_authority::protocol::basic(
                    queried,
                    returned,
                    basic[0] as u32,
                    (basic[0] >> 32) as u32
                ),
                "owned fixture fresh read handle authority differs"
            );
        }
        Ok(())
    })();
    let cleanup = if valid && raw != retained {
        (|| {
            let closed = unsafe { registry_authority::native::NtClose(raw) } as u32;
            ensure!(
                closed == 0,
                "owned fixture fresh key close failed nt_status={closed:08X}"
            );
            Ok(())
        })()
    } else {
        Ok(())
    };
    crate::runtime::with_cleanup(operation, cleanup)
}
impl RegistryFixture {
    /// Actual still-suspended LPAC positive and every original mutation/private-child denial.
    pub(in crate::windows_security::native) fn require_child_readonly(
        &self,
        process: Handle,
        package: &str,
    ) -> Result<()> {
        ensure!(
            sxs::ordinal_path_equal(&self.native_name()?, &self.name)?,
            "owned fixture retained identity differs"
        );
        let start = Instant::now();
        let deadline = || {
            ensure!(
                start.elapsed() <= Duration::from_secs(8),
                "owned fixture suspended controls deadline exceeded"
            );
            Ok(())
        };
        sxs::with_authority(process, package, deadline, |qualify| {
            fresh(&self.name, 0x20019, true, self.root, qualify)?;
            for mask in [2, 4, 0x10000, 0x40000, 0x80000] {
                fresh(&self.name, mask, false, self.root, qualify)?;
            }
            for mask in [1, 8, 0x10, 0x20000, 0x20019] {
                fresh(
                    &format!("{}\\private-child", self.name),
                    mask,
                    false,
                    self.root,
                    qualify,
                )?;
            }
            Ok(())
        })?;
        ensure!(
            sxs::ordinal_path_equal(&self.native_name()?, &self.name)?,
            "owned fixture identity changed during suspended controls"
        );
        Ok(())
    }
}
