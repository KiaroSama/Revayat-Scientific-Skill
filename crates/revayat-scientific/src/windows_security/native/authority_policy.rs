//! Bounded actual primary/duplicate DACL observations; no formatted record is decoded as policy.
use super::*;
#[link(name = "advapi32")]
unsafe extern "system" {
    fn DuplicateTokenEx(
        token: Handle,
        access: u32,
        attributes: Handle,
        level: i32,
        kind: i32,
        output: *mut Handle,
    ) -> i32;
}
fn read(token: Handle) -> Result<Vec<u8>> {
    let mut buffer = vec![0u64; 8192];
    let result = (|| {
        let mut returned = 0;
        ensure!(
            unsafe {
                GetTokenInformation(token, 6, buffer.as_mut_ptr().cast(), 65536, &mut returned)
            } != 0
                && (8..=65536).contains(&returned),
            "read native diagnostic default DACL failed"
        );
        let bytes =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned as usize) };
        let acl = crate::windows_security::policy::token_default_acl(bytes, buffer.as_ptr() as u64)
            .map_err(|_| anyhow::anyhow!("native diagnostic DACL returned span differs"))?
            .ok_or_else(|| anyhow::anyhow!("native diagnostic default DACL is null"))?;
        Ok(acl.to_vec())
    })();
    buffer.fill(0);
    result
}
pub(super) fn observe(process: Handle, observer: &mut dyn AuthorityObserver) -> Result<()> {
    let mut primary = Owned(null_mut());
    let mut duplicate = Owned(null_mut());
    let result = (|| {
        let opened = unsafe { OpenProcessToken(process, 0xa, &mut primary.0) };
        ensure!(
            opened != 0 && !primary.0.is_null(),
            "open exact native diagnostic primary token failed"
        );
        let copied = unsafe { DuplicateTokenEx(primary.0, 8, null_mut(), 2, 1, &mut duplicate.0) };
        ensure!(
            copied != 0 && !duplicate.0.is_null() && duplicate.0 != primary.0,
            "duplicate native diagnostic primary token failed"
        );
        let mut before = read(primary.0)?;
        let mut after = match read(duplicate.0) {
            Ok(value) => value,
            Err(error) => {
                before.fill(0);
                return Err(error);
            }
        };
        let result = observer.default_policy(&before, &after);
        before.fill(0);
        after.fill(0);
        result
    })();
    let mut errors = result.err().into_iter().collect::<Vec<_>>();
    for result in [duplicate.close(), primary.close()] {
        if let Err(error) = result {
            errors.push(error);
        }
    }
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.remove(0)),
        _ => Err(crate::windows_security::activation::Failures { errors }.into()),
    }
}
