//! Actual suspended-token repair and independently queried worker owner inventory.
use super::ffi::*;
use crate::windows_security::quota_controls::{OwnerInventory, Sid};
use anyhow::{Result, ensure};
use std::ptr::{null, null_mut};

struct Data {
    aligned: Vec<u64>,
    bytes: usize,
}
impl Data {
    fn query(token: Raw, class: i32) -> Result<Self> {
        let mut bytes = 0;
        // SAFETY: first call obtains only a bounded required length.
        let initial = unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut bytes) };
        let error = unsafe { GetLastError() };
        ensure!(
            initial == 0 && error == 122 && (4..=65536).contains(&bytes),
            "quota token query size is invalid"
        );
        let capacity = bytes;
        let mut aligned = vec![0u64; (bytes as usize).div_ceil(8)];
        // SAFETY: allocation has sufficient initialized aligned writable capacity.
        ensure!(
            unsafe {
                GetTokenInformation(
                    token,
                    class,
                    aligned.as_mut_ptr().cast(),
                    capacity,
                    &mut bytes,
                )
            } != 0
                && (4..=capacity).contains(&bytes),
            "quota token query failed or changed bounds"
        );
        Ok(Self {
            aligned,
            bytes: bytes as usize,
        })
    }
    fn bytes(&self) -> &[u8] {
        // SAFETY: only the successfully initialized and bounded returned bytes are exposed.
        unsafe { std::slice::from_raw_parts(self.aligned.as_ptr().cast(), self.bytes) }
    }
    fn u32(&self, offset: usize) -> Result<u32> {
        let bytes = self
            .bytes()
            .get(offset..offset + 4)
            .ok_or_else(|| anyhow::anyhow!("quota token field is truncated"))?;
        Ok(u32::from_le_bytes(bytes.try_into()?))
    }
    fn pointer(&self, offset: usize) -> Result<usize> {
        let bytes = self
            .bytes()
            .get(offset..offset + 8)
            .ok_or_else(|| anyhow::anyhow!("quota token pointer is truncated"))?;
        Ok(u64::from_le_bytes(bytes.try_into()?) as usize)
    }
    fn sid(&self, offset: usize) -> Result<Sid> {
        let pointer = self.pointer(offset)?;
        let base = self.aligned.as_ptr() as usize;
        ensure!(
            pointer >= base && pointer.is_multiple_of(4),
            "quota token SID pointer is outside query"
        );
        let offset = pointer - base;
        let header = self
            .bytes()
            .get(offset..offset.saturating_add(8))
            .ok_or_else(|| anyhow::anyhow!("quota token SID header is outside query"))?;
        ensure!(
            header[0] == 1 && header[1] <= 15,
            "quota token SID header differs"
        );
        let bytes = 8 + usize::from(header[1]) * 4;
        Sid::binary(
            self.bytes()
                .get(offset..offset.saturating_add(bytes))
                .ok_or_else(|| anyhow::anyhow!("quota token SID is outside query"))?,
        )
    }
}
impl Drop for Data {
    fn drop(&mut self) {
        self.aligned.fill(0);
    }
}

fn groups(token: Raw) -> Result<Vec<(Sid, u32)>> {
    let data = Data::query(token, 2)?;
    let count = data.u32(0)? as usize;
    ensure!(
        count <= 256 && 8 + count * 16 <= data.bytes,
        "quota owner group inventory exceeds bound"
    );
    let admin = Sid::text("S-1-5-32-544")?;
    let mut groups = Vec::with_capacity(count);
    for index in 0..count {
        let sid = data.sid(8 + index * 16)?;
        let attributes = data.u32(16 + index * 16)?;
        if sid == admin {
            ensure!(
                attributes & (8 | 4 | 2) == 0 && attributes & 16 != 0,
                "Administrators retains enabled or quota-owner authority"
            );
        }
        groups.push((sid, attributes));
    }
    Ok(groups)
}
fn inventory(token: Raw, expected_package: &str) -> Result<OwnerInventory> {
    let user = Data::query(token, 1)?.sid(0)?;
    let package = Data::query(token, 31)?.sid(0)?;
    ensure!(
        package == Sid::text(expected_package)?,
        "quota token package differs from prepared profile"
    );
    let owner = Data::query(token, 4)?.sid(0)?;
    OwnerInventory::new(user, package, owner, &groups(token)?)
}
fn privileges(token: Raw) -> Result<Vec<u64>> {
    let data = Data::query(token, 3)?;
    let count = data.u32(0)? as usize;
    ensure!(
        count <= 128 && 4 + count * 12 <= data.bytes,
        "quota token privilege inventory exceeds bound"
    );
    (0..count)
        .map(|index| {
            Ok(u64::from(data.u32(4 + index * 12)?) | (u64::from(data.u32(8 + index * 12)?) << 32))
        })
        .collect()
}
fn repair(token: Raw) -> Result<()> {
    // Reject an unrestricted Administrators owner before modifying any token field.
    groups(token)?;
    let name = wide("SeChangeNotifyPrivilege");
    let mut traversal = 0u64;
    // SAFETY: fixed native privilege name and writable full 64-bit LUID.
    ensure!(
        unsafe {
            LookupPrivilegeValueW(null(), name.as_ptr(), (&mut traversal as *mut u64).cast())
        } != 0
            && traversal == 23,
        "native traversal privilege identity differs"
    );
    let removed = privileges(token)?
        .into_iter()
        .filter(|luid| *luid != traversal)
        .collect::<Vec<_>>();
    if !removed.is_empty() {
        let length = 4 + removed.len() * 12;
        let mut data = vec![0u64; length.div_ceil(8)];
        // SAFETY: fixed packed TOKEN_PRIVILEGES fields fit in initialized aligned allocation.
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(data.as_mut_ptr().cast::<u8>(), length) };
        bytes[..4].copy_from_slice(&(removed.len() as u32).to_le_bytes());
        for (index, luid) in removed.iter().enumerate() {
            bytes[4 + index * 12..12 + index * 12].copy_from_slice(&luid.to_le_bytes());
            bytes[12 + index * 12..16 + index * 12].copy_from_slice(&4u32.to_le_bytes());
        }
        // SAFETY: exclusively prepared token and complete bounded removal-only state.
        unsafe {
            SetLastError(0);
        }
        let ok = unsafe {
            AdjustTokenPrivileges(token, 0, data.as_ptr().cast(), 0, null_mut(), null_mut())
        };
        let error = unsafe { GetLastError() };
        data.fill(0);
        ensure!(
            ok != 0 && error == 0,
            "quota token privilege removal was incomplete"
        );
    }
    ensure!(
        privileges(token)?.iter().all(|luid| *luid == traversal),
        "quota token retained a non-traversal privilege"
    );
    let user = Data::query(token, 1)?.sid(0)?;
    let mut pointer = user.bytes().as_ptr() as Raw;
    // SAFETY: TOKEN_OWNER contains one live bounded user SID pointer; token has ADJUST_DEFAULT.
    ensure!(
        unsafe { SetTokenInformation(token, 4, (&mut pointer as *mut Raw).cast(), 8) } != 0,
        "quota token default owner repair failed"
    );
    ensure!(
        Data::query(token, 4)?.sid(0)? == user,
        "quota token owner readback does not equal user"
    );
    Ok(())
}

/// Borrows the actual process owned by the suspended native completion owner.
/// Does not establish suspension, job membership, a session ticket or completion authority.
pub(super) fn prepare(
    process: Raw,
    package: &str,
    mut persist_owner: impl FnMut(&str) -> Result<()>,
) -> Result<OwnerInventory> {
    ensure!(
        !process.is_null() && process as isize != -1,
        "quota preparation process is invalid"
    );
    let mut raw = null_mut();
    // SAFETY: caller retains actual process ownership; token output becomes exclusively owned.
    let opened = unsafe { OpenProcessToken(process, 0xA8, &mut raw) };
    let mut token = if raw.is_null() {
        Owned::empty()
    } else {
        Owned::new(raw)?
    };
    let result = (|| {
        ensure!(
            opened != 0 && !token.0.is_null(),
            "quota preparation token open failed"
        );
        repair(token.0)?;
        let inventory = inventory(token.0, package)?;
        for owner in inventory.texts() {
            persist_owner(&owner)?;
        }
        ensure!(
            privileges(token.0)?.iter().all(|luid| *luid == 23),
            "quota token privilege policy changed during owner persistence"
        );
        // Requery after persistence; a changed token cannot acquire a qualified inventory.
        ensure!(
            inventory.digest() == self::inventory(token.0, package)?.digest(),
            "quota token inventory changed during owner persistence"
        );
        Ok(inventory)
    })();
    combine(result, token.close())
}

pub(super) fn current(package: &str) -> Result<OwnerInventory> {
    registry_authority::token::controls()
        .map_err(|_| anyhow::anyhow!("quota worker native LPAC token controls failed"))?;
    registry_authority::native::detached().map_err(|_| {
        anyhow::anyhow!("quota worker native detached handles or job control failed")
    })?;
    let mut raw = null_mut();
    // SAFETY: borrowed pseudo process handle, token is separately owned and explicitly closed.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut raw) };
    let mut token = if raw.is_null() {
        Owned::empty()
    } else {
        Owned::new(raw)?
    };
    let result = (|| {
        ensure!(
            opened != 0 && !token.0.is_null(),
            "quota worker token open failed"
        );
        inventory(token.0, package)
    })();
    combine(result, token.close())
}

/// Read back the actual inherited descendant token while its owning thread is still suspended.
pub(super) fn inherited(process: Raw, package: &str, primary: &OwnerInventory) -> Result<()> {
    let mut raw = null_mut();
    let opened = unsafe { OpenProcessToken(process, 8, &mut raw) };
    let mut token = if raw.is_null() {
        Owned::empty()
    } else {
        Owned::new(raw)?
    };
    let result = (|| {
        ensure!(
            opened != 0 && !token.0.is_null(),
            "quota descendant suspended token open failed"
        );
        ensure!(
            privileges(token.0)?.iter().all(|luid| *luid == 23),
            "quota descendant inherited non-traversal privilege"
        );
        ensure!(
            inventory(token.0, package)?.digest() == primary.digest(),
            "quota descendant suspended owner inventory differs"
        );
        Ok(())
    })();
    combine(result, token.close())
}
