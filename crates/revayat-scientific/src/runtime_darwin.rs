//! Darwin excludes zombies from killpg's eligible targets and can return EPERM
//! for a group containing only our unreaped leader. Inspect only that anchored
//! group before accepting this result; a real permission failure remains fatal.
use anyhow::{Context, Result, ensure};

pub(super) fn stopped_group(leader: u32) -> Result<bool> {
    ensure!(
        super::status_without_reaping(leader)?.is_some(),
        "Darwin group leader is still running"
    );
    let mut members = [0 as libc::pid_t; 1024];
    // SAFETY: the typed buffer is writable for precisely the supplied byte size.
    // The unreaped direct child prevents reuse of this exact PGID during lookup.
    let count = unsafe {
        libc::proc_listpgrppids(
            leader as libc::pid_t,
            members.as_mut_ptr().cast(),
            std::mem::size_of_val(&members).try_into()?,
        )
    };
    ensure!(
        count > 0 && (count as usize) < members.len(),
        "Darwin owned group snapshot is unavailable or truncated"
    );
    let mut anchored = false;
    for &pid in &members[..count as usize] {
        ensure!(pid > 1, "Darwin owned group contains an invalid identity");
        // SAFETY: proc_bsdinfo is a C output record with valid zero initialization.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info);
        // SAFETY: the live typed record is writable for its exact ABI size.
        let returned = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                1, // Include zombies; arg=0 cannot inspect our retained anchor.
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size.try_into()?,
            )
        };
        if returned == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) && pid as u32 != leader {
                continue; // A descendant was reaped after the group snapshot.
            }
            return Err(error).context("Darwin owned group status unavailable");
        }
        ensure!(
            returned as usize == size,
            "Darwin owned group status is truncated"
        );
        ensure!(
            info.pbi_pid == pid as u32,
            "Darwin process identity differs"
        );
        if info.pbi_pgid == leader {
            if info.pbi_status != libc::SZOMB {
                return Ok(false);
            }
            anchored |= pid as u32 == leader;
        }
    }
    ensure!(anchored, "Darwin owned group lost its unreaped leader");
    Ok(true)
}
