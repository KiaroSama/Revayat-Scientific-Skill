//! Darwin excludes zombies from killpg's eligible targets and can return EPERM
//! for a group containing only our unreaped leader. Inspect only that anchored
//! group before accepting this result; a real permission failure remains fatal.
use anyhow::{Context, Result, ensure};
#[path = "runtime_darwin_state.rs"]
mod state;

// The short flavor supplies every ownership/state field needed here without
// the full BSD flavor's effective-UID gate (for example, an exited setuid ps).
const _: () = assert!(std::mem::size_of::<libc::proc_bsdshortinfo>() == state::SHORT_INFO_BYTES);
const _: () = assert!(libc::SZOMB == state::ZOMBIE_STATUS);

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
    let mut snapshot = state::GroupSnapshot::new(leader)?;
    for &pid in &members[..count as usize] {
        ensure!(pid > 1, "Darwin owned group contains an invalid identity");
        // SAFETY: the short BSD output record has valid zero initialization.
        let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info);
        // SAFETY: the live typed record is writable for its exact ABI size.
        let returned = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDT_SHORTBSDINFO,
                1, // Include zombies; arg=0 cannot inspect our retained anchor.
                (&mut info as *mut libc::proc_bsdshortinfo).cast(),
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
        snapshot.observe(
            pid,
            returned,
            info.pbsi_pid,
            info.pbsi_pgid,
            info.pbsi_status,
        )?;
    }
    snapshot.finish()
}
