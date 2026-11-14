//! Validation of Darwin's fixed short BSD records for one unreaped PGID.
use anyhow::{Result, ensure};

pub(super) const SHORT_INFO_BYTES: usize = 64;
pub(super) const ZOMBIE_STATUS: u32 = 5;

pub(super) struct GroupSnapshot {
    leader: u32,
    anchored: bool,
    stopped: bool,
}

impl GroupSnapshot {
    pub(super) fn new(leader: u32) -> Result<Self> {
        ensure!(
            leader > 1 && leader <= i32::MAX as u32,
            "Darwin owned group identity is invalid"
        );
        Ok(Self {
            leader,
            anchored: false,
            stopped: true,
        })
    }

    pub(super) fn observe(
        &mut self,
        requested_pid: i32,
        returned_bytes: i32,
        pid: u32,
        pgid: u32,
        status: u32,
    ) -> Result<()> {
        ensure!(requested_pid > 1, "Darwin group member identity is invalid");
        ensure!(
            returned_bytes == SHORT_INFO_BYTES as i32,
            "Darwin owned group status is truncated"
        );
        ensure!(
            pid == requested_pid as u32,
            "Darwin process identity differs"
        );
        if pgid != self.leader {
            // A descendant can leave or be recycled between snapshot and query.
            // The direct child must retain the exact unreaped group anchor.
            ensure!(pid != self.leader, "Darwin owned group anchor differs");
            return Ok(());
        }
        self.anchored |= pid == self.leader;
        self.stopped &= status == ZOMBIE_STATUS;
        Ok(())
    }

    pub(super) fn finish(self) -> Result<bool> {
        ensure!(self.anchored, "Darwin owned group lost its unreaped leader");
        Ok(self.stopped)
    }
}
