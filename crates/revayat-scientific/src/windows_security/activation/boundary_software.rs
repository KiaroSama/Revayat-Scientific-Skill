//! Exact shared stopped-context mechanics for ordinary, callback and entry modes.
//! Software origin is unverified; accepting a snapshot never advances hardware observation.
use super::{CONTEXT_SIZE, raw_debug_equal, trap_qualifiers};
use anyhow::{Result, ensure};
#[derive(Clone, Copy, Debug, Default)]
pub struct ObservationRoles {
    pub callback: bool,
    pub entry: bool,
    pub resource: bool,
    pub resource_deadline: bool,
    pub dispatch: bool,
    pub module_dispatch: bool,
    pub python_dispatch: bool,
}
pub fn require_modes(role: ObservationRoles) -> Result<()> {
    ensure!(
        !(role.python_dispatch && (!role.dispatch || role.module_dispatch)
            || role.module_dispatch && !role.dispatch
            || role.dispatch && !role.resource
            || u8::from(role.callback) + u8::from(role.entry) + u8::from(role.resource) > 1
            || role.resource != role.resource_deadline),
        "activation observation roles cannot overlap"
    );
    Ok(())
}
pub fn value(context: &[u8], offset: usize) -> Result<u64> {
    ensure!(
        context.len() == CONTEXT_SIZE && offset <= CONTEXT_SIZE - 8,
        "fixed boundary context width differs"
    );
    Ok(u64::from_le_bytes(context[offset..offset + 8].try_into()?))
}
pub fn put(context: &mut [u8], offset: usize, value: u64) -> Result<()> {
    ensure!(
        context.len() == CONTEXT_SIZE && offset <= CONTEXT_SIZE - 8,
        "fixed boundary context width differs"
    );
    context[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    Ok(())
}
pub fn control(baseline: &[u8], active: &[bool; 2]) -> Result<u64> {
    Ok(value(baseline, 112)? | u64::from(active[0]) | (u64::from(active[1]) << 2))
}
pub fn desired(
    before: &[u8],
    baseline: &[u8],
    sites: &[u64; 2],
    active: &[bool; 2],
    restore: bool,
) -> Result<Vec<u8>> {
    ensure!(
        before.len() == CONTEXT_SIZE,
        "fixed boundary context width differs"
    );
    let mut result = before.to_vec();
    let mut flags = value(baseline, 112)?;
    for index in 0..4 {
        put(
            &mut result,
            72 + index * 8,
            if restore || index >= 2 {
                value(baseline, 72 + index * 8)?
            } else {
                sites[index]
            },
        )?;
        if !restore && index < 2 && active[index] {
            flags |= 1 << (index * 2);
        }
    }
    put(&mut result, 104, value(baseline, 104)?)?;
    put(&mut result, 112, flags)?;
    result[48..52].copy_from_slice(&0x100010u32.to_le_bytes());
    Ok(result)
}
pub fn free(context: &[u8]) -> Result<bool> {
    for offset in (72..=96).step_by(8) {
        if value(context, offset)? != 0 {
            return Ok(false);
        }
    }
    Ok(value(context, 112)? & 0xffff28ff == 0 && value(context, 104)? & 0xe00f == 0)
}
pub fn software_status(status: u64, flags: u64, expected: u64) -> bool {
    status & !(0x10000 | 0x800) == 0xfffe07f0
        && expected & !0x405 == 0
        && (flags ^ expected) & !0x400 == 0
}
pub fn ownership(
    context: &[u8],
    baseline: &[u8],
    sites: &[u64; 2],
    active: &[bool; 2],
    trap: bool,
) -> Result<()> {
    for (index, expected) in sites
        .iter()
        .copied()
        .chain([value(baseline, 88)?, value(baseline, 96)?])
        .enumerate()
    {
        ensure!(
            value(context, 72 + index * 8)? == expected,
            "fixed boundary address ownership differs"
        );
    }
    if !trap {
        ensure!(
            software_status(
                value(context, 104)?,
                value(context, 112)?,
                control(baseline, active)?
            ),
            "fixed boundary software control ownership differs"
        );
    }
    Ok(())
}
#[derive(Clone, Copy, Debug)]
pub enum SoftwareRole {
    Boundary,
    Callback,
    Entry,
}
#[derive(Clone, Copy, Debug)]
pub struct SoftwareEvent {
    pub thread: u32,
    pub creator: u32,
    pub code: u32,
    pub first: bool,
}
pub fn software_stage(
    role: SoftwareRole,
    stage: u8,
    invalidated: bool,
    initial: bool,
    event: SoftwareEvent,
) -> bool {
    let stage = match role {
        SoftwareRole::Boundary => stage == 1,
        SoftwareRole::Callback => (1..=3).contains(&stage),
        SoftwareRole::Entry => (1..=2).contains(&stage),
    };
    stage
        && !invalidated
        && !initial
        && event.thread == event.creator
        && event.code == 0x80000003
        && event.first
}
#[derive(Default)]
pub struct SoftwarePresentation {
    initial: bool,
    snapshot: Option<String>,
}
impl SoftwarePresentation {
    pub fn initial(&self) -> bool {
        self.initial
    }
    pub fn snapshot(&self) -> Option<&str> {
        self.snapshot.as_deref()
    }
    pub fn accept(
        &mut self,
        context: &[u8],
        baseline: &[u8],
        sites: &[u64; 2],
        active: &[bool; 2],
    ) -> Result<()> {
        ensure!(
            !self.initial,
            "fixed software breakpoint was already captured"
        );
        ownership(context, baseline, sites, active, false)?;
        let snapshot = format!(
            " software_{} software_origin_verified=False",
            trap_qualifiers(value(context, 104)?).replace(' ', " software_")
        );
        ensure!(
            snapshot.len() <= 1024,
            "fixed software snapshot bound exceeded"
        );
        self.snapshot = Some(snapshot);
        self.initial = true;
        Ok(())
    }
    pub fn callback_load_ownership(
        &self,
        context: &[u8],
        baseline: &[u8],
        sites: &[u64; 2],
        active: &[bool; 2],
    ) -> Result<()> {
        if self.initial {
            ownership(context, baseline, sites, active, false)
        } else {
            ensure!(
                raw_debug_equal(baseline, context)?,
                "callback load baseline debug state differs"
            );
            Ok(())
        }
    }
}
