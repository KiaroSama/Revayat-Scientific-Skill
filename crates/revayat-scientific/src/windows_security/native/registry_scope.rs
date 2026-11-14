//! Closed machine and machine/quota observation plans; no state here is an outer reap proof.
use crate::identity::ObjectId;
use anyhow::{Result, ensure};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
#[path = "registry_restore.rs"]
mod restore;
pub(in crate::windows_security::native) use restore::{RestoreAuthorization, RestoreTransaction};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::windows_security::native) enum Mode {
    Machine,
    MachineQuota,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::windows_security::native) enum Plan {
    Original,
    Modified,
    Quota,
    Restored,
}
impl Plan {
    pub fn argument(self) -> Option<&'static str> {
        match self {
            Self::Original | Self::Restored => Some("--machine-baseline"),
            Self::Modified | Self::Quota => None,
        }
    }
    pub fn expected(self) -> i32 {
        match self {
            Self::Original | Self::Restored => 0xC0000022u32 as i32,
            Self::Modified | Self::Quota => 0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::windows_security::native) enum LeaseKind {
    Machine,
    Volume,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Running,
    Retired,
    Restoring,
    Uncertain,
    Closed,
}
struct QuotaIdentity {
    image: String,
    arguments: String,
}
struct Slot {
    id: u64,
    resource: Rc<RefCell<Option<String>>>,
}
struct State {
    run: String,
    session: String,
    image: String,
    quota: Option<QuotaIdentity>,
    mode: Mode,
    profile: Option<(ObjectId, String)>,
    epoch: u64,
    phase: Phase,
    plan: Option<Plan>,
    leases: BTreeMap<LeaseKind, Slot>,
    next_lease: u64,
}
#[derive(Clone)]
pub(in crate::windows_security::native) struct Scope(Rc<RefCell<State>>);
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Scope {
    pub(super) fn new(run: &str, image: &str) -> Result<Self> {
        Self::create(run, image, None)
    }
    pub(super) fn machine_quota(
        run: &str,
        image: &str,
        quota_image: &str,
        arguments: &str,
    ) -> Result<Self> {
        ensure!(
            digest(quota_image) && digest(arguments),
            "native quota plan identity differs"
        );
        Self::create(
            run,
            image,
            Some(QuotaIdentity {
                image: quota_image.into(),
                arguments: arguments.into(),
            }),
        )
    }
    fn create(run: &str, image: &str, quota: Option<QuotaIdentity>) -> Result<Self> {
        ensure!(
            run.len() == 32
                && run
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && digest(image),
            "native session identity differs"
        );
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|_| anyhow::anyhow!("native session nonce unavailable"))?;
        let session = bytes.iter().map(|b| format!("{b:02x}")).collect();
        bytes.fill(0);
        let mode = if quota.is_some() {
            Mode::MachineQuota
        } else {
            Mode::Machine
        };
        Ok(Self(Rc::new(RefCell::new(State {
            run: run.into(),
            session,
            image: image.into(),
            quota,
            mode,
            profile: None,
            epoch: 0,
            phase: Phase::Idle,
            plan: None,
            leases: BTreeMap::new(),
            next_lease: 0,
        }))))
    }
    pub(in crate::windows_security::native) fn bind_profile(
        &self,
        identity: ObjectId,
        package: &str,
    ) -> Result<()> {
        crate::windows_security::package_sid(package)?;
        let mut state = self.0.borrow_mut();
        ensure!(
            state.phase == Phase::Idle
                && state.epoch == 0
                && state.leases.is_empty()
                && state.profile.is_none(),
            "native session profile binding already consumed"
        );
        state.profile = Some((identity, package.into()));
        Ok(())
    }
    pub(super) fn begin(&self, plan: Plan, run: &str, image: &str) -> Result<Ticket> {
        self.begin_checked(plan, run, image, None)
    }
    pub(super) fn begin_quota(&self, run: &str, image: &str, arguments: &str) -> Result<Ticket> {
        self.begin_checked(Plan::Quota, run, image, Some(arguments))
    }
    fn begin_checked(
        &self,
        plan: Plan,
        run: &str,
        image: &str,
        arguments: Option<&str>,
    ) -> Result<Ticket> {
        let mut state = self.0.borrow_mut();
        let expected = match (state.mode, state.epoch) {
            (_, 0) => Plan::Original,
            (_, 1) => Plan::Modified,
            (Mode::Machine, 2) | (Mode::MachineQuota, 3) => Plan::Restored,
            (Mode::MachineQuota, 2) => Plan::Quota,
            _ => anyhow::bail!("native observation plan already consumed"),
        };
        let identity = if plan == Plan::Quota {
            state.quota.as_ref().is_some_and(|quota| {
                quota.image == image && Some(quota.arguments.as_str()) == arguments
            })
        } else {
            state.image == image && arguments.is_none()
        };
        let leases = match plan {
            Plan::Original | Plan::Restored => state.leases.is_empty(),
            Plan::Modified | Plan::Quota => {
                state.leases.len() == 1
                    && state
                        .leases
                        .get(&LeaseKind::Machine)
                        .is_some_and(|slot| slot.resource.borrow().is_some())
            }
        };
        ensure!(
            state.phase == Phase::Idle
                && state.profile.is_some()
                && plan == expected
                && state.run == run
                && identity
                && leases,
            "native observation run/session/plan/order differs"
        );
        state.epoch += 1;
        state.plan = Some(plan);
        state.phase = Phase::Running;
        Ok(Ticket {
            scope: self.clone(),
            epoch: state.epoch,
            plan,
            armed: true,
        })
    }
    pub(in crate::windows_security::native) fn bind_lease(&self) -> Result<LeaseBinding> {
        let mut state = self.0.borrow_mut();
        ensure!(
            state.phase == Phase::Idle && state.epoch == 1 && state.leases.is_empty(),
            "native machine lease requires completed original control"
        );
        Self::reserve(self, &mut state, LeaseKind::Machine, None)
    }
    fn reserve(
        scope: &Self,
        state: &mut State,
        kind: LeaseKind,
        resource: Option<String>,
    ) -> Result<LeaseBinding> {
        ensure!(
            state.profile.is_some() && !state.leases.contains_key(&kind),
            "native policy obligation is foreign or already reserved"
        );
        state.next_lease = state
            .next_lease
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("native lease identity exhausted"))?;
        let id = state.next_lease;
        let resource = Rc::new(RefCell::new(resource));
        state.leases.insert(
            kind,
            Slot {
                id,
                resource: resource.clone(),
            },
        );
        let (epoch, plan) = match state.mode {
            Mode::Machine => (2, Plan::Modified),
            Mode::MachineQuota => (3, Plan::Quota),
        };
        Ok(LeaseBinding {
            scope: scope.clone(),
            kind,
            id,
            resource,
            epoch,
            plan,
            run: state.run.clone(),
            session: state.session.clone(),
        })
    }
    pub(super) fn close(&self) -> Result<()> {
        let mut state = self.0.borrow_mut();
        let last = if state.mode == Mode::Machine { 3 } else { 4 };
        ensure!(
            state.phase == Phase::Idle && state.epoch == last && state.leases.is_empty(),
            "native session did not finish its restored control"
        );
        state.phase = Phase::Closed;
        Ok(())
    }
    pub(in crate::windows_security::native) fn uncertain(&self) {
        self.0.borrow_mut().phase = Phase::Uncertain;
    }
}
pub(in crate::windows_security::native) struct Ticket {
    scope: Scope,
    epoch: u64,
    plan: Plan,
    armed: bool,
}
impl Ticket {
    pub(super) fn require_profile(&self, profile: &super::NativeProfileBinding<'_>) -> Result<()> {
        profile.require()?;
        let state = self.scope.0.borrow();
        ensure!(
            Rc::ptr_eq(&self.scope.0, &profile.scope().0)
                && state.phase == Phase::Running
                && state.epoch == self.epoch
                && state.plan == Some(self.plan)
                && state.run == profile.view().run_id()
                && state
                    .profile
                    .as_ref()
                    .is_some_and(|(id, package)| *id == profile.view().state_identity()
                        && package == profile.view().package_sid()),
            "suspended native plan/profile binding differs"
        );
        Ok(())
    }
    pub(super) fn reserve_lease(&self, kind: LeaseKind, resource: &str) -> Result<LeaseBinding> {
        ensure!(
            kind == LeaseKind::Volume && digest(resource),
            "native quota lease resource identity differs"
        );
        let mut state = self.scope.0.borrow_mut();
        ensure!(
            state.mode == Mode::MachineQuota
                && state.phase == Phase::Running
                && self.plan == Plan::Quota
                && state.plan == Some(self.plan)
                && state.epoch == self.epoch
                && state.leases.len() == 1
                && state.leases.contains_key(&LeaseKind::Machine),
            "native quota lease requires its exact suspended actor"
        );
        Scope::reserve(&self.scope, &mut state, kind, Some(resource.into()))
    }
    pub(super) fn retired(mut self) -> Result<Retired> {
        {
            let mut state = self.scope.0.borrow_mut();
            let obligations = self.plan != Plan::Quota
                || (state.leases.len() == 2
                    && [LeaseKind::Machine, LeaseKind::Volume].iter().all(|kind| {
                        state
                            .leases
                            .get(kind)
                            .is_some_and(|slot| slot.resource.borrow().is_some())
                    }));
            ensure!(
                state.phase == Phase::Running
                    && state.epoch == self.epoch
                    && state.plan == Some(self.plan)
                    && obligations,
                "native retirement scope/obligations differ"
            );
            state.phase = Phase::Retired;
        }
        self.armed = false;
        Ok(Retired {
            scope: self.scope.clone(),
            epoch: self.epoch,
            plan: self.plan,
            armed: true,
        })
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if self.armed {
            self.scope.uncertain();
        }
    }
}
pub(in crate::windows_security::native) struct LeaseBinding {
    scope: Scope,
    kind: LeaseKind,
    id: u64,
    resource: Rc<RefCell<Option<String>>>,
    epoch: u64,
    plan: Plan,
    run: String,
    session: String,
}
pub(in crate::windows_security::native) type LeaseScope = LeaseBinding;
pub(in crate::windows_security::native) struct LeaseResourceWriter {
    scope: Scope,
    kind: LeaseKind,
    id: u64,
    resource: Rc<RefCell<Option<String>>>,
}
impl LeaseBinding {
    pub(in crate::windows_security::native) fn writer(&self) -> LeaseResourceWriter {
        LeaseResourceWriter {
            scope: self.scope.clone(),
            kind: self.kind,
            id: self.id,
            resource: self.resource.clone(),
        }
    }
    pub(in crate::windows_security::native) fn uncertain(&self) {
        self.scope.uncertain();
    }
}
impl LeaseResourceWriter {
    pub(in crate::windows_security::native) fn bind_resource(&self, value: &str) -> Result<()> {
        ensure!(digest(value), "native policy resource digest differs");
        let state = self.scope.0.borrow();
        ensure!(
            state.phase == Phase::Idle
                && self.kind == LeaseKind::Machine
                && state.epoch == 1
                && state.leases.get(&self.kind).is_some_and(
                    |slot| slot.id == self.id && Rc::ptr_eq(&slot.resource, &self.resource)
                )
                && self.resource.borrow().is_none(),
            "native durable lease resource binding differs"
        );
        *self.resource.borrow_mut() = Some(value.into());
        Ok(())
    }
}
pub(super) struct Retired {
    scope: Scope,
    epoch: u64,
    plan: Plan,
    armed: bool,
}
impl Retired {
    pub(super) fn complete(mut self) -> Result<()> {
        {
            let mut state = self.scope.0.borrow_mut();
            ensure!(
                state.phase == Phase::Retired
                    && state.epoch == self.epoch
                    && state.plan == Some(self.plan)
                    && matches!(self.plan, Plan::Original | Plan::Restored)
                    && state.leases.is_empty(),
                "native nontrial retirement differs"
            );
            state.phase = Phase::Idle;
        }
        self.armed = false;
        Ok(())
    }
    pub(super) fn advance_intermediate(mut self) -> Result<()> {
        {
            let mut state = self.scope.0.borrow_mut();
            ensure!(
                state.mode == Mode::MachineQuota
                    && state.phase == Phase::Retired
                    && state.epoch == 2
                    && self.epoch == 2
                    && self.plan == Plan::Modified
                    && state.plan == Some(self.plan)
                    && state.leases.len() == 1
                    && state.leases.contains_key(&LeaseKind::Machine),
                "native intermediate retirement cannot restore policies"
            );
            state.phase = Phase::Idle;
        }
        self.armed = false;
        Ok(())
    }
    pub(super) fn begin_restore(
        mut self,
        profile: &super::NativeProfileBinding<'_>,
    ) -> Result<RestoreTransaction> {
        profile.require()?;
        let scope = profile.scope();
        {
            let mut state = self.scope.0.borrow_mut();
            let (epoch, plan) = match state.mode {
                Mode::Machine => (2, Plan::Modified),
                Mode::MachineQuota => (3, Plan::Quota),
            };
            ensure!(
                Rc::ptr_eq(&self.scope.0, &scope.0)
                    && state.phase == Phase::Retired
                    && state.epoch == epoch
                    && self.epoch == epoch
                    && self.plan == plan
                    && state.plan == Some(plan)
                    && state
                        .profile
                        .as_ref()
                        .is_some_and(|(id, package)| *id == profile.view().state_identity()
                            && package == profile.view().package_sid()),
                "native final retirement/profile binding differs"
            );
            state.phase = Phase::Restoring;
        }
        let transaction = RestoreTransaction::new(self.scope.clone(), self.epoch, self.plan)?;
        self.armed = false;
        Ok(transaction)
    }
    pub(in crate::windows_security::native) fn restore(
        mut self,
        lease: &LeaseBinding,
    ) -> Result<Restore> {
        {
            let mut state = self.scope.0.borrow_mut();
            ensure!(
                state.mode == Mode::Machine
                    && Rc::ptr_eq(&self.scope.0, &lease.scope.0)
                    && state.phase == Phase::Retired
                    && state.epoch == 2
                    && self.epoch == lease.epoch
                    && self.plan == Plan::Modified
                    && lease.plan == self.plan
                    && state.plan == Some(self.plan)
                    && state.run == lease.run
                    && state.session == lease.session
                    && lease.kind == LeaseKind::Machine
                    && lease.resource.borrow().is_some()
                    && state
                        .leases
                        .get(&lease.kind)
                        .is_some_and(|slot| slot.id == lease.id
                            && Rc::ptr_eq(&slot.resource, &lease.resource)),
                "native observation cannot restore a foreign/composed lease"
            );
            state.phase = Phase::Restoring;
        }
        self.armed = false;
        Ok(Restore {
            scope: self.scope.clone(),
            armed: true,
        })
    }
}
impl Drop for Retired {
    fn drop(&mut self) {
        if self.armed {
            self.scope.uncertain();
        }
    }
}
/// Compatibility for the unchanged three-observation, machine-only owner.
pub(in crate::windows_security::native) struct Restore {
    scope: Scope,
    armed: bool,
}
impl Restore {
    pub(in crate::windows_security::native) fn complete(mut self) -> Result<()> {
        {
            let mut state = self.scope.0.borrow_mut();
            ensure!(
                state.mode == Mode::Machine
                    && state.phase == Phase::Restoring
                    && state.leases.len() == 1,
                "native machine restore owner differs"
            );
            state.leases.clear();
            state.phase = Phase::Idle;
        }
        self.armed = false;
        Ok(())
    }
}
impl Drop for Restore {
    fn drop(&mut self) {
        if self.armed {
            self.scope.uncertain();
        }
    }
}
