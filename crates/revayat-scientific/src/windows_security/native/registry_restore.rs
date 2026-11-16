//! One consumed final observation authorizes bounded independent policy obligations.
use super::*;
use crate::windows_security::activation::Failures;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Attempt {
    Pending,
    Active,
    Done,
    Failed,
}
struct Attempts {
    slots: BTreeMap<LeaseKind, Attempt>,
}
pub(in crate::windows_security::native) struct RestoreTransaction {
    scope: Scope,
    epoch: u64,
    plan: Plan,
    attempts: RefCell<Attempts>,
    errors: Vec<anyhow::Error>,
    armed: bool,
}
pub(in crate::windows_security::native) struct RestoreAuthorization<'a> {
    transaction: &'a RestoreTransaction,
    kind: LeaseKind,
}
impl RestoreTransaction {
    pub(super) fn new(scope: Scope, epoch: u64, plan: Plan) -> Result<Self> {
        let slots = {
            let state = scope.0.borrow();
            let expected = if state.mode == Mode::Machine {
                vec![LeaseKind::Machine]
            } else {
                vec![LeaseKind::Machine, LeaseKind::Volume]
            };
            ensure!(
                state.phase == Phase::Restoring
                    && state.epoch == epoch
                    && state.plan == Some(plan)
                    && state.leases.len() == expected.len()
                    && expected.iter().all(|kind| state
                        .leases
                        .get(kind)
                        .is_some_and(|slot| slot.resource.borrow().is_some())),
                "native restore obligations are incomplete"
            );
            expected
                .into_iter()
                .map(|kind| (kind, Attempt::Pending))
                .collect()
        };
        Ok(Self {
            scope,
            epoch,
            plan,
            attempts: RefCell::new(Attempts { slots }),
            errors: Vec::new(),
            armed: true,
        })
    }
    /// Always call every required attempt; failure is accumulated until finish.
    pub(in crate::windows_security::native) fn attempt(
        &mut self,
        kind: LeaseKind,
        operation: impl FnOnce(&RestoreAuthorization<'_>) -> Result<()>,
    ) {
        let allowed = {
            let mut attempts = self.attempts.borrow_mut();
            match attempts.slots.get_mut(&kind) {
                Some(value) if *value == Attempt::Pending => {
                    *value = Attempt::Active;
                    true
                }
                _ => false,
            }
        };
        if !allowed {
            self.errors.push(anyhow::anyhow!(
                "native restore obligation is foreign or already attempted"
            ));
            return;
        }
        let result = operation(&RestoreAuthorization {
            transaction: self,
            kind,
        });
        let discharged = self.attempts.borrow().slots.get(&kind) == Some(&Attempt::Done);
        match result {
            Ok(()) if discharged => {}
            Ok(()) => {
                self.attempts
                    .borrow_mut()
                    .slots
                    .insert(kind, Attempt::Failed);
                self.errors.push(anyhow::anyhow!(
                    "native policy returned without bound cleanup discharge"
                ));
            }
            Err(error) => {
                self.attempts
                    .borrow_mut()
                    .slots
                    .insert(kind, Attempt::Failed);
                self.errors.push(error);
            }
        }
    }
    pub(in crate::windows_security::native) fn finish(mut self) -> Result<()> {
        if self
            .attempts
            .borrow()
            .slots
            .values()
            .any(|value| matches!(value, Attempt::Pending | Attempt::Active))
        {
            self.errors.push(anyhow::anyhow!(
                "native restore transaction has incomplete obligations"
            ));
        }
        if !self.errors.is_empty() {
            self.scope.uncertain();
            self.armed = false;
            let mut errors = std::mem::take(&mut self.errors);
            return if errors.len() == 1 {
                Err(errors.remove(0))
            } else {
                Err(Failures { errors }.into())
            };
        }
        {
            let mut state = self.scope.0.borrow_mut();
            ensure!(
                state.phase == Phase::Restoring
                    && state.epoch == self.epoch
                    && state.plan == Some(self.plan),
                "native restore transaction scope changed"
            );
            state.leases.clear();
            state.phase = Phase::Idle;
        }
        self.armed = false;
        Ok(())
    }
}
impl Drop for RestoreTransaction {
    fn drop(&mut self) {
        if self.armed {
            self.scope.uncertain();
        }
    }
}
impl RestoreAuthorization<'_> {
    pub(in crate::windows_security::native) fn require_profile(
        &self,
        profile: &super::super::NativeProfileBinding<'_>,
    ) -> Result<()> {
        profile.require()?;
        let state = self.transaction.scope.0.borrow();
        ensure!(
            Rc::ptr_eq(&self.transaction.scope.0, &profile.scope().0)
                && state.phase == Phase::Restoring
                && state.epoch == self.transaction.epoch
                && state.plan == Some(self.transaction.plan)
                && state.run == profile.view().run_id()
                && state
                    .profile
                    .as_ref()
                    .is_some_and(|(id, package)| *id == profile.view().state_identity()
                        && package == profile.view().package_sid()),
            "native restore authorization profile differs"
        );
        Ok(())
    }
    pub(in crate::windows_security::native) fn require_lease(
        &self,
        binding: &LeaseBinding,
    ) -> Result<()> {
        let state = self.transaction.scope.0.borrow();
        ensure!(
            state.phase == Phase::Restoring
                && state.epoch == self.transaction.epoch
                && state.plan == Some(self.transaction.plan)
                && binding.kind == self.kind
                && binding.epoch == self.transaction.epoch
                && binding.plan == self.transaction.plan
                && state.run == binding.run
                && state.session == binding.session
                && Rc::ptr_eq(&self.transaction.scope.0, &binding.scope.0)
                && state
                    .leases
                    .get(&self.kind)
                    .is_some_and(|slot| slot.id == binding.id
                        && Rc::ptr_eq(&slot.resource, &binding.resource)
                        && slot.resource.borrow().is_some())
                && self.transaction.attempts.borrow().slots.get(&self.kind)
                    == Some(&Attempt::Active),
            "native restore authorization belongs to a foreign/completed policy"
        );
        Ok(())
    }
    pub(in crate::windows_security::native) fn complete_lease(
        &self,
        binding: &LeaseBinding,
    ) -> Result<()> {
        self.require_lease(binding)?;
        self.transaction
            .attempts
            .borrow_mut()
            .slots
            .insert(self.kind, Attempt::Done);
        Ok(())
    }
}
