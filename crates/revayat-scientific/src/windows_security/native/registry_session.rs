//! One real profile and fixed held-image identity across the machine A/B/A session.
use super::super::{
    NativeRunView,
    registry_machine::{MachineLease, read_surface},
};
use super::*;
use super::{
    authority_completion::{Completed, NativeTreeRetired},
    registry_scope::{Plan, Scope},
};
use crate::windows_security::policy::{
    child_acl_equal,
    registry_comparison::{self, Trial, wire},
};
use std::cell::RefCell;

#[path = "registry_quota_session.rs"]
mod quota;
pub use quota::run_machine_quota_session;
#[path = "registry_kernel_session.rs"]
mod kernel;
pub use kernel::run_machine_kernel_session;

/// Created only after actual profile creation/sealing and matching held run identity.
pub(in crate::windows_security::native) struct NativeProfileBinding<'a> {
    view: &'a NativeRunView,
    scope: Scope,
    package: String,
}
impl<'a> NativeProfileBinding<'a> {
    fn new(view: &'a NativeRunView, profile: &Profile, image: &str) -> Result<Self> {
        Self::bind(view, profile, Scope::new(view.run_id(), image)?)
    }
    fn machine_quota(
        view: &'a NativeRunView,
        profile: &Profile,
        machine: &str,
        quota: &str,
        arguments: &str,
    ) -> Result<Self> {
        Self::bind(
            view,
            profile,
            Scope::machine_quota(view.run_id(), machine, quota, arguments)?,
        )
    }
    fn kernel(
        view: &'a NativeRunView,
        profile: &Profile,
        machine: &str,
        worker: &str,
        primary_arguments: &str,
        wall_arguments: &str,
    ) -> Result<Self> {
        Self::bind(
            view,
            profile,
            Scope::kernel(
                view.run_id(),
                machine,
                worker,
                primary_arguments,
                wall_arguments,
            )?,
        )
    }
    fn bind(view: &'a NativeRunView, profile: &Profile, scope: Scope) -> Result<Self> {
        view.require()?;
        let package = profile.sid_text()?;
        ensure!(
            profile.created && profile.outer_recovery && package == view.package_sid(),
            "native registry session profile binding differs"
        );
        scope.bind_profile(view.state_identity(), &package)?;
        Ok(Self {
            view,
            scope,
            package,
        })
    }
    pub(in crate::windows_security::native) fn require(&self) -> Result<()> {
        crate::windows_security::activation::native::require_host()?;
        self.view.require()?;
        ensure!(
            self.package == self.view.package_sid(),
            "native registry package binding changed"
        );
        Ok(())
    }
    pub(in crate::windows_security::native) fn view(&self) -> &NativeRunView {
        self.view
    }
    pub(in crate::windows_security::native) fn scope(&self) -> &Scope {
        &self.scope
    }
}
struct Observer<'a> {
    package: &'a str,
    expected: i32,
    prepared: bool,
    created: bool,
    reads: bool,
    snapshots: usize,
    policy: Vec<u8>,
}
impl<'a> Observer<'a> {
    fn new(package: &'a str, plan: Plan) -> Self {
        Self {
            package,
            expected: plan.expected(),
            prepared: false,
            created: false,
            reads: false,
            snapshots: 0,
            policy: Vec::new(),
        }
    }
}
impl Drop for Observer<'_> {
    fn drop(&mut self) {
        self.policy.fill(0);
    }
}
impl AuthorityObserver for Observer<'_> {
    fn prepare(&mut self, package: &str) -> Result<()> {
        ensure!(
            !self.prepared && package == self.package,
            "machine observation package differs"
        );
        self.prepared = true;
        Ok(())
    }
    fn before_create(&mut self) -> Result<()> {
        ensure!(
            self.prepared && !self.created,
            "machine observation creation repeated"
        );
        self.created = true;
        Ok(())
    }
    fn token_metadata(&mut self, record: &str) -> Result<()> {
        ensure!(
            record.len() <= 4096,
            "machine observation metadata exceeds bound"
        );
        Ok(())
    }
    fn default_policy(&mut self, primary: &[u8], duplicate: &[u8]) -> Result<()> {
        ensure!(
            self.created && self.snapshots < 2 && child_acl_equal(primary, duplicate)?,
            "machine observation primary/duplicate DACL differs"
        );
        if self.snapshots == 0 {
            self.policy = primary.into();
        } else {
            ensure!(
                child_acl_equal(&self.policy, primary)?,
                "machine observation DACL changed during preparation"
            );
        }
        self.snapshots += 1;
        Ok(())
    }
    fn registry_status(&mut self, status: i32) -> Result<()> {
        ensure!(
            !self.reads
                && self.snapshots == 2
                && if self.expected == 0 {
                    status >= 0
                } else {
                    status == self.expected
                },
            "machine observation did not retain its exact registry condition"
        );
        self.reads = true;
        Ok(())
    }
    fn before_resume(&mut self, _: Handle, package: &str, image: &Path) -> Result<()> {
        ensure!(
            self.prepared
                && self.created
                && self.reads
                && self.snapshots == 2
                && package == self.package
                && image
                    .file_name()
                    .is_some_and(|name| name == "registry-authority.exe"),
            "machine observation was not qualified before resume"
        );
        Ok(())
    }
    fn after_reap(&mut self, reaped: bool) -> Result<()> {
        ensure!(reaped, "machine observation cleanup remains uncertain");
        Ok(())
    }
}
fn observe(
    image: &Path,
    identity: &crate::identity::Fingerprint,
    profile: &Profile,
    binding: &NativeProfileBinding<'_>,
    plan: Plan,
) -> Result<Completed> {
    binding.require()?;
    ensure!(
        profile.sid_text()? == binding.package,
        "native session SID changed"
    );
    let ticket = binding
        .scope
        .begin(plan, binding.view.run_id(), &identity.sha256)?;
    super::authority_machine_run::run(
        image,
        identity,
        profile,
        &mut Observer::new(&binding.package, plan),
        plan,
        ticket,
    )
}
fn finish_negative(completed: Completed) -> Result<()> {
    let retired = match completed.retired {
        Some(retired) => retired,
        None => {
            return Err(completed.result.err().unwrap_or_else(|| {
                anyhow::anyhow!("native negative control lacks completed ownership retirement")
            }));
        }
    };
    let retirement = retired.complete();
    let observation = match completed.result {
        Ok(value) => {
            retirement?;
            value
        }
        Err(primary) => return Err(primary_first(primary, retirement)),
    };
    ensure!(
        observation.code == 0 && observation.errors.is_empty(),
        "native negative control transport differs"
    );
    registry_authority::protocol::require_machine_baseline(observation.output.as_bytes())
        .map_err(|_| anyhow::anyhow!("native negative control did not prove exact access denial"))
}
fn primary_first(primary: anyhow::Error, cleanup: Result<()>) -> anyhow::Error {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => crate::windows_security::activation::Failures {
            errors: vec![primary, cleanup],
        }
        .into(),
    }
}
/// Explicit disposable-host diagnostic only. Default owned-fixture execution does not call this.
pub fn run_machine_authority_session(image: &Path, view: &NativeRunView) -> Result<String> {
    crate::windows_security::activation::native::require_host()?;
    view.require()?;
    let executable = std::env::current_exe()?;
    let expected =
        crate::executable_paths::binary_directory(&executable)?.join("registry-authority.exe");
    ensure!(
        image.file_name() == expected.file_name()
            && crate::identity::path_object_id(image)?
                == crate::identity::path_object_id(&expected)?,
        "machine authority is not the fixed same-profile sibling"
    );
    plain_path(image)?;
    let image = expected.as_path();
    let identity = crate::identity::file_identity(image, Some(8 * 1024 * 1024))?;
    let mut held = authority_image::AuthorityImage::open(image, &identity)?;
    let mut profile = match Profile::new_owned(view) {
        Ok(profile) => profile,
        Err(primary) => return Err(primary_first(primary, held.close())),
    };
    let result = (|| {
        let binding = NativeProfileBinding::new(view, &profile, &identity.sha256)?;
        finish_negative(observe(
            image,
            &identity,
            &profile,
            &binding,
            Plan::Original,
        )?)?;
        let before = RefCell::new(None);
        let lease = RefCell::new(None::<MachineLease>);
        let retirement = RefCell::new(None::<NativeTreeRetired>);
        let output = RefCell::new(None::<String>);
        registry_comparison::execute_authority(
            || {
                let completed = observe(image, &identity, &profile, &binding, Plan::Modified)?;
                *retirement.borrow_mut() = completed.retired;
                let observation = completed.result?;
                wire::require_root_only(&observation.output)?;
                *output.borrow_mut() = Some(observation.output);
                Ok(())
            },
            || {
                *lease.borrow_mut() = Some(MachineLease::begin_session(&binding)?);
                Ok(Trial {
                    restore: Box::new(|| {
                        let proof = retirement.borrow_mut().take().ok_or_else(|| {
                            anyhow::anyhow!(
                                "machine trial lacks its completed observation retirement"
                            )
                        })?;
                        lease
                            .borrow_mut()
                            .as_mut()
                            .unwrap()
                            .finish_observation(proof)
                    }),
                    defer: Box::new(|| lease.borrow_mut().as_mut().unwrap().defer()),
                })
            },
            || {
                let original = read_surface()?;
                original.require_equal(&read_surface()?)?;
                *before.borrow_mut() = Some(original);
                Ok(())
            },
            || {
                before
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .require_equal(&read_surface()?)?;
                finish_negative(observe(
                    image,
                    &identity,
                    &profile,
                    &binding,
                    Plan::Restored,
                )?)?;
                binding.scope.close()
            },
            || Ok(()),
        )?;
        held.require(image)?;
        let original = before.into_inner().unwrap();
        Ok(format!(
            "{}WINDOWS_REGISTRY_AUTHORITY runtime=rust authority_qualified=True root_values={} root_subkeys={} value_type_mask={} host_surface_restored=True original_access_denied=True restored_access_denied=True read_surface_approved=False production_grant=False target_admitted=False\n",
            output.into_inner().unwrap(),
            original.values,
            original.subkeys,
            original.types
        ))
    })();
    let mut errors = result.is_err();
    let closed = held.close();
    errors |= closed.is_err();
    let profile_closed = if errors {
        profile.retain()
    } else {
        profile.close()
    };
    match (result, closed, profile_closed) {
        (Ok(value), Ok(()), Ok(())) => Ok(value),
        (result, closed, profile) => {
            let mut failures = result.err().into_iter().collect::<Vec<_>>();
            failures.extend(closed.err());
            failures.extend(profile.err());
            Err(wire::sanitize(if failures.len() == 1 {
                failures.remove(0)
            } else {
                crate::windows_security::activation::Failures { errors: failures }.into()
            }))
        }
    }
}
