//! Fixed machine-key LPAC role. It cannot select arbitrary executables or arguments.
use super::*;
use super::{
    authority_completion::{Completed, NativeCompletion, Observation},
    registry_scope::{Plan, Ticket},
};
use crate::{identity, windows_security::policy::registry_comparison::wire};

pub(super) fn run(
    image: &Path,
    expected: &identity::Fingerprint,
    profile: &Profile,
    observer: &mut dyn AuthorityObserver,
    plan: Plan,
    ticket: Ticket,
) -> Result<Completed> {
    let mut owner = NativeCompletion::new(observer)?;
    let operation = (|| {
        let target = authority_launch::prepare(
            &mut owner,
            image,
            expected,
            profile,
            authority_launch::LaunchKind::Machine(plan),
        )?;
        let sid = profile.sid_text()?;
        owner
            .observer
            .before_resume(owner.process.0, &sid, &target)?;
        owner.close_inputs()?;
        owner.resume()?;
        let started = Instant::now();
        loop {
            drain(&owner.stdout, &mut owner.output, OUTPUT_LIMIT)?;
            drain(&owner.stderr, &mut owner.error, ERROR_LIMIT)?;
            let wait = unsafe { WaitForSingleObject(owner.process.0, 10) };
            ensure!(wait == 0 || wait == 258, "machine authority wait failed");
            if wait == 0 {
                owner.signaled = true;
                break;
            }
            ensure!(
                started.elapsed() < Duration::from_secs(20),
                "machine authority wall deadline exceeded"
            );
        }
        let mut code = 0;
        ensure!(
            unsafe { GetExitCodeProcess(owner.process.0, &mut code) } != 0,
            "query machine authority exit failed"
        );
        owner.job.terminate()?;
        drain(&owner.stdout, &mut owner.output, OUTPUT_LIMIT)?;
        drain(&owner.stderr, &mut owner.error, ERROR_LIMIT)?;
        let output = owner.output.finish(OUTPUT_LIMIT)?.to_owned();
        let errors = owner.error.finish(ERROR_LIMIT)?.to_owned();
        if plan == Plan::Modified {
            wire::validate_wire(code, Some(&output), Some(&errors))?;
            wire::require_root_only(&output)?;
        } else {
            ensure!(
                code == 0 && errors.is_empty(),
                wire::transport_failure(code, Some(&errors))
            );
            registry_authority::protocol::require_machine_baseline(output.as_bytes())
                .map_err(|_| anyhow::anyhow!("fixed native machine denial receipt differs"))?;
        }
        owner.source.as_mut().unwrap().require(image)?;
        owner.target.as_mut().unwrap().require(&target)?;
        Ok(Observation {
            code,
            output,
            errors,
        })
    })();
    Ok(owner.finish(operation, ticket))
}
