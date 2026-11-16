#[cfg(test)]
use crate::protocol;
use crate::protocol::{
    Failure, PanicPhase, Result, fixture_record, mark_panic_phase, need, panic_frame, record,
    take_cleanup_failure,
};
use crate::{process, registry};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

static DESCENDANT: AtomicBool = AtomicBool::new(false);

#[link(name = "kernel32")]
unsafe extern "system" {
    fn WriteFile(
        handle: crate::native::Raw,
        data: *const u8,
        size: u32,
        written: *mut u32,
        overlapped: crate::native::Raw,
    ) -> i32;
}

fn panic_diagnostic() {
    let mut remaining = panic_frame(DESCENDANT.load(Ordering::Relaxed));
    // SAFETY: this only borrows the inherited stderr handle. Static bytes need
    // no allocation or panic payload/location access, and no handle is closed.
    let handle = unsafe { crate::native::GetStdHandle((-12i32) as u32) };
    if handle.is_null() || handle as isize == -1 {
        return;
    }
    while !remaining.is_empty() {
        let mut written = 0;
        // SAFETY: bounded immutable static bytes and an exact writable count;
        // the inherited handle is used synchronously without OVERLAPPED state.
        let status = unsafe {
            WriteFile(
                handle,
                remaining.as_ptr(),
                remaining.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if status == 0 || written == 0 || written as usize > remaining.len() {
            return;
        }
        remaining = &remaining[written as usize..];
    }
}

fn clean(result: Result<String>) -> Result<String> {
    if !take_cleanup_failure() {
        return result;
    }
    let mut failure = result
        .err()
        .unwrap_or_else(|| Failure::new("close", "cleanup"));
    if failure.events.last() != Some(&("close", "cleanup")) && failure.events.len() < 8 {
        failure.events.push(("close", "cleanup"));
    }
    Err(failure)
}

fn run(role: &str, observed_exit: &mut Option<u32>) -> Result<String> {
    let controls = registry::controls().and_then(|(keys, accessible)| {
        mark_panic_phase(PanicPhase::Record);
        if std::env::var_os("REVAYAT_AUTHORITY_FIXTURE").is_some() {
            fixture_record(role, keys, accessible)
        } else {
            record(role, keys, accessible)
        }
    });
    let own = clean(controls)?;
    if role == "descendant" {
        return Ok(own);
    }
    mark_panic_phase(PanicPhase::Descendant);
    let child = process::descendant(observed_exit)?;
    let output = own + &child;
    need(output.is_ascii() && output.len() <= 2048, "report")?;
    Ok(output)
}

fn retain_exit(result: Result<()>, observed_exit: Option<u32>) -> Result<()> {
    result.map_err(|mut failure| {
        if failure.child_exit.is_none() {
            failure.child_exit = observed_exit;
        }
        failure
    })
}

pub fn main() {
    // Private panic payloads/paths never cross the fixed diagnostic transport.
    std::panic::set_hook(Box::new(|_| panic_diagnostic()));
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let descendant = args.len() == 1 && args[0] == "--descendant";
    DESCENDANT.store(descendant, Ordering::Relaxed);
    let baseline = args.len() == 1 && args[0] == "--machine-baseline";
    let role = if descendant { "descendant" } else { "primary" };
    let mut observed_exit = None;
    let result = need(args.is_empty() || descendant || baseline, "start").and_then(|_| {
        if baseline {
            mark_panic_phase(PanicPhase::Baseline);
            registry::machine_baseline()
        } else {
            run(role, &mut observed_exit)
        }
    });
    let result = clean(result).and_then(|wire| {
        mark_panic_phase(PanicPhase::Report);
        let mut output = std::io::stdout().lock();
        output
            .write_all(wire.as_bytes())
            .and_then(|_| output.flush())
            .map_err(|_| Failure::new("report", "native"))
    });
    let code = match retain_exit(result, observed_exit) {
        Ok(()) => 0,
        Err(error) => {
            mark_panic_phase(PanicPhase::FailureReport);
            let wire = error.wire(role);
            let mut output = std::io::stderr().lock();
            if output
                .write_all(wire.as_bytes())
                .and_then(|_| output.flush())
                .is_err()
            {
                std::process::exit(1);
            }
            1
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_exit_survives_cleanup_and_reporting_failures() {
        for phase in [
            PanicPhase::NetworkTcp4,
            PanicPhase::Report,
            PanicPhase::FailureReport,
        ] {
            mark_panic_phase(phase);
            let primary = std::str::from_utf8(panic_frame(false)).expect("fixed frame");
            assert!(protocol::failure_summary(primary).is_some());
            assert!(primary.contains(" errors=panic:"));
            assert!(!primary.contains("cleanup"));
            let descendant = std::str::from_utf8(panic_frame(true)).expect("fixed frame");
            assert!(protocol::failure_summary(descendant).is_none());
        }
        mark_panic_phase(PanicPhase::Start);
        for observed in [None, Some(0), Some(7), Some(0xC0000022)] {
            protocol::cleanup_failed();
            let result = retain_exit(clean(Ok("fixed".into())).map(|_| ()), observed);
            let failure = result.expect_err("cleanup must remain fatal");
            assert_eq!(failure.child_exit, observed);
            assert_eq!(failure.events, vec![("close", "cleanup")]);
            protocol::cleanup_failed();
            let result = clean(Err(Failure::new("root", "control"))).map(|_| ());
            let failure = retain_exit(result, observed).expect_err("operation remains first");
            assert_eq!(failure.child_exit, observed);
            assert_eq!(
                failure.events,
                vec![("root", "control"), ("close", "cleanup")]
            );
            let failure = retain_exit(Err(Failure::new("report", "native")), observed)
                .expect_err("report failed");
            assert_eq!(failure.child_exit, observed);
        }
        let mut original = Failure::new("descendant", "transport");
        original.child_exit = Some(7);
        assert_eq!(
            retain_exit(Err(original), Some(0))
                .expect_err("failed child")
                .child_exit,
            Some(7)
        );
    }
}
