#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("registry-authority requires Windows x64");

mod native;
mod process;
mod protocol;
mod registry;
mod token;

use protocol::{Failure, Result, need, record, take_cleanup_failure};
use std::io::Write;

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
    let controls =
        registry::controls().and_then(|(keys, accessible)| record(role, keys, accessible));
    let own = clean(controls)?;
    if role == "descendant" {
        return Ok(own);
    }
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

fn main() {
    // Private panic payloads/paths never cross the fixed diagnostic transport.
    std::panic::set_hook(Box::new(|_| {}));
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let descendant = args.len() == 1 && args[0] == "--descendant";
    let role = if descendant { "descendant" } else { "primary" };
    let mut observed_exit = None;
    let result =
        need(args.is_empty() || descendant, "start").and_then(|_| run(role, &mut observed_exit));
    let result = clean(result).and_then(|wire| {
        let mut output = std::io::stdout().lock();
        output
            .write_all(wire.as_bytes())
            .and_then(|_| output.flush())
            .map_err(|_| Failure::new("report", "native"))
    });
    let code = match retain_exit(result, observed_exit) {
        Ok(()) => 0,
        Err(error) => {
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
