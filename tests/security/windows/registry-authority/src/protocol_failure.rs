//! Closed failure metadata for the owner. Unknown child diagnostics stay private.
use super::{DESCENDANT_CHECKS, NATIVE_CHECKS, RestrictionQuery, TOKEN_CHECKS};

fn hex(value: &str) -> bool {
    value.len() == 8
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

fn event(value: &str) -> bool {
    let Some((phase, kind)) = value.split_once(':') else {
        return false;
    };
    match phase {
        "token" => kind == "control" || TOKEN_CHECKS.contains(&kind),
        "descendant" => {
            DESCENDANT_CHECKS.contains(&kind)
                || ["control", "native", "transport", "timeout"].contains(&kind)
        }
        "start" => kind == "control",
        "root" => ["control", "control-name", "control-open", "control-handle"].contains(&kind),
        "mutation" | "report" => ["control", "native"].contains(&kind),
        "identity" => ["control", "decode"].contains(&kind),
        "inventory" => ["control", "decode", "timeout"].contains(&kind),
        "close" => kind == "cleanup",
        _ => false,
    }
}

/// Reads only the fixed primary failure wire. It never admits successful containment.
pub fn failure_summary(frame: &str) -> Option<String> {
    if frame.len() > 512 || !frame.is_ascii() {
        return None;
    }
    let body = frame
        .strip_prefix("REGISTRY_AUTHORITY_FAILURE role=primary child_exit=")?
        .strip_suffix('\n')?;
    let (child, body) = body.split_once(" errors=")?;
    if child != "none" && !hex(child) {
        return None;
    }
    let mut fields = body.split(' ');
    let events = fields.next()?;
    let count = events.split(',').count();
    if !(1..=8).contains(&count) || !events.split(',').all(event) {
        return None;
    }
    let detail = match fields.next() {
        None => String::new(),
        Some(field) => {
            if let Some(query) = field.strip_prefix("restrictions=") {
                RestrictionQuery::parse(query)?;
                if !events
                    .split(',')
                    .any(|value| value == "token:control-restrictions-query")
                {
                    return None;
                }
            } else if let Some(status) = field.strip_prefix("nt_status=") {
                if !hex(status)
                    || status == "00000000"
                    || !events.split(',').any(|value| value == "root:control-open")
                {
                    return None;
                }
            } else {
                let code = field.strip_prefix("native_error=")?;
                if !hex(code)
                    || !events.split(',').any(|value| {
                        value
                            .strip_prefix("descendant:")
                            .is_some_and(|kind| NATIVE_CHECKS.contains(&kind))
                    })
                {
                    return None;
                }
            }
            format!(" {field}")
        }
    };
    if fields.next().is_some() {
        return None;
    }
    Some(format!("events={events} child_exit={child}{detail}"))
}
