//! Closed bounded failure formatting; numeric diagnostics never qualify containment.
use super::*;
impl Failure {
    pub fn new(phase: &'static str, kind: &'static str) -> Self {
        Self {
            events: vec![(phase, kind)],
            child_exit: None,
            restrictions: None,
            native_error: None,
            network_diag: None,
        }
    }

    pub fn wire(&self, role: &str) -> String {
        let code = self
            .child_exit
            .map_or_else(|| "none".into(), |value| format!("{value:08X}"));
        let events = self
            .events
            .iter()
            .take(8)
            .map(|(phase, kind)| format!("{phase}:{kind}"))
            .collect::<Vec<_>>()
            .join(",");
        let restrictions = self
            .restrictions
            .filter(|_| {
                self.native_error.is_none()
                    && self
                        .events
                        .iter()
                        .take(8)
                        .any(|event| *event == ("token", "control-restrictions-query"))
            })
            .map_or_else(String::new, |query| {
                format!(" restrictions={}", query.wire())
            });
        let native = self
            .native_error
            .filter(|_| {
                role == "primary"
                    && self.restrictions.is_none()
                    && self.events.iter().take(8).any(|(phase, kind)| {
                        (*phase == "descendant" && NATIVE_CHECKS.contains(kind))
                            || (*phase == "mutation"
                                && (SCRATCH_CHECKS.contains(kind) || NETWORK_CHECKS.contains(kind)))
                    })
            })
            .map_or_else(String::new, |error| format!(" native_error={error:08X}"));
        let root_status = self
            .native_error
            .filter(|_| {
                role == "primary"
                    && self.restrictions.is_none()
                    && self
                        .events
                        .iter()
                        .take(8)
                        .any(|event| *event == ("root", "control-open"))
            })
            .map_or_else(String::new, |status| format!(" nt_status={status:08X}"));
        let native = if root_status.is_empty() {
            native
        } else {
            String::new()
        };
        let mut frame = format!(
            "REGISTRY_AUTHORITY_FAILURE role={role} child_exit={code} errors={events}{restrictions}{native}{root_status}"
        );
        if let Some(diagnostic) = self.network_diag.as_deref().filter(|_| {
            role == "primary"
                && self.restrictions.is_none()
                && root_status.is_empty()
                && self.native_error.is_some_and(|code| code != 0)
                && self
                    .events
                    .iter()
                    .take(8)
                    .any(|event| *event == ("mutation", "network-startup"))
        }) {
            let field = format!(" network_diag={}", diagnostic.wire());
            if frame.len() + field.len() < 512 {
                frame.push_str(&field);
            }
        }
        frame.push('\n');
        frame
    }
}
