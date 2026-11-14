use super::*;
#[derive(Clone, Debug)]
pub(super) struct Fault(pub Arc<()>);
impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fixed preparation transition")
    }
}
impl std::error::Error for Fault {}
pub(super) struct FixtureIo {
    pub order: Vec<&'static str>,
    pub inside: bool,
    pub host: bool,
    pub success: bool,
    pub label: &'static str,
    pub fail_at: usize,
    pub step: usize,
    pub failure: Arc<()>,
    pub allocations: Vec<PolicyBuffer>,
}
impl FixtureIo {
    pub fn new(kind: Experiment) -> Self {
        Self {
            order: Vec::new(),
            inside: true,
            host: kind != Experiment::Token,
            success: true,
            label: match kind {
                Experiment::Image => "image-bundle",
                Experiment::ActivationBundle => "activation-bundle",
                _ => "create-release",
            },
            fail_at: 0,
            step: 0,
            failure: Arc::new(()),
            allocations: Vec::new(),
        }
    }
    fn visit(&mut self, name: &'static str) -> Result<()> {
        self.step += 1;
        if self.step == self.fail_at {
            return Err(Fault(self.failure.clone()).into());
        }
        self.order.push(name);
        Ok(())
    }
    fn read(&mut self, name: &'static str) -> Result<PolicyBuffer> {
        self.visit(name)?;
        ensure!(self.inside, "policy read outside qualified child token");
        let value = PolicyBuffer::new(EMPTY_POLICY.to_vec());
        self.allocations.push(value.clone());
        Ok(value)
    }
}
impl PreparationIo for FixtureIo {
    fn qualify(&mut self) -> Result<()> {
        self.visit("qualify")?;
        ensure!(self.inside, "different preparation token");
        Ok(())
    }
    fn deadline(&mut self) -> Result<()> {
        self.visit("deadline")
    }
    fn primary(&mut self) -> Result<PolicyBuffer> {
        self.read("primary")
    }
    fn duplicate(&mut self) -> Result<PolicyBuffer> {
        self.read("duplicate")
    }
    fn operation(&mut self) -> Result<bool> {
        self.visit(self.label)?;
        ensure!(
            self.inside != self.host,
            "preparation operation context differs"
        );
        Ok(self.success)
    }
    fn leave(&mut self) -> Result<()> {
        self.visit("leave")?;
        ensure!(self.inside, "preparation leave repeated");
        self.inside = false;
        Ok(())
    }
    fn require_host(&mut self) -> Result<()> {
        self.visit("host")?;
        ensure!(!self.inside, "preparation host still impersonates");
        Ok(())
    }
    fn enter(&mut self) -> Result<()> {
        self.visit("enter")?;
        ensure!(!self.inside, "preparation enter repeated");
        self.inside = true;
        Ok(())
    }
}
pub(super) fn prepared(
    condition: Condition,
    kind: Experiment,
    success: bool,
) -> Result<Observation> {
    let mut value = Observation::new(condition, kind);
    let mut io = FixtureIo::new(kind);
    io.success = success;
    if kind == Experiment::Token {
        prepare_token(&mut value, &mut io)?;
    } else {
        prepare_host(&mut value, &mut io)?;
    }
    if value.call_expected() && !value.compound() {
        value.activation(&if kind == Experiment::Host {
            (if success { CREATED } else { DENIED }).replace("context=lpac", "context=host")
        } else {
            (if success { CREATED } else { DENIED }).into()
        })?;
    }
    Ok(value)
}
pub(super) fn check() -> Result<()> {
    for kind in [
        Experiment::Token,
        Experiment::Host,
        Experiment::Image,
        Experiment::ActivationBundle,
    ] {
        for condition in [
            Condition::Baseline,
            Condition::ChildCreate,
            Condition::BaselineAgain,
        ] {
            let mut value = Observation::new(condition, kind);
            let mut io = FixtureIo::new(kind);
            if kind == Experiment::Token {
                prepare_token(&mut value, &mut io)?;
            } else {
                prepare_host(&mut value, &mut io)?;
            }
            let mut expected = vec![
                "qualify",
                "deadline",
                "primary",
                "duplicate",
                "qualify",
                "deadline",
            ];
            if kind != Experiment::Token {
                expected.extend(["leave", "host", "deadline"]);
            }
            if value.call_expected() {
                expected.push(io.label);
            }
            if kind != Experiment::Token {
                expected.extend(["host", "deadline", "enter"]);
            }
            expected.extend(["qualify", "deadline", "primary", "duplicate"]);
            ensure!(
                io.order == expected
                    && io.inside
                    && value.prepared
                    && value.attempted == value.call_expected()
                    && (!value.compound() || !value.created),
                "preparation exact transition order differs"
            );
            if kind == Experiment::Token {
                ensure!(
                    prepare_token(&mut value, &mut io).is_err(),
                    "preparation reused owner"
                );
            } else {
                ensure!(
                    prepare_host(&mut value, &mut io).is_err(),
                    "host preparation reused owner"
                );
            }
            if value.call_expected() {
                if value.compound() {
                    ensure!(
                        value.activation(CREATED).is_err(),
                        "compound preparation accepted activation receipt"
                    );
                } else if kind == Experiment::Host {
                    ensure!(
                        value.activation(CREATED).is_err(),
                        "host preparation accepted LPAC receipt"
                    );
                    value.activation(&CREATED.replace("context=lpac", "context=host"))?;
                } else {
                    value.activation(CREATED)?;
                }
            }
            value.record(0, "", "")?;
            let metadata = value.metadata()?;
            ensure!(
                metadata.starts_with(&format!("{} condition={}", value.prefix(), value.label())),
                "preparation role metadata differs"
            );
            if value.compound() && value.call_expected() {
                ensure!(
                    value.activation_metadata()?
                        == format!(
                            "{}_CALL condition={} operation_completed=True all_access_succeeded_claimed=False cause_claimed=False target_admitted=False production_grant=False",
                            value.prefix(),
                            value.label()
                        ),
                    "compound call metadata differs"
                );
            }
            value.clear();
            ensure!(
                io.allocations.iter().all(PolicyBuffer::cleared),
                "preparation successful policy buffers not cleared"
            );
        }
        for fail_at in 1..=if kind == Experiment::Token { 11 } else { 17 } {
            let mut value = Observation::new(Condition::ChildCreate, kind);
            let mut io = FixtureIo::new(kind);
            io.fail_at = fail_at;
            let result = if kind == Experiment::Token {
                prepare_token(&mut value, &mut io)
            } else {
                prepare_host(&mut value, &mut io)
            };
            let error = result.unwrap_err();
            ensure!(
                error
                    .downcast_ref::<Fault>()
                    .is_some_and(|f| Arc::ptr_eq(&f.0, &io.failure))
                    && !value.prepared
                    && !value.policy_retained()
                    && io.allocations.iter().all(PolicyBuffer::cleared),
                "preparation transition failure identity/zeroing differs kind={kind:?} step={fail_at}"
            );
        }
        if kind != Experiment::Token {
            ensure!(
                prepare_token(
                    &mut Observation::new(Condition::Baseline, kind),
                    &mut FixtureIo::new(kind)
                )
                .is_err(),
                "compound/host used token preparation"
            );
        }
        if matches!(kind, Experiment::Image | Experiment::ActivationBundle) {
            ensure!(
                Observation::new(Condition::Baseline, kind)
                    .complete_bundle()
                    .is_err(),
                "fresh compound operation marked complete"
            );
            for code in [0, 1, 121, 0xc0000022, 0xc0150002, u32::MAX] {
                let mut value = prepared(Condition::ChildCreate, kind, true)?;
                ensure!(
                    value.record(code, "private-sentinel", "").is_err()
                        && value.record(code, "", "private-sentinel").is_err(),
                    "compound accepted pass output"
                );
                value.record(code, "", "")?;
                ensure!(
                    value.exit == code
                        && value.completed == (code == 0)
                        && value
                            .metadata()?
                            .contains(&format!("raw_process_exit=0x{code:08X}"))
                        && value.record(code, "", "").is_err(),
                    "compound pass result differs"
                );
                value.clear();
            }
        }
    }
    ensure!(
        prepare_host(
            &mut Observation::new(Condition::Baseline, Experiment::Token),
            &mut FixtureIo::new(Experiment::Token)
        )
        .is_err(),
        "token used host preparation"
    );
    let before = PolicyBuffer::new(EMPTY_POLICY.to_vec());
    let wrong = PolicyBuffer::new(vec![4, 0, 8, 0, 0, 0, 0, 0]);
    ensure!(
        equal_and_clear(&before, wrong.clone()).is_err() && wrong.cleared(),
        "mismatching policy not cleared"
    );
    before.clear();
    require_bundle_registry_status(0)?;
    for status in [1, 0x40000003, -1, 0xc0000022u32 as i32] {
        ensure!(
            require_bundle_registry_status(status).is_err(),
            "informational/failed bundle registry result accepted"
        );
    }
    Ok(())
}
