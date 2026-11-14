use super::*;
use revayat_scientific::{
    migration::execution::{
        CaseOutcome,
        events::{OperationEvent, VariantOutcome},
    },
    windows_security::preparation,
};
use std::{cell::Cell, sync::Arc};

const OWNER: &str = "crates/revayat-scientific/test/windows_contract::bootstrap::controller_markers_preserve_validation_order";
const SITES: [u16; 19] = [
    26, 27, 32, 33, 37, 68, 69, 72, 74, 75, 76, 89, 94, 95, 96, 100, 105, 115, 119,
];

#[derive(Default)]
pub(super) struct SiteJournal(Vec<OperationEvent>);
impl SiteJournal {
    /// Called by the carrier only after the specific assertion and every reached loop variant.
    pub(super) fn observe(&mut self, line: u16, variants: &[String], helper: &str) {
        assert_eq!(SITES.get(self.0.len()), Some(&line));
        self.0.push(OperationEvent {
            case_id: format!("tests/security/windows/Check-RuntimePreparation.ps1::Require@{line}"),
            parent_id: OWNER.into(),
            sequence: self.0.len() + 1,
            invokes_ids: vec![format!(
                "crates/revayat-scientific/src/windows_security/preparation.rs::{helper}"
            )],
            obligation_ids: vec![format!("RUNTIME-PREPARATION-L{line}")],
            source: "execution".into(),
            outcome: CaseOutcome::Passed,
            exit: 0,
            cleanup_complete: false,
            assertions_complete: true,
            variants: variants
                .iter()
                .map(|id| VariantOutcome {
                    id: id.clone(),
                    outcome: CaseOutcome::Passed,
                })
                .collect(),
            check_results: vec![],
        });
    }
    pub(super) fn finish(self) {
        assert_eq!(self.0.len(), SITES.len());
        let Some(directory) = std::env::var_os("REVAYAT_RUNTIME_PREPARATION_EVENT_DIR") else {
            return;
        };
        let directory = Path::new(&directory);
        assert!(directory.is_absolute());
        plain_path(directory).unwrap();
        let path = directory.join("runtime-preparation-observations.json");
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        let value = serde_json::json!({
            "schema": 1,
            "population": "runtime-preparation",
            "owner_case_id": OWNER,
            "events": self.0,
        });
        serde_json::to_writer(&mut output, &value).unwrap();
        output.sync_all().unwrap();
    }
}

fn progress(
    events: &mut Vec<String>,
    output: &mut Vec<u8>,
    phase: &str,
    state: &str,
    count: i64,
) -> preparation::PreparationResult<()> {
    preparation::write_preparation_progress(
        &mut |message| {
            events.push(message.into());
            Ok(())
        },
        output,
        phase,
        state,
        count,
    )
}

pub(super) fn assert_original_preparation_contract(journal: &mut SiteJournal) {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source فارسی");
    let destination = directory.path().join("destination");
    std::fs::create_dir_all(source.join("empty")).unwrap();
    std::fs::create_dir_all(source.join("nested")).unwrap();
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(source.join("nested/a[1].txt"), "fixture فارسی".as_bytes()).unwrap();
    let hidden = source.join(".hidden");
    std::fs::write(&hidden, b"hidden fixture").unwrap();
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_HIDDEN, SetFileAttributesW};
        let name: Vec<u16> = hidden.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: name is a live NUL-terminated path with no embedded NUL.
        assert_ne!(
            unsafe { SetFileAttributesW(name.as_ptr(), FILE_ATTRIBUTE_HIDDEN) },
            0
        );
    }
    let mut events = Vec::new();
    let mut output = Vec::new();
    preparation::assert_source_tree(&source, "python-lib", |p, s, c| {
        progress(&mut events, &mut output, p, s, c)
    })
    .unwrap();
    assert_eq!(
        events,
        [
            "runtime preparation phase=python-lib state=before count=0",
            "runtime preparation phase=python-lib state=after count=4",
        ]
    );
    assert_eq!(
        String::from_utf8(output.clone()).unwrap(),
        format!(
            "WINDOWS_RUNTIME_PREPARATION phase=python-lib state=before count=0{}WINDOWS_RUNTIME_PREPARATION phase=python-lib state=after count=4{}",
            preparation::NEWLINE,
            preparation::NEWLINE
        )
    );
    journal.observe(89, &[], "assert_source_tree");

    events.clear();
    output.clear();
    progress(&mut events, &mut output, "copy-python-trees", "before", 0).unwrap();
    preparation::copy_runtime_tree(&source, &destination, "copy-python-trees", |p, s, c| {
        progress(&mut events, &mut output, p, s, c)
    })
    .unwrap();
    assert_eq!(
        events,
        [
            "runtime preparation phase=copy-python-trees state=before count=0",
            "runtime preparation phase=copy-python-trees state=after count=2",
        ]
    );
    journal.observe(94, &[], "copy_runtime_tree");
    assert_eq!(
        std::fs::read(destination.join("source فارسی/nested/a[1].txt")).unwrap(),
        "fixture فارسی".as_bytes()
    );
    assert_eq!(
        std::fs::read(destination.join("source فارسی/.hidden")).unwrap(),
        b"hidden fixture"
    );
    journal.observe(95, &[], "copy_runtime_tree");
    assert!(destination.join("source فارسی/empty").is_dir());
    journal.observe(96, &[], "copy_runtime_tree");

    events.clear();
    output.clear();
    let produced = Cell::new(0);
    let items = (0..257).map(|_| {
        produced.set(produced.get() + 1);
        Ok(preparation::SourceEntry {
            path: directory.path().join("not-executed.txt"),
            is_directory: false,
            is_reparse_point: false,
        })
    });
    preparation::measure_runtime_copy("copy-python-leaves", items, |p, s, c| {
        assert_eq!(produced.get(), c);
        progress(&mut events, &mut output, p, s, c)
    })
    .unwrap();
    assert_eq!(
        events,
        [
            "runtime preparation phase=copy-python-leaves state=copied count=256",
            "runtime preparation phase=copy-python-leaves state=after count=257",
        ]
    );
    journal.observe(100, &[], "measure_runtime_copy");

    let mut refused = Vec::new();
    for (id, phase, state, count) in [
        ("private-phase", "private/path", "before", 0),
        ("private-state", "python-lib", "secret", 0),
        ("negative-count", "python-lib", "after", -1),
    ] {
        events.clear();
        output.clear();
        assert!(progress(&mut events, &mut output, phase, state, count).is_err());
        assert!(events.is_empty() && output.is_empty());
        refused.push(id.to_owned());
    }
    journal.observe(105, &refused, "write_preparation_progress");

    events.clear();
    output.clear();
    let requests = Cell::new(0);
    let entries = std::iter::from_fn(|| {
        requests.set(requests.get() + 1);
        assert_eq!(
            requests.get(),
            1,
            "producer advanced after rejected reparse point"
        );
        Some(Ok(preparation::SourceEntry {
            path: source.join("link"),
            is_directory: false,
            is_reparse_point: true,
        }))
    });
    let caught = preparation::assert_source_tree_stream(
        &source,
        "python-lib",
        || Ok(entries),
        |p, s, c| progress(&mut events, &mut output, p, s, c),
    )
    .unwrap_err();
    assert_eq!(
        caught.to_string(),
        "Prepared runtime copy source contains a reparse point"
    );
    assert_eq!(requests.get(), 1);
    assert_eq!(
        events,
        ["runtime preparation phase=python-lib state=before count=0"]
    );
    journal.observe(115, &[], "assert_source_tree_stream");

    let original: preparation::SharedError =
        Arc::new(std::io::Error::other("fixed enumeration failure"));
    let caught = preparation::assert_source_tree_stream(
        &source,
        "python-lib",
        || {
            Err::<std::iter::Empty<preparation::PreparationResult<preparation::SourceEntry>>, _>(
                original.clone(),
            )
        },
        |p, s, c| progress(&mut events, &mut output, p, s, c),
    )
    .unwrap_err();
    assert!(Arc::ptr_eq(&caught, &original));
    assert_eq!(caught.to_string(), "fixed enumeration failure");
    journal.observe(119, &[], "assert_source_tree_stream");
    // These are actual owned fixture cleanup results, not a child process certificate.
    directory.close().unwrap();
}
#[test]
fn diagnostics_precede_independent_admission() {
    let diagnostic = Receipt::new(Phase::Prepare, Fault::Control);
    assert!(authority::child_record(diagnostic.wire().unwrap().as_bytes()).is_err());
}
#[test]
fn scratch_observer_is_not_admission() {
    let directory = tempfile::tempdir().unwrap();
    plain_path(directory.path()).unwrap();
    assert!(authority::child_record(b"plain_path=true\n").is_err());
}
#[test]
fn supported_policy_refuses_nested_or_repeated_trial() {
    let mut state = Lifecycle::Running;
    assert!(state.advance(Lifecycle::Suspended).is_err());
    assert!(state.advance(Lifecycle::Running).is_err());
}
#[test]
fn owned_lifecycle_recovery_requires_reap() {
    let mut value = Lifecycle::Running;
    assert!(value.advance(Lifecycle::Closed).is_err());
    value.advance(Lifecycle::Reaped).unwrap();
    value.advance(Lifecycle::Restored).unwrap();
    value.advance(Lifecycle::Closed).unwrap();
}
#[test]
fn successful_consumer_requires_independent_token_control() {
    let record = authority::record("descendant", 0, 0).unwrap();
    assert!(
        authority::child_record(record.replace("\"lpac\":true", "\"lpac\":false").as_bytes())
            .is_err()
    );
}
#[test]
fn native_authority_is_distinct_from_diagnostics() {
    assert!(authority::child_record(b"WINDOWS_PREFLIGHT_FAILURE\n").is_err());
    assert!(
        authority::child_record(authority::record("primary", 0, 0).unwrap().as_bytes()).is_err()
    );
}
#[test]
fn image_preparation_refuses_unsafe_leaf_names() {
    for name in [
        "image.exe:",
        "image.exe.",
        "image.exe ",
        "COM1.exe",
        "../image.exe",
    ] {
        assert!(relative_leaf(Path::new(name)).is_err());
    }
    assert!(relative_leaf(Path::new("registry-authority.exe")).is_ok());
}
#[test]
fn token_stage_allowlist_does_not_accept_private_values() {
    assert!(authority::token_kind("control-priv-value").is_some());
    for bad in [
        "control-priv-value\n",
        "private-token",
        "CONTROL-PRIV-VALUE",
    ] {
        assert!(authority::token_kind(bad).is_none());
    }
}
#[test]
fn descendant_errors_keep_native_boundary() {
    let error = authority::descendant_native(false, "control-resume", || 0xc0000022).unwrap_err();
    assert_eq!(error.events, [("descendant", "control-resume")]);
    assert_eq!(error.native_error, Some(0xc0000022));
}
#[test]
fn restrictions_query_uses_immediate_failure_only() {
    use std::cell::Cell;
    let calls = Cell::new(0);
    assert!(
        authority::restriction_need(1, 4, || {
            calls.set(1);
            99
        })
        .is_ok()
    );
    assert_eq!(calls.get(), 0);
    assert!(
        authority::restriction_need(0, 4, || {
            calls.set(1);
            5
        })
        .is_err()
    );
    assert_eq!(calls.get(), 1);
}
#[test]
fn privilege_full_luid_cannot_alias_by_low_part() {
    assert!(privilege_inventory(&privileges(&[(23, 2), (23 | (1u64 << 32), 2)]), 28).is_err());
}
#[test]
fn admission_requires_fresh_exact_record() {
    let fresh = authority::record("descendant", 2, 0).unwrap();
    for altered in [
        fresh.replace("true", "false"),
        fresh.replace("\"accessible\":0", "\"accessible\":00"),
        format!("{fresh}{fresh}"),
    ] {
        assert!(authority::child_record(altered.as_bytes()).is_err());
    }
}
#[test]
fn native_launch_preserves_aggregate_job_prerequisites() {
    let expected = JobLimits::default();
    assert_eq!(expected.processes, 8);
    assert_eq!(expected.job_memory, 512 * 1024 * 1024);
    assert_eq!(expected.cpu_seconds, 30);
    assert!(expected.validate().is_ok());
}
#[test]
fn preparation_failure_has_one_ordered_boundary() {
    let mut receipt = Receipt::new(Phase::Prepare, Fault::Native);
    receipt.retain(Phase::Close, Fault::Cleanup);
    assert_eq!(
        Receipt::parse(receipt.wire().unwrap().as_bytes())
            .unwrap()
            .failures[0],
        (Phase::Prepare, Fault::Native)
    );
}
#[test]
fn prerequisite_failures_are_private_and_nonzero() {
    let value = Receipt::new(Phase::Prerequisite, Fault::Control);
    assert!(value.wire().unwrap().contains("prerequisite"));
    assert!(Receipt::parse(b"{}\n").is_err());
}
#[test]
fn reported_metadata_is_closed() {
    let wire = frame().wire().unwrap();
    for unknown in ["{\"path\":\"private\",", "{\"command\":\"secret\","] {
        assert!(Receipt::parse(wire.replacen('{', unknown, 1).as_bytes()).is_err());
    }
}
#[test]
fn fixed_controls_can_be_checked_without_kernel_claim() {
    assert!(JobLimits::browser().validate().is_ok());
    assert!(JobLimits::ownership().validate().is_ok());
    let outer = JobLimits::security_bootstrap();
    assert_eq!(
        (
            outer.processes,
            outer.process_memory,
            outer.job_memory,
            outer.cpu_seconds
        ),
        (64, 0, 0, 0)
    );
    assert!(outer.validate().is_ok());
    assert_ne!(outer, JobLimits::browser());
    assert_ne!(outer, JobLimits::ownership());
    for altered in [
        JobLimits {
            processes: 63,
            ..outer
        },
        JobLimits {
            cpu_seconds: 1,
            ..outer
        },
        JobLimits {
            process_memory: 1,
            ..outer
        },
    ] {
        assert!(altered.validate().is_err());
    }
    let invalid = JobLimits {
        processes: 9,
        ..Default::default()
    };
    assert!(invalid.validate().is_err());
}
#[test]
fn failure_projection_preserves_exit_order_and_privacy() {
    let mut value = Receipt::new(Phase::Wait, Fault::Exit);
    value.observe_exit(u32::MAX);
    value.retain(Phase::Close, Fault::Cleanup);
    let wire = value.wire().unwrap();
    assert_eq!(Receipt::parse(wire.as_bytes()).unwrap(), value);
    assert!(!wire.contains("private"));
}
#[test]
fn streaming_copy_refuses_reparse_source() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    std::fs::write(&source, b"content").unwrap();
    let link = directory.path().join("link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&source, &link).unwrap();
    #[cfg(windows)]
    {
        let target = directory.path().join("junction-target");
        std::fs::create_dir(&target).unwrap();
        super::windows_junction::create(&link, &target).unwrap();
        use std::os::windows::fs::MetadataExt;
        assert_ne!(
            std::fs::symlink_metadata(&link).unwrap().file_attributes() & 0x400,
            0
        );
    }
    assert!(plain_path(&link).is_err());
    assert!(plain_path(&source).is_ok());
    for selected in [
        link.clone(),
        link.join("missing-child"),
        link.join("../source"),
    ] {
        assert!(
            preparation::assert_source_path(&selected).is_err(),
            "reparse source spelling was accepted: {selected:?}"
        );
        assert_eq!(
            preparation::assert_source_path(&selected)
                .unwrap_err()
                .to_string(),
            "Prepared copy source or ancestor is a reparse point"
        );
    }
    preparation::assert_source_path(&source).unwrap();
    preparation::assert_source_path(&directory.path().join("not-created/../not-created")).unwrap();

    let produced = Cell::new(0);
    let entries = (0..257).map(|_| {
        produced.set(produced.get() + 1);
        Ok(preparation::SourceEntry {
            path: source.clone(),
            is_directory: false,
            is_reparse_point: false,
        })
    });
    let mut observations = Vec::new();
    preparation::assert_source_tree_stream(
        directory.path(),
        "python-lib",
        || Ok(entries),
        |phase, state, count| {
            assert_eq!(phase, "python-lib");
            assert_eq!(produced.get(), count);
            observations.push((state.to_owned(), count));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        observations,
        [
            ("before".to_owned(), 0),
            ("validated".to_owned(), 256),
            ("after".to_owned(), 257)
        ]
    );
}
