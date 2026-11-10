use revayat_scientific::migration::{
    Baseline, LegacyTest, Mapping, MigrationMap, audit, audit_censuses,
};
use std::collections::BTreeSet;
fn baseline() -> Baseline {
    Baseline {
        schema: 1,
        baseline_commit: "0123456789abcdef0123456789abcdef01234567".into(),
        public_test_count: 2,
        tests: vec![
            LegacyTest {
                id: "old::one".into(),
            },
            LegacyTest {
                id: "old::two".into(),
            },
        ],
    }
}
fn mapping(old: &str, new: &str) -> Mapping {
    Mapping {
        legacy_id: old.into(),
        rust_test: new.into(),
        additional_rust_tests: vec![],
        rationale: "Exercises the original mutation/refusal boundary using native Rust objects"
            .into(),
        platforms: vec![],
    }
}
#[test]
fn missing_old_cases_cannot_be_hidden_by_many_new_tests() {
    let tests = (0..100).map(|i| format!("new::{i}")).collect();
    let report = audit(
        &baseline(),
        &MigrationMap {
            schema: 1,
            mappings: vec![],
        },
        &tests,
        "linux",
    )
    .unwrap();
    assert_eq!(report.pending, ["old::one", "old::two"]);
    assert_eq!(report.registered_rust_tests, 100);
}
#[test]
fn one_rust_case_cannot_fill_two_legacy_rows() {
    let map = MigrationMap {
        schema: 1,
        mappings: vec![
            mapping("old::one", "new::one"),
            mapping("old::two", "new::one"),
        ],
    };
    assert!(audit(&baseline(), &map, &BTreeSet::new(), "linux").is_err());
}
#[test]
fn unknown_legacy_identity_is_rejected() {
    let map = MigrationMap {
        schema: 1,
        mappings: vec![mapping("unknown", "new::one")],
    };
    assert!(audit(&baseline(), &map, &BTreeSet::new(), "linux").is_err());
}
#[test]
fn duplicate_legacy_rows_are_rejected() {
    let map = MigrationMap {
        schema: 1,
        mappings: vec![
            mapping("old::one", "new::one"),
            mapping("old::one", "new::two"),
        ],
    };
    assert!(audit(&baseline(), &map, &BTreeSet::new(), "linux").is_err());
}
#[test]
fn listed_source_names_do_not_establish_registered_tests() {
    let map = MigrationMap {
        schema: 1,
        mappings: vec![
            mapping("old::one", "new::one"),
            mapping("old::two", "new::two"),
        ],
    };
    let report = audit(
        &baseline(),
        &map,
        &BTreeSet::from(["new::one".into()]),
        "linux",
    )
    .unwrap();
    assert_eq!(report.unavailable, ["new::two"]);
    assert!(report.pending.is_empty());
}
#[test]
fn platform_native_cases_remain_in_complete_inventory() {
    let mut windows = mapping("old::two", "native::windows");
    windows.platforms = vec!["windows".into()];
    let map = MigrationMap {
        schema: 1,
        mappings: vec![mapping("old::one", "new::one"), windows],
    };
    let listed = BTreeSet::from(["new::one".into()]);
    let linux = audit(&baseline(), &map, &listed, "linux").unwrap();
    assert!(linux.pending.is_empty());
    assert!(linux.unavailable.is_empty());
    assert_eq!(linux.mapped_tests, 2);
    let windows = audit(&baseline(), &map, &listed, "windows").unwrap();
    assert_eq!(windows.unavailable, ["native::windows"]);
}
#[test]
fn baseline_count_cannot_be_reduced_without_changing_inventory() {
    let mut baseline = baseline();
    baseline.public_test_count = 1;
    assert!(
        audit(
            &baseline,
            &MigrationMap {
                schema: 1,
                mappings: vec![]
            },
            &BTreeSet::new(),
            "linux"
        )
        .is_err()
    );
}
#[test]
fn complete_unique_registered_mapping_passes() {
    let map = MigrationMap {
        schema: 1,
        mappings: vec![
            mapping("old::one", "new::one"),
            mapping("old::two", "new::two"),
        ],
    };
    let report = audit(
        &baseline(),
        &map,
        &BTreeSet::from(["new::one".into(), "new::two".into()]),
        "linux",
    )
    .unwrap();
    assert_eq!(report.mapped_tests, 2);
    assert!(report.pending.is_empty() && report.unavailable.is_empty());
}

#[test]
fn reviewed_extra_counterparts_never_replace_primary_or_pad_the_baseline() {
    let mut one = mapping("old::one", "new::one");
    one.additional_rust_tests = vec!["new::equipped".into()];
    let mut map = MigrationMap {
        schema: 1,
        mappings: vec![one, mapping("old::two", "new::two")],
    };
    let registered = BTreeSet::from(["new::one".into(), "new::two".into(), "new::equipped".into()]);
    let report = audit(&baseline(), &map, &registered, "linux").unwrap();
    assert_eq!(report.mapped_tests, 2);
    assert!(report.unavailable.is_empty());
    let mut missing = registered.clone();
    missing.remove("new::one");
    assert_eq!(
        audit(&baseline(), &map, &missing, "linux")
            .unwrap()
            .unavailable,
        ["new::one"]
    );
    missing = registered.clone();
    missing.remove("new::equipped");
    assert_eq!(
        audit(&baseline(), &map, &missing, "linux")
            .unwrap()
            .unavailable,
        ["new::equipped"]
    );
    map.mappings[0].additional_rust_tests = vec!["new::two".into()];
    assert!(
        audit(&baseline(), &map, &registered, "linux")
            .unwrap()
            .unavailable
            .is_empty()
    );
    let without_second = BTreeSet::from(["new::one".into(), "new::equipped".into()]);
    assert!(
        !audit(&baseline(), &map, &without_second, "linux")
            .unwrap()
            .unavailable
            .is_empty()
    );
    for extra in [
        vec!["new::one".into()],
        vec!["new::equipped".into(), "new::equipped".into()],
        vec!["".into()],
    ] {
        map.mappings[0].additional_rust_tests = extra;
        assert!(audit(&baseline(), &map, &registered, "linux").is_err());
    }
}

#[test]
fn verifier_registration_floor_is_reported_separately_and_missing_case_fails() {
    use revayat_scientific::runtime::{CommandSpec, run};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut registered = BTreeSet::new();
    for name in [
        "rust-migration-map",
        "upstream-rust-migration-map",
        "security-rust-migration-map",
        "verifier-rust-migration-map",
    ] {
        let map: MigrationMap = serde_json::from_slice(
            &std::fs::read(root.join(format!("tests/{name}.json"))).unwrap(),
        )
        .unwrap();
        for mapping in map.mappings {
            registered.insert(mapping.rust_test);
            registered.extend(mapping.additional_rust_tests);
        }
    }
    let verifier: MigrationMap = serde_json::from_slice(
        &std::fs::read(root.join("tests/verifier-rust-migration-map.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(verifier.mappings.len(), 14);
    assert!(registered.remove(&verifier.mappings[0].rust_test));
    let owned = tempfile::tempdir().unwrap();
    let registry = owned.path().join("registered cases.json");
    std::fs::write(&registry, serde_json::to_vec(&registered).unwrap()).unwrap();
    let mut command = CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args(["migration-check", "--root"])
        .args([root.as_os_str()])
        .args(["--registry"])
        .args([registry.as_os_str()])
        .args(["--census", "verifier"]);
    command.cwd = Some(owned.path().to_owned());
    command.timeout = std::time::Duration::from_secs(30);
    let refused = run(&command).unwrap();
    assert!(!refused.success());
    command.args.push("--report-only".into());
    let report = run(&command).unwrap();
    assert!(report.success(), "{}", report.stderr_text());
    let value: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(value["verifier"]["legacy_tests"], 14);
    assert_eq!(value["verifier"]["mapped_tests"], 14);
    assert_eq!(
        value["verifier"]["unavailable"],
        serde_json::json!([verifier.mappings[0].rust_test])
    );
    assert_eq!(value["evidence_level"], "registration_only");
    assert_eq!(value["execution_unverified"], true);
    assert_eq!(value["final_parity_verified"], false);
}

#[test]
fn standalone_security_inventory_cannot_reuse_a_public_test_or_change_history() {
    let public = baseline();
    let mut security = baseline();
    security.tests = vec![LegacyTest {
        id: "security::one".into(),
    }];
    security.public_test_count = 1;
    let public_map = MigrationMap {
        schema: 1,
        mappings: vec![
            mapping("old::one", "native::one"),
            mapping("old::two", "native::two"),
        ],
    };
    let mut security_map = MigrationMap {
        schema: 1,
        mappings: vec![mapping("security::one", "native::one")],
    };
    assert!(audit_censuses(&[(&public, &public_map), (&security, &security_map)]).is_err());
    security_map.mappings[0].rust_test = "security::unique".into();
    audit_censuses(&[(&public, &public_map), (&security, &security_map)]).unwrap();
    security.baseline_commit = "a".repeat(40);
    assert!(audit_censuses(&[(&public, &public_map), (&security, &security_map)]).is_err());
}
