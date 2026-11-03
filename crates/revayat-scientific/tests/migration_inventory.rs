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
