use revayat_scientific::migration::{
    Baseline, BehaviorLedger, ExecutionEvidence, MigrationMap, audit, audit_behavior,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
fn baseline() -> Baseline {
    serde_json::from_value(json!({"schema":1,"baseline_commit":SHA,"public_test_count":1,"tests":[{"id":"legacy::file_create"}]})).unwrap()
}
fn mapping() -> MigrationMap {
    serde_json::from_value(json!({"schema":1,"mappings":[{"legacy_id":"legacy::file_create","rust_test":"native::file_create","rationale":"Exact creation arguments and immediate error refusal remain exercised."}]})).unwrap()
}
fn ledger() -> Value {
    json!({
        "schema":1,"baseline_commit":SHA,
        "identities":[{"id":"legacy::file_create","kind":"test","parent_ids":[],"invokes_ids":["helper::last_error"],"obligation_ids":["file::failure"]},
            {"id":"helper::last_error","kind":"assertion-helper","parent_ids":[],"invokes_ids":[],"obligation_ids":[]}],
        "obligations":[{"id":"file::failure","baseline_ids":["legacy::file_create"],"rust_test":"native::file_create","assertions":["Failure retains immediate code5"],"platforms":["windows"],"tier":"native"}]
    })
}
fn evidence() -> Value {
    json!({"schema":1,"tested_sha":SHA,"run_id":"41722801997","witnesses":[{
        "job":"windows-security","platform":"windows","tier":"native","case_id":"native::file_create","parent_id":null,
        "obligation_ids":["file::failure"],"source":"execution","outcome":"passed","exit":0,"cleanup_complete":true
    }]})
}
fn check(ledger: Value, evidence: Value) -> anyhow::Result<usize> {
    audit_behavior(
        &baseline(),
        &mapping(),
        &serde_json::from_value::<BehaviorLedger>(ledger)?,
        &serde_json::from_value::<ExecutionEvidence>(evidence)?,
        SHA,
        "windows",
        "native",
    )
}

#[test]
fn registered_test_is_not_an_executed_behavior() {
    let mut listed = evidence();
    listed["witnesses"][0]["source"] = json!("registration");
    assert!(check(ledger(), listed).is_err());
    assert_eq!(check(ledger(), evidence()).unwrap(), 1);
}
#[test]
fn no_inventory_cannot_pass_vacuously() {
    let mut baseline = baseline();
    baseline.tests.clear();
    baseline.public_test_count = 0;
    let empty: MigrationMap = serde_json::from_value(json!({"schema":1,"mappings":[]})).unwrap();
    assert!(audit(&baseline, &empty, &BTreeSet::new(), "windows").is_err());
    let mut empty = ledger();
    empty["identities"] = json!([]);
    assert!(check(empty, evidence()).is_err());
}
#[test]
fn duplicate_or_unresolved_relationships_are_rejected() {
    let mut duplicate = ledger();
    let identity = duplicate["identities"][0].clone();
    duplicate["identities"]
        .as_array_mut()
        .unwrap()
        .push(identity);
    assert!(check(duplicate, evidence()).is_err());
    for field in ["parent_ids", "invokes_ids", "obligation_ids"] {
        let mut broken = ledger();
        broken["identities"][0][field] = json!(["missing"]);
        assert!(check(broken, evidence()).is_err(), "{field}");
    }
    let mut cyclic = ledger();
    cyclic["identities"][1]["invokes_ids"] = json!(["legacy::file_create"]);
    assert!(check(cyclic, evidence()).is_err());
    let mut valid = ledger();
    valid["identities"][1]["parent_ids"] = json!(["legacy::file_create"]);
    assert_eq!(check(valid, evidence()).unwrap(), 1);
}
#[test]
fn helper_does_not_pad_independent_test_count_or_drop_test_obligations() {
    let mut missing = ledger();
    missing["identities"][0]["obligation_ids"] = json!([]);
    assert!(check(missing, evidence()).is_err());
    let mut relabeled = ledger();
    relabeled["identities"][0]["kind"] = json!("assertion-helper");
    assert!(check(relabeled, evidence()).is_err());
}
#[test]
fn foreign_counterpart_or_orphan_obligation_cannot_claim_equivalence() {
    for (field, value) in [
        ("rust_test", json!("native::unrelated")),
        ("baseline_ids", json!(["helper::last_error"])),
        ("assertions", json!([])),
        ("platforms", json!(["unknown"])),
    ] {
        let mut broken = ledger();
        broken["obligations"][0][field] = value;
        assert!(check(broken, evidence()).is_err(), "{field}");
    }
}
#[test]
fn equipped_variant_requires_primary_and_canonical_additional_obligations() {
    let mut map = mapping();
    map.mappings[0]
        .additional_rust_tests
        .push("native::equipped".into());
    let audit = |reviewed: Value, ran: Value| {
        audit_behavior(
            &baseline(),
            &map,
            &serde_json::from_value(reviewed).unwrap(),
            &serde_json::from_value(ran).unwrap(),
            SHA,
            "windows",
            "native",
        )
    };
    assert!(
        audit(ledger(), evidence()).is_err(),
        "declared supporting case has no obligation"
    );
    let mut only_extra = ledger();
    only_extra["obligations"][0]["rust_test"] = json!("native::equipped");
    let mut only_extra_ran = evidence();
    only_extra_ran["witnesses"][0]["case_id"] = json!("native::equipped");
    assert!(
        audit(only_extra, only_extra_ran).is_err(),
        "support cannot replace unique primary"
    );
    let mut reviewed = ledger();
    let mut extra = reviewed["obligations"][0].clone();
    extra["id"] = json!("file::equipped");
    extra["rust_test"] = json!("native::equipped");
    reviewed["obligations"].as_array_mut().unwrap().push(extra);
    reviewed["identities"][0]["obligation_ids"] = json!(["file::failure", "file::equipped"]);
    let mut ran = evidence();
    let mut extra = ran["witnesses"][0].clone();
    extra["case_id"] = json!("native::equipped");
    extra["obligation_ids"] = json!(["file::equipped"]);
    ran["witnesses"].as_array_mut().unwrap().push(extra);
    assert_eq!(audit(reviewed.clone(), ran.clone()).unwrap(), 2);
    ran["witnesses"].as_array_mut().unwrap().remove(0);
    assert!(audit(reviewed.clone(), ran).is_err());
    assert!(
        audit(reviewed, evidence()).is_err(),
        "required supporting execution is missing"
    );
}
#[test]
fn missing_wrong_scope_or_duplicate_witness_is_not_coverage() {
    let mut absent = evidence();
    absent["witnesses"] = json!([]);
    assert!(check(ledger(), absent).is_err());
    for (field, value) in [
        ("platform", json!("linux")),
        ("tier", json!("portable")),
        ("case_id", json!("native::unrelated")),
        ("parent_id", json!("missing-parent")),
        ("obligation_ids", json!(["missing"])),
    ] {
        let mut broken = evidence();
        broken["witnesses"][0][field] = value;
        assert!(check(ledger(), broken).is_err(), "{field}");
    }
    let mut duplicate = evidence();
    let witness = duplicate["witnesses"][0].clone();
    duplicate["witnesses"].as_array_mut().unwrap().push(witness);
    assert!(check(ledger(), duplicate).is_err());
}
#[test]
fn stale_sha_nonexecution_and_bad_exit_or_cleanup_remain_failure() {
    let mut stale = evidence();
    stale["tested_sha"] = json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(check(ledger(), stale).is_err());
    for outcome in [
        "failed",
        "skipped",
        "cancelled",
        "timed-out",
        "not-run",
        "inconclusive",
    ] {
        let mut broken = evidence();
        broken["witnesses"][0]["outcome"] = json!(outcome);
        assert!(check(ledger(), broken).is_err(), "{outcome}");
    }
    for (field, value) in [("exit", json!(1)), ("cleanup_complete", json!(false))] {
        let mut broken = evidence();
        broken["witnesses"][0][field] = value;
        assert!(check(ledger(), broken).is_err(), "{field}");
    }
}
#[test]
fn external_evidence_rejects_unknown_fields_missing_fields_and_unknown_enums() {
    let mut unknown = ledger();
    unknown["identities"][0]["kind"] = json!("invented-test-kind");
    assert!(serde_json::from_value::<BehaviorLedger>(unknown).is_err());
    let mut unknown = evidence();
    unknown["witnesses"][0]["outcome"] = json!("assumed-green");
    assert!(serde_json::from_value::<ExecutionEvidence>(unknown).is_err());
    let mut unknown = evidence();
    unknown["assumed_success"] = json!(true);
    assert!(serde_json::from_value::<ExecutionEvidence>(unknown).is_err());
    let mut missing = ledger();
    missing["identities"][0]
        .as_object_mut()
        .unwrap()
        .remove("obligation_ids");
    assert!(serde_json::from_value::<BehaviorLedger>(missing).is_err());
    let mut missing = evidence();
    missing["witnesses"][0]
        .as_object_mut()
        .unwrap()
        .remove("parent_id");
    assert!(serde_json::from_value::<ExecutionEvidence>(missing).is_err());
    assert!(serde_json::from_value::<ExecutionEvidence>(evidence()).is_ok());
}
#[test]
fn known_parent_requires_reviewed_containment_or_call_relationship() {
    let mut baseline = baseline();
    baseline
        .tests
        .push(revayat_scientific::migration::LegacyTest {
            id: "legacy::parent".into(),
        });
    baseline.public_test_count = 2;
    let mut map = mapping();
    let mut parent = map.mappings[0].clone();
    parent.legacy_id = "legacy::parent".into();
    parent.rust_test = "native::parent".into();
    map.mappings.push(parent);
    let mut ledger = ledger();
    ledger["identities"].as_array_mut().unwrap().push(json!({"id":"legacy::parent","kind":"test","parent_ids":[],"invokes_ids":[],"obligation_ids":["parent::control"]}));
    ledger["obligations"].as_array_mut().unwrap().push(json!({"id":"parent::control","baseline_ids":["legacy::parent"],"rust_test":"native::parent","assertions":["Independent parent control executed"],"platforms":["windows"],"tier":"native"}));
    let mut evidence = evidence();
    evidence["witnesses"][0]["parent_id"] = json!("native::parent");
    let mut witness = evidence["witnesses"][0].clone();
    witness["case_id"] = json!("native::parent");
    witness["parent_id"] = Value::Null;
    witness["obligation_ids"] = json!(["parent::control"]);
    evidence["witnesses"].as_array_mut().unwrap().push(witness);
    let audit = |ledger: Value, evidence: Value| {
        audit_behavior(
            &baseline,
            &map,
            &serde_json::from_value(ledger).unwrap(),
            &serde_json::from_value(evidence).unwrap(),
            SHA,
            "windows",
            "native",
        )
    };
    assert!(audit(ledger.clone(), evidence.clone()).is_err());
    let mut roots = evidence.clone();
    roots["witnesses"][0]["parent_id"] = Value::Null;
    assert_eq!(audit(ledger.clone(), roots.clone()).unwrap(), 2);
    ledger["identities"][0]["parent_ids"] = json!(["legacy::parent"]);
    assert_eq!(audit(ledger.clone(), evidence.clone()).unwrap(), 2);
    assert!(audit(ledger.clone(), roots).is_err());
    ledger["identities"][0]["parent_ids"] = json!([]);
    ledger["identities"][2]["invokes_ids"] = json!(["legacy::file_create"]);
    assert_eq!(audit(ledger, evidence).unwrap(), 2);
}
