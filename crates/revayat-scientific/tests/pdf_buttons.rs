#[path = "common/pdf.rs"]
mod common;
use common::*;
use lopdf::{Object, dictionary};
use revayat_scientific::{pdf as p, pdf_forms as f};
use serde_json::json;
use std::fs;
fn fields(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    v.as_object().unwrap().clone()
}
#[test]
fn test_checkbox_booleans_select_all_supported_name_encodings() {
    for label in ["Yes", "Has space", "a/b", "#Yes", "فارسی"] {
        let x = Fixture::new();
        let mut d = document(1);
        let id = checkbox(&mut d, "Approved", label);
        x.save(d);
        let source = fs::read(&x.source).unwrap();
        p::fill_pdf(&x.source, &x.output, &fields(json!({"Approved":true})), &[]).unwrap();
        let after = p::open_pdf(&x.output, false).unwrap();
        assert_eq!(f::stored_value(&after, id).unwrap().as_deref(), Some(label));
        assert_eq!(
            after
                .get_dictionary(id)
                .unwrap()
                .get(b"AS")
                .unwrap()
                .as_name()
                .unwrap(),
            label.as_bytes()
        );
        assert_eq!(fs::read(&x.source).unwrap(), source);
    }
}
#[test]
fn test_inventory_advertises_decoded_names_that_are_valid_fill_inputs() {
    let x = Fixture::new();
    let mut d = document(1);
    checkbox(&mut d, "Approved", "Has space");
    x.save(d);
    let report = p::inspect_pdf(&x.source).unwrap();
    assert_eq!(report["fields"][0]["on_state"], "Has space");
    p::fill_pdf(
        &x.source,
        &x.output,
        &fields(json!({"Approved":report["fields"][0]["on_state"]})),
        &[],
    )
    .unwrap();
}
#[test]
fn test_false_and_exact_off_keep_checkbox_unselected() {
    for value in [json!(false), json!("Off")] {
        let x = Fixture::new();
        let mut d = document(1);
        let id = checkbox(&mut d, "Approved", "Yes");
        x.save(d);
        p::fill_pdf(
            &x.source,
            &x.output,
            &fields(json!({"Approved":value})),
            &[],
        )
        .unwrap();
        assert_eq!(
            f::stored_value(&p::open_pdf(&x.output, false).unwrap(), id)
                .unwrap()
                .as_deref(),
            Some("Off")
        );
    }
}
#[test]
fn test_serialized_escape_spelling_is_not_a_second_alias() {
    let x = Fixture::new();
    let mut d = document(1);
    checkbox(&mut d, "Approved", "Has space");
    x.save(d);
    x.previous();
    assert!(
        p::fill_pdf(
            &x.source,
            &x.output,
            &fields(json!({"Approved":"Has#20space"})),
            &[]
        )
        .is_err()
    );
    x.preserved();
}
#[test]
fn test_radio_names_are_decoded_and_only_requested_option_is_selected() {
    let x = Fixture::new();
    let mut d = document(1);
    let (parent, kids) = radio(&mut d, "Mode", &["Small / a", "Large # b"]);
    x.save(d);
    p::fill_pdf(
        &x.source,
        &x.output,
        &fields(json!({"Mode":"Large # b"})),
        &[],
    )
    .unwrap();
    let d = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(
        d.get_dictionary(kids[0])
            .unwrap()
            .get(b"AS")
            .unwrap()
            .as_name()
            .unwrap(),
        b"Off"
    );
    assert_eq!(
        d.get_dictionary(kids[1])
            .unwrap()
            .get(b"AS")
            .unwrap()
            .as_name()
            .unwrap(),
        b"Large # b"
    );
    assert_eq!(
        f::stored_value(&d, parent).unwrap().as_deref(),
        Some("Large # b")
    );
}
#[test]
fn test_mismatched_stored_value_cannot_pass_by_matching_appearance() {
    let mut d = document(1);
    let id = checkbox(&mut d, "Approved", "Yes");
    let plan = f::plan_fill(&d, &fields(json!({"Approved":true}))).unwrap();
    f::apply_fill(&mut d, &plan).unwrap();
    d.get_object_mut(id)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("V", "Off");
    assert!(f::verify_fill(&d, &plan).is_err());
}
#[test]
fn test_mismatched_appearance_type_or_value_remains_rejected() {
    for appearance in [
        Object::string_literal("Yes"),
        Object::Name(b"Off".to_vec()),
        Object::Name(b"Unknown".to_vec()),
    ] {
        let mut d = document(1);
        let id = checkbox(&mut d, "Approved", "Yes");
        let plan = f::plan_fill(&d, &fields(json!({"Approved":true}))).unwrap();
        f::apply_fill(&mut d, &plan).unwrap();
        d.get_object_mut(id)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("AS", appearance);
        assert!(f::verify_fill(&d, &plan).is_err());
    }
}
#[test]
fn test_duplicate_on_states_across_radio_widgets_are_rejected_before_writes() {
    let x = Fixture::new();
    let mut d = document(1);
    radio(&mut d, "Mode", &["Yes", "Yes"]);
    x.save(d);
    let before = fs::read(&x.source).unwrap();
    x.previous();
    assert!(p::fill_pdf(&x.source, &x.output, &fields(json!({"Mode":"Yes"})), &[]).is_err());
    x.preserved();
    assert_eq!(fs::read(&x.source).unwrap(), before);
}
#[test]
#[ignore = "requires Poppler"]
fn test_unrelated_prose_and_unselected_render_stay_intact() {
    let x = Fixture::new();
    let mut d = document(1);
    checkbox(&mut d, "Approved", "Yes");
    x.save(d);
    let before = render(&x.source, 1);
    p::fill_pdf(
        &x.source,
        &x.output,
        &fields(json!({"Approved":false})),
        &[],
    )
    .unwrap();
    assert_eq!(render(&x.output, 1), before);
    assert_eq!(
        p::pdf_text(&x.source).unwrap(),
        p::pdf_text(&x.output).unwrap()
    );
}
#[test]
fn test_shared_parent_radio_value_is_verified_after_reopening() {
    let x = Fixture::new();
    let mut d = document(1);
    let (parent, _) = radio(&mut d, "Mode", &["One", "Two"]);
    x.save(d);
    p::fill_pdf(&x.source, &x.output, &fields(json!({"Mode":"Two"})), &[]).unwrap();
    let d = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(f::stored_value(&d, parent).unwrap().as_deref(), Some("Two"));
}
#[test]
fn test_appearance_derived_radio_value_cannot_hide_wrong_parent_value() {
    let mut d = document(1);
    let (parent, _) = radio(&mut d, "Mode", &["One", "Two"]);
    let plan = f::plan_fill(&d, &fields(json!({"Mode":"Two"}))).unwrap();
    f::apply_fill(&mut d, &plan).unwrap();
    d.get_object_mut(parent)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("V", "One");
    assert!(f::verify_fill(&d, &plan).is_err());
}
#[test]
fn test_appearance_dictionary_refuses_nonstreams_and_ambiguous_states() {
    for ambiguous in [false, true] {
        let mut d = document(1);
        let id = checkbox(&mut d, "Approved", "Yes");
        let nonstream = d.add_object(dictionary! {});
        let mut states = dictionary! {"Off"=>nonstream,"Yes"=>nonstream};
        if ambiguous {
            let stream = appearance(&mut d, true);
            states = dictionary! {"Off"=>stream,"Yes"=>stream,"Other"=>stream};
        }
        d.get_object_mut(id)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("AP", dictionary! {"N"=>states});
        assert!(f::plan_fill(&d, &fields(json!({"Approved":true}))).is_err());
    }
}
#[test]
fn test_native_serialized_names_do_not_depend_on_widget_parser() {
    let x = Fixture::new();
    let mut d = document(1);
    let id = checkbox(&mut d, "Approved", "a/b # c");
    x.save(d);
    let raw = fs::read(&x.source).unwrap();
    assert!(raw.windows(3).any(|s| s == b"#2F") || raw.windows(3).any(|s| s == b"#2f"));
    let d = p::open_pdf(&x.source, false).unwrap();
    assert!(
        f::button_states(&d, id, b"N")
            .unwrap()
            .unwrap()
            .contains(&"a/b # c".to_owned())
    );
}
#[test]
fn test_public_inspect_and_fill_accept_the_same_decoded_labels() {
    let x = Fixture::new();
    let mut d = document(1);
    checkbox(&mut d, "Approved", "a/b");
    x.save(d);
    let report = x.temp.path().join("inspect.json");
    assert_eq!(
        p::cli(&[
            "inspect".into(),
            x.source.to_string_lossy().into(),
            "--output".into(),
            report.to_string_lossy().into()
        ])
        .unwrap(),
        0
    );
    let value: serde_json::Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    let fields = x.temp.path().join("fields.json");
    fs::write(
        &fields,
        json!({"Approved":value["fields"][0]["on_state"]}).to_string(),
    )
    .unwrap();
    p::cli(&[
        "fill".into(),
        x.source.to_string_lossy().into(),
        x.output.to_string_lossy().into(),
        "--fields".into(),
        fields.to_string_lossy().into(),
    ])
    .unwrap();
}
#[test]
fn test_late_saved_value_verification_failure_preserves_previous_delivery() {
    let x = Fixture::new();
    let mut d = document(1);
    checkbox(&mut d, "Approved", "Yes");
    x.save(d.clone());
    x.previous();
    let expected = p::geometry(&d).unwrap();
    let result = p::save_document(
        &mut d,
        &x.output,
        std::slice::from_ref(&x.source),
        &expected,
        |_| anyhow::bail!("injected stored value failure"),
    );
    assert!(result.is_err());
    x.preserved();
    assert!(!fs::read_dir(x.temp.path()).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-")
    }));
}
#[test]
fn test_state_reader_limits_and_non_utf8_names_fail_without_mutation() {
    let mut d = document(1);
    let id = checkbox(&mut d, "Approved", "Yes");
    let stream = appearance(&mut d, true);
    for bad in [vec![255], vec![b'x'; 65536], vec![b'a', 0]] {
        let states = lopdf::Dictionary::from_iter([
            (b"Off".to_vec(), Object::Reference(stream)),
            (bad, Object::Reference(stream)),
        ]);
        d.get_object_mut(id)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("AP", dictionary! {"N"=>states});
        assert!(f::button_states(&d, id, b"N").is_err());
    }
}
#[test]
fn test_stored_value_parent_cycles_fail_instead_of_looping() {
    let mut d = document(1);
    let a = d.add_object(dictionary! {});
    let b = d.add_object(dictionary! {"Parent"=>a});
    d.get_object_mut(a)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Parent", b);
    assert!(f::stored_value(&d, a).is_err());
}
