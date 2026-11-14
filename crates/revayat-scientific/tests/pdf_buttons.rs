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
    for (label, indirect) in [
        "Yes",
        "On State",
        "A/B",
        "/Leading",
        "A#B",
        "A#20B",
        "État",
        "تایید",
        "Has space",
        "a/b",
        "#Yes",
        "فارسی",
    ]
    .into_iter()
    .flat_map(|label| [false, true].map(|indirect| (label, indirect)))
    {
        let x = Fixture::new();
        let mut d = document(1);
        let id = checkbox(&mut d, "Approved", label);
        if indirect {
            let normal = d
                .get_dictionary(id)
                .unwrap()
                .get(b"AP")
                .unwrap()
                .as_dict()
                .unwrap()
                .get(b"N")
                .unwrap()
                .clone();
            let normal = d.add_object(normal);
            d.get_object_mut(id)
                .unwrap()
                .as_dict_mut()
                .unwrap()
                .set("AP", dictionary! {"N"=>normal});
        }
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
    for label in ["On State", "/Leading", "A#20B", "تایید", "Has space"] {
        let x = Fixture::new();
        let mut d = document(1);
        let id = checkbox(&mut d, "Approved", label);
        x.save(d);
        let report = p::inspect_pdf(&x.source).unwrap();
        assert_eq!(report["fields"][0]["on_state"], label);
        assert!(
            report["fields"][0]["button_states"]["normal"]
                .as_array()
                .unwrap()
                .contains(&json!(label))
        );
        p::fill_pdf(
            &x.source,
            &x.output,
            &fields(json!({"Approved":report["fields"][0]["on_state"]})),
            &[],
        )
        .unwrap();
        assert_eq!(
            f::stored_value(&p::open_pdf(&x.output, false).unwrap(), id)
                .unwrap()
                .as_deref(),
            Some(label)
        );
    }
}
#[test]
fn test_false_and_exact_off_keep_checkbox_unselected() {
    for value in [json!(false), json!("Off")] {
        let x = Fixture::new();
        let mut d = document(1);
        let id = checkbox(&mut d, "Approved", "On State");
        x.save(d);
        p::fill_pdf(
            &x.source,
            &x.output,
            &fields(json!({"Approved":value})),
            &[],
        )
        .unwrap();
        let reopened = p::open_pdf(&x.output, false).unwrap();
        assert_eq!(
            f::stored_value(&reopened, id).unwrap().as_deref(),
            Some("Off")
        );
        assert_eq!(
            reopened
                .get_dictionary(id)
                .unwrap()
                .get(b"AS")
                .unwrap()
                .as_name()
                .unwrap(),
            b"Off"
        );
    }
}
#[test]
fn test_serialized_escape_spelling_is_not_a_second_alias() {
    for (label, encoded) in [("Has space", "Has#20space"), ("On State", "On#20State")] {
        let x = Fixture::new();
        let mut d = document(1);
        checkbox(&mut d, "Approved", label);
        x.save(d);
        let before = fs::read(&x.source).unwrap();
        x.previous();
        assert!(
            p::fill_pdf(
                &x.source,
                &x.output,
                &fields(json!({"Approved":encoded})),
                &[]
            )
            .is_err()
        );
        x.preserved();
        assert_eq!(fs::read(&x.source).unwrap(), before);
    }
}
#[test]
fn test_radio_names_are_decoded_and_only_requested_option_is_selected() {
    for (unselected, selected) in [
        ("Not selected", "Option A"),
        ("Not selected", "A#20B"),
        ("Not selected", "تایید"),
        ("Small / a", "Large # b"),
    ] {
        for shared in [false, true] {
            let x = Fixture::new();
            let mut d = document(1);
            let (parent, kids) = radio(&mut d, "Mode", &[unselected, selected]);
            if !shared {
                for id in &kids {
                    let widget = d.get_object_mut(*id).unwrap().as_dict_mut().unwrap();
                    widget.remove(b"Parent");
                    widget.set("FT", "Btn");
                    widget.set("Ff", 1 << 15);
                    widget.set("T", Object::string_literal("Mode"));
                    widget.set("V", "Off");
                }
                d.catalog_mut().unwrap().set("AcroForm",dictionary! {"Fields"=>kids.iter().copied().map(Object::Reference).collect::<Vec<_>>()});
            }
            let normal = d
                .get_dictionary(kids[1])
                .unwrap()
                .get(b"AP")
                .unwrap()
                .as_dict()
                .unwrap()
                .get(b"N")
                .unwrap()
                .clone();
            let normal = d.add_object(normal);
            d.get_object_mut(kids[1])
                .unwrap()
                .as_dict_mut()
                .unwrap()
                .set("AP", dictionary! {"N"=>normal});
            let inventory = f::inventory(&d).unwrap();
            assert_eq!(
                inventory
                    .iter()
                    .map(|row| row["on_state"].clone())
                    .collect::<Vec<_>>(),
                vec![json!(unselected), json!(selected)]
            );
            x.save(d);
            let before = fs::read(&x.source).unwrap();
            p::fill_pdf(&x.source, &x.output, &fields(json!({"Mode":selected})), &[]).unwrap();
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
                selected.as_bytes()
            );
            if shared {
                assert_eq!(
                    f::stored_value(&d, parent).unwrap().as_deref(),
                    Some(selected)
                );
            } else {
                assert!(
                    kids.iter()
                        .all(|id| !d.get_dictionary(*id).unwrap().has(b"Parent"))
                );
            }
            assert_eq!(fs::read(&x.source).unwrap(), before);
        }
    }
}
#[test]
fn test_mismatched_stored_value_cannot_pass_by_matching_appearance() {
    for label in ["Yes", "On State"] {
        let mut d = document(1);
        let id = checkbox(&mut d, "Approved", label);
        let plan = f::plan_fill(&d, &fields(json!({"Approved":true}))).unwrap();
        f::apply_fill(&mut d, &plan).unwrap();
        d.get_object_mut(id)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("V", "Off");
        assert!(f::verify_fill(&d, &plan).is_err());
    }
}
#[test]
fn test_mismatched_appearance_type_or_value_remains_rejected() {
    for appearance in [
        Object::string_literal("Yes"),
        Object::Name(b"Off".to_vec()),
        Object::Name(b"Unknown".to_vec()),
        Object::Null,
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
    for shared in [false, true] {
        let x = Fixture::new();
        let mut d = document(1);
        let (_, kids) = radio(&mut d, "Mode", &["Yes", "Yes"]);
        if !shared {
            for id in &kids {
                let widget = d.get_object_mut(*id).unwrap().as_dict_mut().unwrap();
                widget.remove(b"Parent");
                widget.set("FT", "Btn");
                widget.set("Ff", 1 << 15);
                widget.set("T", Object::string_literal("Mode"));
                widget.set("V", "Off");
            }
            d.catalog_mut().unwrap().set("AcroForm",dictionary! {"Fields"=>kids.iter().copied().map(Object::Reference).collect::<Vec<_>>()});
        }
        x.save(d);
        let before = fs::read(&x.source).unwrap();
        x.previous();
        assert!(p::fill_pdf(&x.source, &x.output, &fields(json!({"Mode":"Yes"})), &[]).is_err());
        x.preserved();
        assert_eq!(fs::read(&x.source).unwrap(), before);
    }
}
#[test]
#[ignore = "requires Poppler"]
fn test_unrelated_prose_and_unselected_render_stay_intact() {
    let x = Fixture::new();
    let mut d = document(1);
    checkbox(&mut d, "Approved", "Yes");
    x.save(d);
    let before = render(&x.source, 1);
    let original = fs::read(&x.source).unwrap();
    let prose = p::pdf_text(&x.source).unwrap();
    let body = x.temp.path().join("body.pdf");
    let selected_body = x.temp.path().join("selected-body.pdf");
    let mut bare = p::open_pdf(&x.source, false).unwrap();
    bare.get_object_mut(pages(&bare)[0])
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .remove(b"Annots");
    bare.save(&body).unwrap();
    p::fill_pdf(&x.source, &x.output, &fields(json!({"Approved":true})), &[]).unwrap();
    assert_ne!(
        render(&x.output, 1),
        before,
        "selected appearance must really change"
    );
    let mut selected = p::open_pdf(&x.output, false).unwrap();
    selected
        .get_object_mut(pages(&selected)[0])
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .remove(b"Annots");
    selected.save(&selected_body).unwrap();
    assert_eq!(render(&body, 1), render(&selected_body, 1));
    assert_eq!(p::pdf_text(&x.output).unwrap(), prose);
    let deselected = x.temp.path().join("deselected.pdf");
    p::fill_pdf(
        &x.output,
        &deselected,
        &fields(json!({"Approved":false})),
        &[],
    )
    .unwrap();
    assert_eq!(render(&deselected, 1), before);
    assert_eq!(p::pdf_text(&deselected).unwrap(), prose);
    assert_eq!(fs::read(&x.source).unwrap(), original);
}
#[test]
fn test_shared_parent_radio_value_is_verified_after_reopening() {
    let x = Fixture::new();
    let mut d = document(1);
    let (parent, kids) = radio(&mut d, "Mode", &["One", "Two"]);
    x.save(d);
    p::fill_pdf(&x.source, &x.output, &fields(json!({"Mode":"Two"})), &[]).unwrap();
    let d = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(f::stored_value(&d, parent).unwrap().as_deref(), Some("Two"));
    assert_eq!(
        kids.iter()
            .map(|id| d
                .get_dictionary(*id)
                .unwrap()
                .get(b"AS")
                .unwrap()
                .as_name()
                .unwrap())
            .collect::<Vec<_>>(),
        vec![b"Off".as_slice(), b"Two".as_slice()]
    );
}
#[test]
fn test_appearance_derived_radio_value_cannot_hide_wrong_parent_value() {
    let x = Fixture::new();
    let mut d = document(1);
    let (parent, kids) = radio(&mut d, "Mode", &["One", "Two"]);
    let plan = f::plan_fill(&d, &fields(json!({"Mode":"Two"}))).unwrap();
    f::apply_fill(&mut d, &plan).unwrap();
    d.get_object_mut(parent)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("V", "Off");
    x.save(d);
    let d = p::open_pdf(&x.source, false).unwrap();
    assert_eq!(
        d.get_dictionary(kids[1])
            .unwrap()
            .get(b"AS")
            .unwrap()
            .as_name()
            .unwrap(),
        b"Two"
    );
    assert!(f::verify_fill(&d, &plan).is_err());
}
#[test]
fn test_appearance_dictionary_refuses_nonstreams_and_ambiguous_states() {
    for variant in ["nonstream", "ambiguous", "dangling", "null", "empty"] {
        let mut d = document(1);
        let id = checkbox(&mut d, "Approved", "Yes");
        let nonstream = d.add_object(dictionary! {});
        let stream = appearance(&mut d, true);
        let states = match variant {
            "nonstream" => dictionary! {"Off"=>nonstream,"Yes"=>nonstream},
            "ambiguous" => dictionary! {"Off"=>stream,"Yes"=>stream,"Other"=>stream},
            "dangling" => {
                dictionary! {"Off"=>Object::Reference((0,0)),"Yes"=>Object::Reference((0,0))}
            }
            "null" => dictionary! {"Off"=>Object::Null,"Yes"=>Object::Null},
            _ => dictionary! {},
        };
        d.get_object_mut(id)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("AP", dictionary! {"N"=>states});
        let before = d.objects.clone();
        assert!(
            f::plan_fill(&d, &fields(json!({"Approved":true}))).is_err(),
            "{variant}"
        );
        assert_eq!(d.objects, before);
    }
}
#[test]
fn test_native_serialized_names_do_not_depend_on_widget_parser() {
    let x = Fixture::new();
    let mut d = document(1);
    let slash = checkbox(&mut d, "Other", "a/b # c");
    let id = checkbox(&mut d, "Approved", "A#20B");
    x.save(d);
    let raw = fs::read(&x.source).unwrap();
    assert!(raw.windows(3).any(|s| s == b"#2F") || raw.windows(3).any(|s| s == b"#2f"));
    assert!(raw.windows(b"/A#2320B".len()).any(|s| s == b"/A#2320B"));
    let d = p::open_pdf(&x.source, false).unwrap();
    assert!(
        f::button_states(&d, id, b"N")
            .unwrap()
            .unwrap()
            .contains(&"A#20B".to_owned())
    );
    assert!(
        f::button_states(&d, slash, b"N")
            .unwrap()
            .unwrap()
            .contains(&"a/b # c".to_owned())
    );
    assert_eq!(f::inventory(&d).unwrap()[1]["on_state"], "A#20B");
    let plan = f::plan_fill(&d, &fields(json!({"Approved":"A#20B"}))).unwrap();
    assert_eq!(plan[0].value, "A#20B");
}
#[test]
fn test_public_inspect_and_fill_accept_the_same_decoded_labels() {
    for label in ["On State", "a/b"] {
        let x = Fixture::new();
        let mut d = document(1);
        checkbox(&mut d, "Approved", label);
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
        let original = fs::read(&x.source).unwrap();
        assert_eq!(
            p::cli(&[
                "fill".into(),
                x.source.to_string_lossy().into(),
                x.output.to_string_lossy().into(),
                "--fields".into(),
                fields.to_string_lossy().into(),
            ])
            .unwrap(),
            0
        );
        let output = p::inspect_pdf(&x.output).unwrap();
        assert_eq!(output["fields"][0]["value"], label);
        for command in [
            vec![
                "pdf".into(),
                "inspect".into(),
                x.source.as_os_str().to_owned(),
                "--output".into(),
                x.temp.path().join("public.json").into_os_string(),
            ],
            vec![
                "pdf".into(),
                "fill".into(),
                x.source.as_os_str().to_owned(),
                x.output.as_os_str().to_owned(),
                "--fields".into(),
                fields.as_os_str().to_owned(),
            ],
        ] {
            let mut spec = revayat_scientific::runtime::CommandSpec::new(env!(
                "CARGO_BIN_EXE_revayat-scientific"
            ));
            spec.args = command;
            spec.timeout = std::time::Duration::from_secs(25);
            spec.env.insert(
                "REVAYAT_LOG_DIR".into(),
                x.temp.path().join("logs").into_os_string(),
            );
            assert!(revayat_scientific::runtime::run(&spec).unwrap().success());
        }
        let public: serde_json::Value =
            serde_json::from_slice(&fs::read(x.temp.path().join("public.json")).unwrap()).unwrap();
        assert_eq!(public["fields"][0]["on_state"], label);
        assert_eq!(
            p::inspect_pdf(&x.output).unwrap()["fields"][0]["value"],
            label
        );
        assert_eq!(fs::read(&x.source).unwrap(), original);
    }
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
    let before = fs::read(&x.source).unwrap();
    let mut reached = false;
    assert!(
        p::fill_pdf_observed(
            &x.source,
            &x.output,
            &fields(json!({"Approved":true})),
            &[],
            |boundary, path| {
                if boundary == p::PdfBoundary::StageWritten {
                    reached = true;
                    let mut saved = p::open_pdf(path, false)?;
                    let id = f::widgets(&saved)?[0].id;
                    saved.get_object_mut(id)?.as_dict_mut()?.set("V", "Off");
                    saved.save(path)?;
                }
                Ok(())
            }
        )
        .is_err()
    );
    assert!(reached);
    x.preserved();
    assert_eq!(fs::read(&x.source).unwrap(), before);
    assert!(!fs::read_dir(x.temp.path()).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-")
    }));
}
#[test]
fn test_state_reader_limits_and_non_utf8_names_fail_without_mutation() {
    for bad in [
        vec![255],
        vec![233],
        vec![10],
        vec![b'x'; 65536],
        vec![b'a', 0],
    ] {
        let mut d = document(1);
        let id = checkbox(&mut d, "Approved", "Yes");
        let stream = appearance(&mut d, true);
        let states = lopdf::Dictionary::from_iter([
            (b"Off".to_vec(), Object::Reference(stream)),
            (bad, Object::Reference(stream)),
        ]);
        d.get_object_mut(id)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("AP", dictionary! {"N"=>states});
        let before = d.objects.clone();
        assert!(f::button_states(&d, id, b"N").is_err());
        assert!(f::plan_fill(&d, &fields(json!({"Approved":true}))).is_err());
        assert_eq!(d.objects, before);
    }
    let mut d = document(1);
    let id = checkbox(&mut d, "Approved", "Yes");
    let stream = appearance(&mut d, true);
    let mut states = dictionary! {"Off"=>stream};
    for index in 0..1024 {
        states.set(format!("State{index}"), stream);
    }
    d.get_object_mut(id)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("AP", dictionary! {"N"=>states});
    let before = d.objects.clone();
    assert!(
        f::button_states(&d, id, b"N")
            .unwrap_err()
            .to_string()
            .contains("excessive")
    );
    assert_eq!(d.objects, before);
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
    assert!(
        f::stored_value(&d, a)
            .unwrap_err()
            .to_string()
            .contains("cycle")
    );
}
