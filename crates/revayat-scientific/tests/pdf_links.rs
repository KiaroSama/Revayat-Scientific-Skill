#[path = "common/pdf.rs"]
mod common;
use common::*;
use lopdf::{Object, dictionary};
use revayat_scientific::{pdf as p, pdf_navigation as n};
use serde_json::json;
use std::fs;
fn preserved_refusals(x: &Fixture, first: usize, last: usize, category: &str) {
    let source = fs::read(&x.source).unwrap();
    for merge in [false, true] {
        x.previous();
        let result = if merge {
            p::merge_pdfs(std::slice::from_ref(&x.source), &x.output)
        } else {
            p::extract_pages(&x.source, &x.output, first, last)
        };
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(category),
            "expected {category:?}, got {error:?}"
        );
        x.preserved();
        assert_eq!(fs::read(&x.source).unwrap(), source);
        assert!(!fs::read_dir(x.temp.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".revayat-")
        }));
    }
}
#[test]
fn test_named_link_boundary_is_explicit() {
    let x = Fixture::new();
    let mut d = document(2);
    let target = pages(&d)[1];
    d.catalog_mut().unwrap().set(
        "Dests",
        dictionary! {"XYZDest"=>vec![target.into(),
        Object::Name(b"XYZ".to_vec()),10.into(),250.into(),1.5.into()]},
    );
    let id = link(&mut d, 0, 1, vec![Object::Name(b"Fit".to_vec())]);
    d.get_object_mut(id)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Dest", Object::Name(b"XYZDest".to_vec()));
    x.save(d);
    let admitted = p::open_pdf(&x.source, false).unwrap();
    let dests = admitted
        .catalog()
        .unwrap()
        .get(b"Dests")
        .unwrap()
        .as_dict()
        .unwrap();
    let values = dests.get(b"XYZDest").unwrap().as_array().unwrap();
    assert_eq!(values[0].as_reference().unwrap(), target);
    assert_eq!(
        &values[1..],
        &[
            Object::Name(b"XYZ".to_vec()),
            10.into(),
            250.into(),
            1.5.into()
        ]
    );
    assert_eq!(
        admitted
            .get_dictionary(id)
            .unwrap()
            .get(b"Dest")
            .unwrap()
            .as_name()
            .unwrap(),
        b"XYZDest"
    );
    preserved_refusals(&x, 1, 2, "named or unresolved page destinations");
}
#[test]
fn test_links_to_omitted_pages_fail_before_output() {
    for backwards in [false, true] {
        let x = Fixture::new();
        let mut d = document(3);
        let (from, target, first, last) = if backwards {
            (1, 0, 2, 3)
        } else {
            (0, 2, 1, 2)
        };
        link(
            &mut d,
            from,
            target,
            vec![
                Object::Name(b"XYZ".to_vec()),
                20.into(),
                350.into(),
                1.25.into(),
            ],
        );
        x.save(d);
        x.previous();
        let before = fs::read(&x.source).unwrap();
        let admitted = p::open_pdf(&x.source, false).unwrap();
        assert_eq!(
            n::links(&admitted, 0, 2, 0).unwrap()[0]["navigation"]["direct"]["page"],
            target
        );
        let error = p::extract_pages(&x.source, &x.output, first, last).unwrap_err();
        assert!(error.to_string().contains("outside copied range"));
        x.preserved();
        assert_eq!(fs::read(&x.source).unwrap(), before);
        assert!(
            !fs::read_dir(x.temp.path())
                .unwrap()
                .any(|entry| entry.unwrap().path().is_dir())
        );
    }
}
#[test]
fn test_supported_navigation_is_verified_before_publication() {
    let x = Fixture::new();
    let mut d = document(3);
    let ids = pages(&d);
    for id in &ids {
        d.get_object_mut(*id)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("MediaBox", vec![0.into(), 0.into(), 240.into(), 360.into()]);
    }
    let local = link(
        &mut d,
        1,
        2,
        vec![
            Object::Name(b"XYZ".to_vec()),
            30.into(),
            290.into(),
            1.25.into(),
        ],
    );
    let annotation = d.get_object_mut(local).unwrap().as_dict_mut().unwrap();
    let destination = annotation.remove(b"Dest").unwrap();
    annotation.set("Rect", vec![10.into(), 320.into(), 80.into(), 340.into()]);
    annotation.set("A", dictionary! {"S"=>"GoTo","D"=>destination});
    let uri = "https://example.invalid/paper?q=1&v=2";
    let external = d.add_object(dictionary! {"Type"=>"Annot","Subtype"=>"Link",
    "Rect"=>vec![10.into(),290.into(),100.into(),310.into()],
    "A"=>dictionary! {"S"=>"URI","URI"=>Object::string_literal(uri)}});
    append_annot(&mut d, ids[1], external);
    x.save(d);
    let before = fs::read(&x.source).unwrap();
    let prefix = x.temp.path().join("prefix.pdf");
    document(1).save(&prefix).unwrap();
    let prefix_before = fs::read(&prefix).unwrap();
    for merge in [false, true] {
        x.previous();
        let mut reached = false;
        let lose_navigation = |boundary, path: &std::path::Path| {
            if boundary == p::PdfBoundary::StageWritten {
                reached = true;
                let mut saved = p::open_pdf(path, false)?;
                for page in pages(&saved) {
                    saved.get_object_mut(page)?.as_dict_mut()?.remove(b"Annots");
                }
                saved.save(path)?;
            }
            Ok(())
        };
        let result = if merge {
            p::merge_pdfs_observed(
                &[prefix.clone(), x.source.clone()],
                &x.output,
                lose_navigation,
            )
        } else {
            p::extract_pages_observed(
                &x.source,
                &x.output,
                2,
                3,
                p::AdmissionLimits::default(),
                lose_navigation,
            )
        };
        assert!(reached);
        assert!(result.unwrap_err().to_string().contains("page links"));
        x.preserved();
        if merge {
            p::merge_pdfs(&[prefix.clone(), x.source.clone()], &x.output).unwrap();
        } else {
            p::extract_pages(&x.source, &x.output, 2, 3).unwrap();
        }
        let output = p::open_pdf(&x.output, false).unwrap();
        let (page, target, count) = if merge { (2, 3, 4) } else { (0, 1, 2) };
        assert_eq!(pages(&output).len(), count);
        let rows = n::links(&output, 0, count - 1, 0).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["page"], page);
        assert_eq!(
            rows[0]["navigation"]["goto"],
            json!({"page":target,"fit":"XYZ","args":[30.0,290.0,1.25]})
        );
        assert_eq!(rows[0]["attributes"]["Rect"], json!([10, 320, 80, 340]));
        assert_eq!(rows[1]["attributes"]["Rect"], json!([10, 290, 100, 310]));
        assert_eq!(
            rows[1]["navigation"]["uri"]["URI"]["string_hex"],
            uri.as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(
            p::geometry(&output).unwrap()[page].rect,
            [0., 0., 240., 360.]
        );
        let page_id = pages(&output)[page];
        let annotations = output
            .get_dictionary(page_id)
            .unwrap()
            .get(b"Annots")
            .unwrap()
            .as_array()
            .unwrap();
        let local = n::resolved(&output, &annotations[0])
            .unwrap()
            .as_dict()
            .unwrap();
        let action = n::resolved(&output, local.get(b"A").unwrap())
            .unwrap()
            .as_dict()
            .unwrap();
        let destination = action.get(b"D").unwrap().as_array().unwrap();
        assert_eq!(
            destination[0].as_reference().unwrap(),
            pages(&output)[target]
        );
        assert_eq!(
            &destination[1..],
            &[
                Object::Name(b"XYZ".to_vec()),
                30.into(),
                290.into(),
                1.25.into()
            ]
        );
        assert_eq!(fs::read(&x.source).unwrap(), before);
        assert_eq!(fs::read(&prefix).unwrap(), prefix_before);
        assert!(
            !fs::read_dir(x.temp.path())
                .unwrap()
                .any(|entry| entry.unwrap().path().is_dir())
        );
    }
}
#[test]
fn test_raw_unresolved_annotations_are_not_silently_omitted() {
    for destination in [
        Object::Null,
        Object::Name(b"MissingDestination".to_vec()),
        Object::string_literal("MissingDestination"),
    ] {
        let x = Fixture::new();
        let mut d = document(2);
        let id = link(&mut d, 0, 1, vec![Object::Name(b"Fit".to_vec())]);
        let annotation = d.get_object_mut(id).unwrap().as_dict_mut().unwrap();
        if destination == Object::Null {
            annotation.remove(b"Dest");
        } else {
            annotation.set("Dest", destination.clone());
        }
        assert_eq!(
            d.get_dictionary(id)
                .unwrap()
                .get(b"Subtype")
                .unwrap()
                .as_name()
                .unwrap(),
            b"Link"
        );
        x.save(d);
        preserved_refusals(
            &x,
            1,
            2,
            if destination == Object::Null {
                "unresolved link annotation"
            } else {
                "named or unresolved page destinations"
            },
        );
    }
}
#[test]
fn test_remote_raw_navigation_is_refused_before_output() {
    let x = Fixture::new();
    let mut d = document(2);
    let id = link(&mut d, 0, 1, vec![Object::Name(b"Fit".to_vec())]);
    let a = d.get_object_mut(id).unwrap().as_dict_mut().unwrap();
    a.remove(b"Dest");
    a.set(
        "A",
        dictionary! {"S"=>"GoToR","F"=>Object::string_literal("other.pdf"),
        "D"=>vec![1.into(),Object::Name(b"XYZ".to_vec()),30.into(),290.into(),1.25.into()]},
    );
    x.save(d);
    preserved_refusals(&x, 1, 2, "named, remote or advanced navigation");
    assert!(!x.temp.path().join("other.pdf").exists());
}
#[test]
fn test_chained_page_actions_fail_before_output() {
    for local in [false, true] {
        let x = Fixture::new();
        let mut d = document(2);
        let id = link(&mut d, 0, 1, vec![Object::Name(b"Fit".to_vec())]);
        let destination = d.get_dictionary(id).unwrap().get(b"Dest").unwrap().clone();
        let a = d.get_object_mut(id).unwrap().as_dict_mut().unwrap();
        a.remove(b"Dest");
        a.set("A", if local {
            dictionary! {"S"=>"GoTo","D"=>destination,"Next"=>dictionary! {"S"=>"URI","URI"=>Object::string_literal("https://example.invalid/next")}}
        } else {
            dictionary! {"S"=>"URI","URI"=>Object::string_literal("https://example.org"),"Next"=>dictionary! {"S"=>"Named","N"=>"FirstPage"}}
        });
        x.save(d);
        preserved_refusals(&x, 1, 2, "chained navigation actions");
    }
}
