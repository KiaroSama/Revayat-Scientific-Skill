#[path = "common/pdf.rs"]
mod common;
use common::*;
use lopdf::{Object, dictionary};
use revayat_scientific::{pdf as p, pdf_navigation as n};
#[test]
fn test_named_link_boundary_is_explicit() {
    let x = Fixture::new();
    let mut d = document(2);
    let id = link(&mut d, 0, 1, vec![Object::Name(b"Fit".to_vec())]);
    d.get_object_mut(id)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Dest", Object::Name(b"named-target".to_vec()));
    x.save(d);
    x.previous();
    assert!(p::merge_pdfs(std::slice::from_ref(&x.source), &x.output).is_err());
    x.preserved();
}
#[test]
fn test_links_to_omitted_pages_fail_before_output() {
    let x = Fixture::new();
    let mut d = document(3);
    link(&mut d, 0, 2, vec![Object::Name(b"Fit".to_vec())]);
    x.save(d);
    x.previous();
    assert!(p::extract_pages(&x.source, &x.output, 1, 2).is_err());
    x.preserved();
}
#[test]
fn test_supported_navigation_is_verified_before_publication() {
    let x = Fixture::new();
    let mut d = document(2);
    link(
        &mut d,
        0,
        1,
        vec![
            Object::Name(b"XYZ".to_vec()),
            Object::Null,
            220.into(),
            1.25.into(),
        ],
    );
    let expected = n::links(&d, 0, 1, 0).unwrap();
    x.save(d);
    p::extract_pages(&x.source, &x.output, 1, 2).unwrap();
    assert_eq!(
        n::links(&p::open_pdf(&x.output, false).unwrap(), 0, 1, 0).unwrap(),
        expected
    );
}
#[test]
fn test_raw_unresolved_annotations_are_not_silently_omitted() {
    let x = Fixture::new();
    let mut d = document(2);
    let id = link(&mut d, 0, 1, vec![Object::Name(b"Fit".to_vec())]);
    d.get_object_mut(id)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .remove(b"Dest");
    x.save(d);
    x.previous();
    assert!(p::merge_pdfs(std::slice::from_ref(&x.source), &x.output).is_err());
    x.preserved();
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
        dictionary! {"S"=>"GoToR","F"=>Object::string_literal("other.pdf"),"D"=>0},
    );
    x.save(d);
    x.previous();
    assert!(p::merge_pdfs(std::slice::from_ref(&x.source), &x.output).is_err());
    x.preserved();
}
#[test]
fn test_chained_page_actions_fail_before_output() {
    let x = Fixture::new();
    let mut d = document(2);
    let id = link(&mut d, 0, 1, vec![Object::Name(b"Fit".to_vec())]);
    let a = d.get_object_mut(id).unwrap().as_dict_mut().unwrap();
    a.remove(b"Dest");
    a.set("A",dictionary!{"S"=>"URI","URI"=>Object::string_literal("https://example.org"),"Next"=>dictionary!{"S"=>"Named","N"=>"FirstPage"}});
    x.save(d);
    x.previous();
    assert!(p::merge_pdfs(std::slice::from_ref(&x.source), &x.output).is_err());
    x.preserved();
}
