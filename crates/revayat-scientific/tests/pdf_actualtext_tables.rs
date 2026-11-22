#[path = "common/pdf.rs"]
mod common;
use lopdf::{
    Object,
    content::{Content, Operation},
    dictionary,
};
use std::fs;

#[test]
fn actualtext_before_text_position_keeps_table_cell_value() {
    for rotation in [0, 90, 180, 270] {
        let fixture = common::Fixture::new();
        let mut doc = common::blank();
        let page = common::pages(&doc)[0];
        let mut operations = Vec::new();
        for x in [30, 330] {
            operations.extend([
                Operation::new("m", vec![x.into(), 340.into()]),
                Operation::new("l", vec![x.into(), 440.into()]),
                Operation::new("S", vec![]),
            ]);
        }
        for y in [340, 440] {
            operations.extend([
                Operation::new("m", vec![30.into(), y.into()]),
                Operation::new("l", vec![330.into(), y.into()]),
                Operation::new("S", vec![]),
            ]);
        }
        operations.extend([
            Operation::new(
                "BDC",
                vec![
                    Object::Name(b"Span".to_vec()),
                    Object::Dictionary(dictionary! {
                        "ActualText" => Object::string_literal("-0.25 mV")
                    }),
                ],
            ),
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec![Object::Name(b"F1".to_vec()), 12.into()]),
            Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    40.into(),
                    410.into(),
                ],
            ),
            Operation::new("Tj", vec![Object::string_literal("painted glyphs")]),
            Operation::new("ET", vec![]),
            Operation::new("EMC", vec![]),
        ]);
        doc.change_page_content(page, Content { operations }.encode().unwrap())
            .unwrap();
        doc.get_object_mut(page)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("Rotate", rotation);
        fixture.save(doc);
        let original = fs::read(&fixture.source).unwrap();
        assert_eq!(
            revayat_scientific::pdf::pdf_text(&fixture.source)
                .unwrap()
                .trim(),
            "-0.25 mV"
        );
        revayat_scientific::pdf_extract::extract_tables(&fixture.source, &fixture.output).unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.output).unwrap()).unwrap();
        assert_eq!(
            report["pages"][0]["tables"][0]["cells"],
            serde_json::json!([["-0.25 mV"]]),
            "ActualText cell was lost at page rotation {rotation}"
        );
        assert_eq!(fs::read(&fixture.source).unwrap(), original);
    }
}
