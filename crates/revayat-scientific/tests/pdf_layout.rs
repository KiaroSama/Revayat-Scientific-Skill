use revayat_scientific::pdf_layout::{Glyph, logical_baseline, logical_text};
fn glyphs(text: &str) -> Vec<Glyph> {
    text.chars()
        .enumerate()
        .map(|(i, c)| Glyph {
            text: c.to_string(),
            x: i as f64 * 10.,
            y: 100.,
            advance: 10.,
            size: 12.,
            axis: [1., 0.],
            actual: false,
        })
        .collect()
}
#[test]
fn physical_persian_glyphs_form_logical_words() {
    assert_eq!(logical_baseline(&glyphs("شهوژپ شور"), None), "روش پژوهش");
}
#[test]
fn negative_statement_remains_negative() {
    assert_eq!(
        logical_baseline(&glyphs("تسین ربتعم هجیتن نیا"), None),
        "این نتیجه معتبر نیست"
    );
}
#[test]
fn scientific_latin_numbers_signs_and_units_remain_in_order() {
    let s = "x = −2.5, 1 ≤ n ≤ 12, m = 0.25 kg";
    assert_eq!(logical_baseline(&glyphs(s), Some("fa-IR")), s);
}
#[test]
fn mixed_rtl_and_signed_latin_expression_follow_physical_runs() {
    assert_eq!(
        logical_baseline(&glyphs("تسا x = −2.5 رادقم"), None),
        "مقدار x = −2.5 است"
    );
}
#[test]
fn french_accents_and_word_order_are_retained() {
    let s = "La mesure dépend des conditions expérimentales.";
    assert_eq!(logical_baseline(&glyphs(s), Some("fa")), s);
}
#[test]
fn explicit_logical_actualtext_is_authoritative() {
    let g = Glyph {
        text: "این نتیجه معتبر نیست".into(),
        x: 100.,
        y: 100.,
        advance: 200.,
        size: 12.,
        axis: [1., 0.],
        actual: true,
    };
    assert_eq!(logical_baseline(&[g], Some("fa")), "این نتیجه معتبر نیست");
}
#[test]
fn explicit_visual_actualtext_is_never_reversed_to_match_a_source() {
    let g = Glyph {
        text: "تسین ربتعم".into(),
        x: 100.,
        y: 100.,
        advance: 200.,
        size: 12.,
        axis: [1., 0.],
        actual: true,
    };
    assert_eq!(logical_baseline(&[g], Some("fa")), "تسین ربتعم");
}
#[test]
fn glyph_paint_order_does_not_select_reading_order() {
    let mut g = glyphs("شهوژپ شور");
    g.reverse();
    assert_eq!(logical_baseline(&g, None), "روش پژوهش");
}
#[test]
fn rotated_baselines_use_their_geometric_axis() {
    let mut g = glyphs("شهوژپ شور");
    for p in &mut g {
        p.y = p.x;
        p.x = 100.;
        p.axis = [0., 1.];
    }
    assert_eq!(logical_text(&g, None), "روش پژوهش\n");
}
#[test]
fn multi_character_tounicode_cluster_keeps_internal_logical_order() {
    let mut g = glyphs("م س");
    g[1].text = "لا".into();
    assert_eq!(logical_baseline(&g, None), "سلام");
}
#[test]
fn superscript_stays_with_the_equation_baseline() {
    let mut g = glyphs("x2+3.14");
    g[1].y -= 5.;
    g[1].size = 7.;
    assert_eq!(logical_text(&g, None), "x2+3.14\n");
}

#[test]
fn scientific_value_and_unit_form_one_ltr_cluster_inside_persian() {
    assert_eq!(logical_baseline(&glyphs("23.5 C امد"), None), "دما 23.5 C");
}
#[test]
fn standalone_negative_number_keeps_its_leading_sign() {
    assert_eq!(
        logical_baseline(&glyphs("تسا −2.5 رادقم"), None),
        "مقدار −2.5 است"
    );
}
#[test]
fn comparison_chain_is_not_mirrored_or_reversed() {
    assert_eq!(
        logical_baseline(&glyphs("تسا 1 ≤ n ≤ 12 طرش"), None),
        "شرط 1 ≤ n ≤ 12 است"
    );
}

#[path = "common/pdf.rs"]
mod common;
use lopdf::{Object, content::Content, dictionary};
use std::fs;
fn authored_pdf(text: &str, actual: bool, rotation: i64) -> common::Fixture {
    let f = common::Fixture::new();
    let mut doc = common::blank();
    let page = common::pages(&doc)[0];
    let (font, mut operations) =
        revayat_scientific::pdf_font::appearance(&mut doc, text, 400., 40.).unwrap();
    if !actual {
        operations.retain(|o| !matches!(o.operator.as_str(), "BDC" | "EMC"));
    }
    let d = doc.get_object_mut(page).unwrap().as_dict_mut().unwrap();
    d.set(
        "Resources",
        dictionary! {"Font"=>dictionary!{"RvForm"=>font}},
    );
    d.set("Rotate", rotation);
    doc.add_to_page_content(page, Content { operations })
        .unwrap();
    f.save(doc);
    f
}
#[test]
fn actual_native_pdf_glyphs_recover_logical_persian_without_actualtext() {
    let value = "این نتیجه معتبر نیست و مقدار x = −2.5 kg است";
    let f = authored_pdf(value, false, 0);
    let before = fs::read(&f.source).unwrap();
    let logical = revayat_scientific::pdf::pdf_text(&f.source).unwrap();
    assert_eq!(
        revayat_scientific::text_order::fold(&logical),
        revayat_scientific::text_order::fold(value)
    );
    assert_ne!(
        revayat_scientific::text_order::fold(
            &revayat_scientific::pdf::stored_pdf_text(&f.source).unwrap()
        ),
        revayat_scientific::text_order::fold(value)
    );
    assert_eq!(fs::read(&f.source).unwrap(), before);
}
#[test]
fn pdf_actualtext_remains_exact_for_logical_and_visual_metadata() {
    for value in [
        "این نتیجه معتبر نیست",
        "تسین ربتعم هجیتن نیا",
        "پژوهشِ عِلْمی: x = −2.5 kg؛ 0123 و ۱۲۳",
        "می‌توان شَدّۀ فارسی را با café و A\u{0301} مقایسه کرد",
    ] {
        let f = authored_pdf(value, true, 0);
        assert_eq!(
            revayat_scientific::pdf::pdf_text(&f.source).unwrap().trim(),
            value
        );
        let document = revayat_scientific::pdf::open_pdf(&f.source, false).unwrap();
        let page = common::pages(&document)[0];
        let content = Content::decode(&document.get_page_content(page)).unwrap();
        let positions: Vec<_> = content
            .operations
            .iter()
            .filter(|operation| operation.operator == "Tm")
            .collect();
        assert!(!positions.is_empty());
        for position in positions {
            assert_eq!(position.operands.len(), 6);
            assert!(position.operands[4].as_float().unwrap().is_finite());
            assert!(position.operands[5].as_float().unwrap().is_finite());
        }
    }
}
#[test]
fn actual_pdf_rotation_does_not_change_text_reading_axis() {
    let value = "مقدار x = 23.5 C معتبر نیست";
    for rotation in [0, 90, 180, 270] {
        let f = authored_pdf(value, false, rotation);
        assert_eq!(
            revayat_scientific::text_order::fold(
                &revayat_scientific::pdf::pdf_text(&f.source).unwrap()
            ),
            revayat_scientific::text_order::fold(value)
        );
    }
}
#[test]
fn cid_and_tj_metrics_keep_physical_spacing_without_mutating_dictionary() {
    let doc = common::document(1);
    let page = common::pages(&doc)[0];
    let resource = revayat_scientific::pdf_forms::inherited(&doc, page, b"Resources")
        .unwrap()
        .unwrap()
        .as_dict()
        .unwrap();
    let input = [
        Object::string_literal("A"),
        Object::Integer(-250),
        Object::string_literal("B"),
    ];
    let style = revayat_scientific::pdf_layout::Style {
        size: 10.,
        character_spacing: 0.5,
        word_spacing: 0.,
        horizontal_scale: 2.,
    };
    let (glyphs, total) =
        revayat_scientific::pdf_layout::decode_glyphs(&doc, resource, b"F1", &input, style, false)
            .unwrap();
    assert_eq!(
        glyphs.iter().map(|g| g.text.as_str()).collect::<String>(),
        "A B"
    );
    assert_eq!(glyphs[2].origin, 16.);
    assert_eq!(total, 27.);
}

#[test]
fn glyph_budget_is_enforced_while_decoding_not_after_allocation() {
    let doc = common::document(1);
    let page = common::pages(&doc)[0];
    let resources = revayat_scientific::pdf_forms::inherited(&doc, page, b"Resources")
        .unwrap()
        .unwrap()
        .as_dict()
        .unwrap();
    let style = revayat_scientific::pdf_layout::Style {
        size: 12.,
        character_spacing: 0.,
        word_spacing: 0.,
        horizontal_scale: 1.,
    };
    let error = revayat_scientific::pdf_layout::decode_glyphs_with_limit(
        &doc,
        resources,
        b"F1",
        &[Object::string_literal("ABCDE")],
        style,
        false,
        4,
    )
    .unwrap_err();
    assert!(error.to_string().contains("glyph budget"));
}
