use super::*;
use crate::pdf_revision_fixture as fixture;
use std::cell::RefCell;

fn args(f: &fixture::Fixture) -> Args {
    let map = f.temp.path().join("map.tsv");
    fs::write(
        &map,
        "figure_id\tpdf_page\tx0\ty0\tx1\ty1\nfirst\t1\t0\t0\t40\t40\nsecond\t1\t40\t40\t80\t80\n",
    )
    .unwrap();
    Args {
        pdf: f.source.clone(),
        out: f.temp.path().join("figures"),
        map: Some(map),
        cover: false,
        cover_page: 1,
        author_page: 0,
        dpi: 72,
    }
}

#[test]
fn crop_batch_renders_the_admitted_revision_after_source_aba() {
    let f = fixture::Fixture::new(1);
    let a = args(&f);
    let original = fs::read(&f.source).unwrap();
    let mut calls = 0;
    let mut seen = Vec::new();
    let count = crop_document_with_renderer(
        &a,
        Default::default(),
        |boundary, _| {
            if boundary == CropBoundary::BeforeRender {
                calls += 1;
                if calls == 1 {
                    f.substitute()?;
                } else {
                    f.restore()?;
                }
            }
            Ok(())
        },
        |source, _, _, _, _, stage| {
            seen.push(fs::read(source)?);
            fixture::png(stage, 10)
        },
    )
    .unwrap();
    assert_eq!(count, 2);
    assert_eq!(calls, 2, "both real crop boundaries must run");
    assert_eq!(
        seen,
        vec![original.clone(), original.clone()],
        "a crop used a different PDF revision from its plan"
    );
    assert_eq!(fs::read(&f.source).unwrap(), original);
}

#[test]
fn crop_batch_rejects_an_earlier_stage_changed_by_a_later_render() {
    let f = fixture::Fixture::new(1);
    let a = args(&f);
    fs::create_dir(&a.out).unwrap();
    let approved = a.out.join("fig-first.png");
    fs::write(&approved, b"approved crop").unwrap();
    let first = RefCell::new(None::<PathBuf>);
    let mut reached = false;
    let result = crop_document_with_renderer(
        &a,
        Default::default(),
        |boundary, path| {
            if boundary == CropBoundary::BeforeRender && path.ends_with("fig-second.png") {
                fixture::png(first.borrow().as_ref().unwrap(), 250)?;
                reached = true;
            }
            Ok(())
        },
        |_, _, _, _, _, stage| {
            let expected = fixture::png(stage, 10)?;
            if first.borrow().is_none() {
                *first.borrow_mut() = Some(stage.to_owned());
            }
            Ok(expected)
        },
    );
    assert!(
        reached,
        "the first producer must finish before its stage is substituted"
    );
    assert!(result.is_err(), "a substituted crop stage was published");
    assert_eq!(fs::read(&approved).unwrap(), b"approved crop");
    assert!(!a.out.join("fig-second.png").exists());
    assert_eq!(fs::read_dir(&a.out).unwrap().count(), 1);
}

#[test]
fn unchanged_crop_batch_publishes_each_encoded_stage() {
    let f = fixture::Fixture::new(1);
    let a = args(&f);
    assert_eq!(
        crop_document_with_renderer(
            &a,
            Default::default(),
            |_, _| Ok(()),
            |_, _, _, _, _, stage| fixture::png(stage, 10)
        )
        .unwrap(),
        2
    );
    for name in ["fig-first.png", "fig-second.png"] {
        assert_eq!(
            image::open(a.out.join(name))
                .unwrap()
                .to_rgb8()
                .get_pixel(0, 0)
                .0,
            [10, 30, 80]
        );
    }
    assert_eq!(fs::read_dir(&a.out).unwrap().count(), 2);
}

#[test]
fn crop_pdf_byte_limit_does_not_limit_the_separate_map() {
    let f = fixture::Fixture::new(1);
    let a = args(&f);
    let maximum = fs::metadata(&f.source).unwrap().len();
    let spaces = " ".repeat(maximum as usize);
    fs::write(a.map.as_ref().unwrap(), format!("figure_id\tpdf_page\tx0\ty0\tx1\ty1\n{spaces}first\t1\t0\t0\t40\t40\n{spaces}second\t1\t40\t40\t80\t80\n")).unwrap();
    assert!(fs::metadata(a.map.as_ref().unwrap()).unwrap().len() > maximum);
    let limits = pdf::AdmissionLimits {
        max_bytes: maximum,
        ..Default::default()
    };
    assert_eq!(
        crop_document_with_renderer(
            &a,
            limits,
            |_, _| Ok(()),
            |_, _, _, _, _, stage| fixture::png(stage, 10)
        )
        .unwrap(),
        2
    );
}
