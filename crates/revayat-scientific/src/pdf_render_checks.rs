use super::*;
use crate::pdf_revision_fixture as fixture;

#[test]
fn zero_pixel_region_is_rejected_before_backend_invocation() {
    let f = fixture::Fixture::new(1);
    let output = f.temp.path().join("zero.png");
    let error = render_region(
        &f.source,
        1,
        36,
        [0.0, 0.0, f64::from_bits(1), 1.0],
        &output,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("zero pixels"),
        "unexpected refusal: {error:#}"
    );
    assert!(!output.exists());
}

#[test]
fn sample_batch_rejects_an_earlier_substituted_stage() {
    let f = fixture::Fixture::new(3);
    let prefix = f.temp.path().join("sample");
    let approved = f.temp.path().join("sample-1.png");
    fs::write(&approved, b"approved sample").unwrap();
    let mut first = None::<PathBuf>;
    let mut reached = false;
    let result = sample_set_with_renderer(&f.source, &prefix, |_, _, _, _, _, stage| {
        let expected = fixture::png(stage, 10)?;
        if let Some(first) = &first {
            fixture::png(first, 250)?;
            reached = true;
        } else {
            first = Some(stage.to_owned());
        }
        Ok(expected)
    });
    assert!(reached);
    assert!(result.is_err(), "a substituted sample stage was published");
    assert_eq!(fs::read(&approved).unwrap(), b"approved sample");
    assert!(!f.temp.path().join("sample-2.png").exists());
    assert!(!f.temp.path().join("sample-3.png").exists());
}

#[test]
fn sample_batch_uses_one_source_revision() {
    let f = fixture::Fixture::new(3);
    let original = fs::read(&f.source).unwrap();
    let prefix = f.temp.path().join("sample");
    let mut seen = Vec::new();
    let outputs = sample_set_with_renderer(&f.source, &prefix, |source, _, _, _, _, stage| {
        seen.push(fs::read(source)?);
        let expected = fixture::png(stage, 10)?;
        if seen.len() == 1 {
            f.substitute()?;
        }
        if seen.len() == 2 {
            f.restore()?;
        }
        Ok(expected)
    })
    .unwrap();
    assert_eq!(outputs.len(), 3);
    assert_eq!(
        seen,
        vec![original.clone(), original.clone(), original.clone()],
        "sample rendering reopened a mutable PDF path"
    );
    assert_eq!(fs::read(&f.source).unwrap(), original);
}
