use super::*;
#[test]
fn embedded_preflight_enforces_the_aggregate_decoded_byte_budget_before_browser_launch()
-> Result<()> {
    let root = tempfile::tempdir()?;
    let source = root.path().join("source.html");
    fs::write(&source, "<html></html>")?;
    let original = fs::read(&source)?;
    let mut policy = ResourcePolicy::new(&source)?;
    policy.total = MAX_TOTAL_BYTES - 2;
    let result = policy.preflight_urls(
        vec!["data:image/png;base64,YWJj".into()],
        &Url::parse("https://revayat.invalid/source.html")?,
        0,
    );
    assert!(result.is_err());
    assert_eq!(policy.requests, 1);
    assert_eq!(policy.total, MAX_TOTAL_BYTES + 1);
    assert_eq!(fs::read(source)?, original);
    Ok(())
}
