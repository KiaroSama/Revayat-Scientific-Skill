//! Browser-independent admission for data URLs which bypass DevTools Fetch.
use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use revayat_scientific::{
    html::ParsedHtml,
    resource::{MAX_TOTAL_BYTES, ResourcePolicy},
    resource_preflight::{css_urls, html_urls, srcset_urls, svg_urls},
};
use std::{fs, path::Path};
fn source(root: &Path, body: &str) -> std::path::PathBuf {
    let path = root.join("source.html");
    fs::write(
        &path,
        format!("<!doctype html><html><head></head><body>{body}</body></html>"),
    )
    .unwrap();
    path
}
#[test]
fn actual_html_data_urls_are_admitted_before_browser_fetch_can_be_bypassed() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = source(
        root.path(),
        "<img src='data:image/png;base64,YWJj'><img src='data:image/png,%00%01'>",
    );
    let before = fs::read(&path)?;
    let mut policy = ResourcePolicy::new(&path)?;
    assert_eq!((policy.requests, policy.total), (2, 5));
    assert_eq!(policy.fetch("data:image/png;base64,YWJj")?.0, b"abc");
    assert_eq!(
        (policy.requests, policy.total),
        (2, 5),
        "actual Fetch must consume its existing admission"
    );
    policy.fetch("data:image/png;base64,YWJj")?;
    assert_eq!(
        (policy.requests, policy.total),
        (3, 8),
        "additional actual requests still consume budget"
    );
    assert_eq!(fs::read(path)?, before);
    Ok(())
}
#[test]
fn actual_data_request_count_overflow_is_refused_before_renderer_or_output_mutation() -> Result<()>
{
    let root = tempfile::tempdir()?;
    let path = source(
        root.path(),
        &"<img src='data:image/png;base64,YWJj'>".repeat(2048),
    );
    let output = root.path().join("approved.pdf");
    fs::write(&output, b"approved")?;
    let before = fs::read(&path)?;
    let mut renderer_called = false;
    let result = revayat_scientific::render::render_html_with(&path, &output, None, |_, _| {
        renderer_called = true;
        anyhow::bail!("renderer must not launch");
    });
    assert!(result.is_err());
    assert!(!renderer_called);
    assert_eq!(fs::read(output)?, b"approved");
    assert_eq!(fs::read(path)?, before);
    Ok(())
}
#[test]
fn css_tokenizer_handles_nested_rules_escaped_urls_imports_and_image_set_strings() -> Result<()> {
    let css = r#"@namespace svg url(http://www.w3.org/2000/svg); @import /*gap*/ "nested.css"; @media print {p {background:u\72l("d\61ta:image/png,abc")} @supports(display:grid){i{background-image:image-set("data:image/png,def" 1x, url(data:image/png,ghi) 2x)}}} .x{content:"url(data:text/html,literal)";font-family:local("data:text/html,not-url")}"#;
    assert_eq!(
        css_urls(css)?,
        [
            "nested.css",
            "data:image/png,abc",
            "data:image/png,def",
            "data:image/png,ghi"
        ]
    );
    Ok(())
}
#[test]
fn comments_rcdata_plain_attribute_examples_and_css_content_strings_are_not_resources() -> Result<()>
{
    let root = tempfile::tempdir()?;
    let path = source(
        root.path(),
        "<!-- <img src='data:text/html,comment'> --><textarea><img src='data:text/html,rcdata'><style>x{background:url(data:text/html,example)}</style></textarea><p title='data:text/html,metadata' data-note='url(data:text/html,literal)'>مثال</p><input type=text src='data:text/html,ignored'><style>p::before{content:'data:text/html,string';}</style>",
    );
    let p = ResourcePolicy::new(&path)?;
    assert_eq!((p.requests, p.total), (0, 0));
    assert!(html_urls(&ParsedHtml::parse(&p.source_text)?)?.is_empty());
    Ok(())
}
#[test]
fn unsupported_embedded_mime_is_denied_in_src_srcset_css_and_svg_references() -> Result<()> {
    let root = tempfile::tempdir()?;
    for body in [
        "<img src='data:text/html,active'>",
        "<source srcset='data:font/woff2,abc 1x'>",
        "<p style='background:url(data:application/javascript,active)'>x</p>",
        "<style>@import 'data:text/css,p{}';</style>",
        "<svg><image href='data:text/html,active'/></svg>",
        "<svg><set attributeName=href to='data:image/png,abc'/></svg>",
    ] {
        let path = source(root.path(), body);
        let before = fs::read(&path)?;
        assert!(ResourcePolicy::new(&path).is_err(), "{body}");
        assert_eq!(fs::read(&path)?, before);
    }
    Ok(())
}
#[test]
fn srcset_preserves_embedded_commas_and_skips_balanced_descriptors() -> Result<()> {
    assert_eq!(
        srcset_urls("data:image/png,abc 1x, second.png 2x, data:image/png,def 300w")?,
        ["data:image/png,abc", "second.png", "data:image/png,def"]
    );
    assert_eq!(
        srcset_urls("first.png, second.png")?,
        ["first.png", "second.png"]
    );
    assert!(srcset_urls("first.png (unclosed").is_err());
    Ok(())
}
#[test]
fn local_css_imports_fonts_and_images_remain_allowed_without_double_charging_network_bytes()
-> Result<()> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("styles"))?;
    fs::write(
        root.path().join("styles/main.css"),
        "@import 'nested.css'; @font-face{font-family:Body;src:url('../normal.woff2')} p{background:url('../normal.png')}",
    )?;
    fs::write(
        root.path().join("styles/nested.css"),
        "@media print {p{background-image:url(data:image/png,abc)}}",
    )?;
    fs::write(root.path().join("normal.woff2"), b"font fixture")?;
    fs::write(root.path().join("normal.png"), b"image fixture")?;
    let source = source(root.path(), "<link rel=stylesheet href='styles/main.css'>");
    let mut p = ResourcePolicy::new(&source)?;
    assert_eq!((p.requests, p.total), (1, 3));
    let css = p.fetch("https://revayat.invalid/styles/main.css")?.0;
    assert_eq!((p.requests, p.total), (2, 3 + css.len()));
    let nested = p.fetch("https://revayat.invalid/styles/nested.css")?.0;
    assert_eq!((p.requests, p.total), (3, 3 + css.len() + nested.len()));
    p.fetch("data:image/png,abc")?;
    assert_eq!((p.requests, p.total), (3, 3 + css.len() + nested.len()));
    assert!(p.fetch("https://revayat.invalid/normal.woff2").is_ok());
    assert!(p.fetch("https://revayat.invalid/normal.png").is_ok());
    Ok(())
}
#[test]
fn nested_svg_images_and_styles_are_admitted_but_dtd_scripts_and_animations_are_refused()
-> Result<()> {
    let root = tempfile::tempdir()?;
    let svg = "<svg xmlns='http://www.w3.org/2000/svg'><style>g{fill:url(#safe)}</style><image href='data:image/png,abc'/><desc><![CDATA[<!doctype is literal text]]></desc></svg>";
    assert_eq!(svg_urls(svg.as_bytes())?, ["#safe", "data:image/png,abc"]);
    let encoded = STANDARD.encode(svg);
    let path = source(
        root.path(),
        &format!("<img src='data:image/svg+xml;base64,{encoded}'>"),
    );
    let p = ResourcePolicy::new(&path)?;
    assert_eq!(p.requests, 2);
    assert_eq!(p.total, svg.len() + 3);
    for svg in [
        "<!DOCTYPE svg [<!ENTITY x 'value'>]><svg/>",
        "<svg><script>active</script></svg>",
        "<svg><animate attributeName='href'/></svg>",
        "<svg onload='active()'/>",
    ] {
        assert!(svg_urls(svg.as_bytes()).is_err(), "{svg}");
    }
    Ok(())
}
#[test]
fn external_svg_processing_instructions_and_nested_references_are_checked() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("art.svg"),
        "<?xml-stylesheet type='text/css' href='svg.css'?><svg xmlns='http://www.w3.org/2000/svg'><image href='data:image/png,abc'/></svg>",
    )?;
    fs::write(
        root.path().join("svg.css"),
        "svg{background:url(data:image/png,def)}",
    )?;
    let path = source(root.path(), "<img src='art.svg'>");
    let p = ResourcePolicy::new(&path)?;
    assert_eq!((p.requests, p.total), (2, 6));
    fs::write(
        root.path().join("svg.css"),
        "@import 'https://evil.invalid/steal.css';",
    )?;
    assert!(ResourcePolicy::new(&path).is_err());
    Ok(())
}
#[test]
fn malformed_css_and_dependency_cycles_are_bounded_without_ignoring_live_data_urls() -> Result<()> {
    assert!(css_urls("p{background:url('broken\nurl')}").is_err());
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("a.css"),
        "@import 'b.css';p{background:url(data:image/png,abc)}",
    )?;
    fs::write(root.path().join("b.css"), "@import 'a.css';")?;
    let path = source(root.path(), "<link rel=stylesheet href=a.css>");
    let p = ResourcePolicy::new(&path)?;
    assert_eq!((p.requests, p.total), (1, 3));
    assert_eq!(p.resources.len(), 3);
    assert!(MAX_TOTAL_BYTES > p.total);
    Ok(())
}
#[test]
#[ignore = "requires native sandboxed Chromium; scientific CI validates actual data-image rendering and pre-launch rejection"]
fn native_browser_admits_image_data_and_preserves_source_but_refuses_unsupported_data_before_launch()
-> Result<()> {
    let root = tempfile::tempdir()?;
    let mut encoded = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
        8,
        8,
        image::Rgb([180, 200, 220]),
    ))
    .write_to(&mut encoded, image::ImageFormat::Png)?;
    let path = source(
        root.path(),
        &format!(
            "<p>Native image data</p><img src='data:image/png;base64,{}'>",
            STANDARD.encode(encoded.into_inner())
        ),
    );
    let before = fs::read(&path)?;
    let output = root.path().join("actual.pdf");
    let browser = revayat_scientific::render::discover_browser(None)?;
    revayat_scientific::render::render_html(&path, &output, &browser, None)?;
    let document = revayat_scientific::pdf::open_pdf(&output, false)?;
    let (_, images) = revayat_scientific::pdf_content::artwork(&document, 1)?;
    assert!(
        images.iter().any(|image| image.width == 8
            && image.height == 8
            && image.bbox[2] > image.bbox[0]
            && image.bbox[3] > image.bbox[1]),
        "the admitted data image must actually be painted into the native PDF"
    );
    assert_eq!(fs::read(&path)?, before);
    let previous = fs::read(&output)?;
    fs::write(&path, "<html><img src='data:text/html,forbidden'></html>")?;
    assert!(revayat_scientific::render::render_html(&path, &output, &browser, None).is_err());
    assert_eq!(fs::read(&output)?, previous);
    Ok(())
}
#[test]
fn dynamic_image_string_and_xml_base_cannot_hide_embedded_resource_admission() -> Result<()> {
    assert!(
        css_urls(":root{--image:'data:text/html,hidden'}p{background:image-set(var(--image) 1x)}")
            .is_err()
    );
    assert_eq!(
        css_urls("p{background:src('data:image/png,abc')}")?,
        ["data:image/png,abc"]
    );
    let root = tempfile::tempdir()?;
    let path = source(
        root.path(),
        "<svg xml:base='data:text/html,hidden'><use href='#x'/></svg>",
    );
    assert!(ResourcePolicy::new(&path).is_err());
    assert!(svg_urls(b"<svg xml:base='data:text/html,hidden'><use href='#x'/></svg>").is_err());
    let path = source(
        root.path(),
        "<svg><linearGradient href='data:text/html,hidden'/></svg>",
    );
    assert!(ResourcePolicy::new(&path).is_err());
    Ok(())
}
#[test]
fn canonical_resource_path_substitution_is_refused_before_reading_any_foreign_bytes() -> Result<()>
{
    use revayat_scientific::resource::ReadBoundary;
    let outer = tempfile::tempdir()?;
    let root = outer.path().join("job");
    fs::create_dir(&root)?;
    let asset = root.join("image.png");
    fs::write(&asset, b"approved asset")?;
    let outside = outer.path().join("private.png");
    fs::write(&outside, b"private sentinel")?;
    let source = source(&root, "");
    let mut policy = ResourcePolicy::new(&source)?;
    let mut reads = 0;
    let error = policy
        .fetch_observed("https://revayat.invalid/image.png", |event, path| {
            if event == ReadBoundary::BeforeOpen {
                #[cfg(unix)]
                fs::remove_file(path)?;
                #[cfg(unix)]
                std::os::unix::fs::symlink(&outside, path)?;
                #[cfg(windows)]
                {
                    let pinned_original = fs::File::open(path)?;
                    let foreign = root.join("foreign-replacement.png");
                    fs::copy(&outside, &foreign)?;
                    assert_ne!(
                        revayat_scientific::identity::object_id(&pinned_original)?,
                        revayat_scientific::identity::path_object_id(&foreign)?
                    );
                    fs::rename(foreign, path)?;
                    drop(pinned_original);
                }
            }
            if event == ReadBoundary::BeforeRead {
                reads += 1;
            }
            Ok(())
        })
        .unwrap_err();
    assert!(
        error.to_string().contains("ownership") || error.to_string().contains("boundary"),
        "{error}"
    );
    assert_eq!(reads, 0);
    assert!(policy.denied);
    assert_eq!(fs::read(outside)?, b"private sentinel");
    Ok(())
}
#[test]
fn revision_during_actual_resource_read_cannot_be_returned_as_a_checked_asset() -> Result<()> {
    use revayat_scientific::resource::ReadBoundary;
    let root = tempfile::tempdir()?;
    let asset = root.path().join("image.png");
    fs::write(&asset, b"original")?;
    let source = source(root.path(), "");
    let mut policy = ResourcePolicy::new(&source)?;
    let mut seam = false;
    let result = policy.fetch_observed("https://revayat.invalid/image.png", |event, path| {
        if event == ReadBoundary::AfterRead {
            seam = true;
            #[cfg(unix)]
            fs::write(path, b"changed after read")?;
            #[cfg(windows)]
            {
                assert!(
                    fs::write(path, b"changed after read").is_err(),
                    "native read handle must deny conflicting writers"
                );
            }
        }
        Ok(())
    });
    assert!(seam);
    #[cfg(unix)]
    {
        assert!(result.is_err());
        assert!(policy.denied);
    }
    #[cfg(windows)]
    {
        assert_eq!(result?.0, b"original");
        assert!(
            !policy.denied,
            "the kernel refused the writer before any mutation"
        );
        assert_eq!(fs::read(asset)?, b"original");
    }
    Ok(())
}
