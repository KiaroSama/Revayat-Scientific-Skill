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
        "<p>متن علمی</p><img src='data:image/png;base64,YWJj'><img src='data:image/png,%00%01'>",
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
    let (served, mime) = policy.fetch("https://revayat.invalid/source.html")?;
    assert_eq!(served, before);
    assert_eq!(mime, "text/html");
    assert_eq!(fs::read(path)?, before);
    fs::write(root.path().join("owned.png"), b"admitted local image")?;
    for (index, body) in [
        "<image src='owned.png'>",
        "<IMAGE SRC='owned.png'/>",
        "<svg><foreignObject><image src='owned.png'></foreignObject></svg>",
        "<math><mtext><image src='owned.png'></mtext></math>",
    ]
    .into_iter()
    .enumerate()
    {
        let path = source(root.path(), body);
        let before = fs::read(&path)?;
        let mut policy = ResourcePolicy::new(&path)?;
        let stage = root.path().join(format!("image-alias-{index}"));
        policy.stage_for_container(&stage)?;
        assert_eq!(
            policy.resources.len(),
            2,
            "HTML image alias must admit its asset: {body}"
        );
        let staged = fs::read_to_string(stage.join(".revayat-main.html"))?;
        let oracle = scraper::Html::parse_document(&staged);
        let selector = scraper::Selector::parse("img").unwrap();
        let images = oracle.select(&selector).collect::<Vec<_>>();
        assert_eq!(images.len(), 1);
        assert!(
            images[0]
                .value()
                .attr("src")
                .unwrap()
                .starts_with("file:///input/.revayat-assets/")
        );
        let assets =
            fs::read_dir(stage.join(".revayat-assets"))?.collect::<std::io::Result<Vec<_>>>()?;
        assert_eq!(assets.len(), 1);
        assert_eq!(fs::read(assets[0].path())?, b"admitted local image");
        assert_eq!(fs::read(path)?, before);
    }
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
    // HTML5 adds document containers to fragment input. Their bookkeeping must
    // not shrink the source parser's existing public work limits.
    for body in [
        format!(
            "{}public boundary{}",
            "<span>".repeat(512),
            "</span>".repeat(512)
        ),
        "<br>".repeat(100_000),
    ] {
        let boundary = root.path().join("work-boundary.html");
        fs::write(&boundary, &body)?;
        ParsedHtml::parse(&body)?;
        let policy = ResourcePolicy::new(&boundary)?;
        assert_eq!(policy.source_bytes, body.as_bytes());
    }
    // Expanding an admitted local URL changes only the private staged view;
    // its byte count must not be mistaken for the unchanged source byte cap.
    fs::write(root.path().join("a.png"), b"public local image")?;
    let mut body = "<img src='a.png'>".to_owned();
    body.push_str(&" ".repeat(16 * 1024 * 1024 - body.len()));
    let boundary = root.path().join("byte-boundary.html");
    fs::write(&boundary, &body)?;
    let mut policy = ResourcePolicy::new(&boundary)?;
    let stage = root.path().join("byte-boundary-stage");
    policy.stage_for_container(&stage)?;
    let staged = fs::read(stage.join(".revayat-main.html"))?;
    assert!(staged.len() > body.len());
    assert!(std::str::from_utf8(&staged)?.contains("file:///input/.revayat-assets/"));
    assert_eq!(fs::read(boundary)?, body.as_bytes());
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
    for css in [
        "@namespace broken {} p{background:url(file:///usr/share/icons/debian-logo.png)}",
        "@namespace broken {x{color:red}} p{background:url(https://example.invalid/image.png)}",
        "@namespace url(http://www.w3.org/2000/svg) {} p{background:url(outside.png)}",
    ] {
        assert!(
            css_urls(css).is_err(),
            "invalid namespace block must not hide later URLs: {css}"
        );
        let root = tempfile::tempdir()?;
        let path = source(root.path(), &format!("<style>{css}</style><p>visible</p>"));
        let before = fs::read(&path)?;
        assert!(ResourcePolicy::new(&path).is_err());
        assert_eq!(fs::read(path)?, before);
    }
    assert_eq!(
        css_urls("@namespace 'urn:static';p{background:url(data:image/png,abc)}")?,
        ["data:image/png,abc"]
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
    let stage = root.path().join("container");
    let mut closed = ResourcePolicy::new(&path)?;
    closed.stage_for_container(&stage)?;
    assert_eq!(
        fs::read(stage.join(".revayat-main.html"))?,
        fs::read(&path)?
    );
    Ok(())
}
#[test]
fn unsupported_embedded_mime_is_denied_in_src_srcset_css_and_svg_references() -> Result<()> {
    let root = tempfile::tempdir()?;
    for body in [
        "<img src='data:text/html,active'>",
        "<image src='data:text/html,active'>",
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
    let outside = tempfile::tempdir()?;
    let private = outside.path().join("outside.png");
    fs::write(&private, b"outside image sentinel")?;
    let private_url = url::Url::from_file_path(&private).unwrap();
    let output = root.path().join("approved.pdf");
    fs::write(&output, b"approved delivery")?;
    for tag in ["image", "isindex"] {
        for url in [
            private_url.as_str(),
            "http://example.invalid/image.png",
            "https://example.invalid/image.png",
        ] {
            let path = source(root.path(), &format!("<{tag} type=image src='{url}'>"));
            let before = fs::read(&path)?;
            assert!(ResourcePolicy::new(&path).is_err(), "{tag}: {url}");
            let mut launched = false;
            let result =
                revayat_scientific::render::render_html_with(&path, &output, None, |_, _| {
                    launched = true;
                    anyhow::bail!("renderer must not launch");
                });
            assert!(result.is_err() && !launched);
            assert_eq!(fs::read(&output)?, b"approved delivery");
            assert_eq!(fs::read(path)?, before);
        }
    }
    // The renderer's HTML5 tree repair must agree with the source-span model.
    // These foreign-content repairs otherwise turn ignored raw URLs into images.
    let mut repairs = vec![
        "<math><annotation-xml><svg><image href='{url}'/></svg></annotation-xml></math>".to_owned(),
        "<noscript><img src='{url}'></noscript>".to_owned(),
    ];
    for integration in [
        "mi",
        "mo",
        "mn",
        "ms",
        "mtext",
        "annotation-xml encoding='text/html'",
    ] {
        let end = integration.split_ascii_whitespace().next().unwrap();
        repairs.push(format!(
            "<math><{integration}><div></{end}><image src='{{url}}'>"
        ));
    }
    for integration in ["desc", "title", "foreignObject"] {
        repairs.push(format!(
            "<svg><{integration}><div></{integration}><image src='{{url}}'>"
        ));
    }
    for body in repairs {
        for url in [
            private_url.as_str(),
            "http://example.invalid/image.png",
            "https://example.invalid/image.png",
        ] {
            let body = body.replace("{url}", url);
            let path = source(root.path(), &body);
            let before = fs::read(&path)?;
            assert!(
                ResourcePolicy::new(&path).is_err(),
                "HTML5 repair must be refused or admitted through policy: {body}"
            );
            let mut launched = false;
            let result =
                revayat_scientific::render::render_html_with(&path, &output, None, |_, _| {
                    launched = true;
                    anyhow::bail!("renderer must not launch");
                });
            assert!(result.is_err() && !launched);
            assert_eq!(fs::read(&output)?, b"approved delivery");
            assert_eq!(fs::read(path)?, before);
        }
    }
    assert_eq!(fs::read(private)?, b"outside image sentinel");
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
    let root = tempfile::tempdir()?;
    for (body, category) in [
        ("<img srcset='data:image/png,abc 1x'>", "srcset"),
        ("<img src src='data:image/png,abc'>", "duplicate attribute"),
    ] {
        let path = source(root.path(), body);
        let before = fs::read(&path)?;
        let mut closed = ResourcePolicy::new(&path)?;
        let stage = root.path().join("container");
        let error = closed.stage_for_container(&stage).unwrap_err();
        assert!(format!("{error:#}").contains(category));
        assert!(closed.denied);
        assert!(!stage.exists());
        assert_eq!(fs::read(path)?, before);
    }
    Ok(())
}
#[test]
fn local_css_imports_fonts_and_images_remain_allowed_without_double_charging_network_bytes()
-> Result<()> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("styles"))?;
    let font_url = url::Url::from_file_path(root.path().join("normal.woff2")).unwrap();
    fs::write(
        root.path().join("styles/main.css"),
        format!(
            "@import /*gap*/ 'nested.css'; @font-face{{font-family:Body;src:url('{font_url}')}} p{{background:url('../normal.png')}} p::before{{content:'../normal.png'}}"
        ),
    )?;
    fs::write(
        root.path().join("styles/nested.css"),
        "@media print {p{background-image:url(data:image/png,abc)}}",
    )?;
    fs::write(root.path().join("normal.woff2"), b"font fixture")?;
    fs::write(root.path().join("normal.png"), b"image fixture")?;
    let source = source(
        root.path(),
        "<link rel=stylesheet href='styles/main.css'><p data-note='../normal.png'>../normal.png</p><img src='https://revayat.invalid/normal&#46;png'>",
    );
    let mut p = ResourcePolicy::new(&source)?;
    assert_eq!((p.requests, p.total), (1, 3));
    let (css, mime) = p.fetch("https://revayat.invalid/styles/main.css")?;
    assert_eq!(mime, "text/css");
    assert_eq!((p.requests, p.total), (2, 3 + css.len()));
    let nested = p.fetch("https://revayat.invalid/styles/nested.css")?.0;
    assert_eq!((p.requests, p.total), (3, 3 + css.len() + nested.len()));
    p.fetch("data:image/png,abc")?;
    assert_eq!((p.requests, p.total), (3, 3 + css.len() + nested.len()));
    assert!(p.fetch("https://revayat.invalid/normal.woff2").is_ok());
    assert!(p.fetch("https://revayat.invalid/normal.png").is_ok());
    let originals = [
        source.clone(),
        root.path().join("styles/main.css"),
        root.path().join("styles/nested.css"),
        root.path().join("normal.woff2"),
        root.path().join("normal.png"),
    ]
    .into_iter()
    .map(|path| Ok((path.clone(), fs::read(path)?)))
    .collect::<Result<Vec<_>>>()?;
    let stage = root.path().join("container");
    let mut closed = ResourcePolicy::new(&source)?;
    closed.stage_for_container(&stage)?;
    assert_eq!(
        closed.resources.len(),
        5,
        "font and image belong to the closure"
    );
    let html = fs::read_to_string(stage.join(".revayat-main.html"))?;
    assert!(html.contains("<p data-note='../normal.png'>../normal.png</p>"));
    let parsed = ParsedHtml::parse(&html)?;
    assert!(parsed.nodes.iter().any(|node| {
        node.tag == "link"
            && node
                .attr("href")
                .starts_with("file:///input/.revayat-assets/")
    }));
    let assets = fs::read_dir(stage.join(".revayat-assets"))?
        .map(|entry| Ok(entry?.path()))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(assets.len(), 5);
    let contents = assets
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()?;
    assert!(contents.iter().any(|bytes| bytes == b"font fixture"));
    assert!(contents.iter().any(|bytes| bytes == b"image fixture"));
    assert!(contents.iter().any(|bytes| bytes == b"abc"));
    assert!(
        contents
            .iter()
            .any(|bytes| String::from_utf8_lossy(bytes).contains("content:'../normal.png'"))
    );
    for path in assets
        .iter()
        .filter(|path| path.extension().is_some_and(|s| s == "css"))
    {
        let css = fs::read_to_string(path)?;
        assert!(
            css_urls(&css)?
                .iter()
                .all(|url| url.starts_with("file:///input/.revayat-assets/"))
        );
    }
    for (path, before) in originals {
        assert_eq!(fs::read(path)?, before);
    }
    let css_path = root.path().join("styles/main.css");
    let before = fs::read(&css_path)?;
    let mut stale = ResourcePolicy::new(&source)?;
    fs::write(&css_path, "p{color:red}")?;
    let rejected = root.path().join("rejected");
    let error = stale.stage_for_container(&rejected).unwrap_err();
    assert!(format!("{error:#}").contains("changed"));
    assert!(stale.denied);
    assert!(!rejected.exists());
    fs::write(css_path, before)?;
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
    let original = fs::read(&path)?;
    let stage = root.path().join("container");
    let mut closed = ResourcePolicy::new(&path)?;
    closed.stage_for_container(&stage)?;
    let assets = fs::read_dir(stage.join(".revayat-assets"))?
        .map(|entry| Ok(entry?.path()))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(assets.len(), 2);
    let artwork = assets
        .iter()
        .find(|path| path.extension().is_some_and(|s| s == "svg"))
        .unwrap();
    let staged_svg = fs::read_to_string(artwork)?;
    let parsed_svg = roxmltree::Document::parse(&staged_svg)?;
    let image = parsed_svg
        .descendants()
        .find(|node| node.tag_name().name() == "image")
        .unwrap();
    assert!(
        image
            .attribute("href")
            .unwrap()
            .starts_with("file:///input/.revayat-assets/")
    );
    assert!(staged_svg.contains("<![CDATA[<!doctype is literal text]]>"));
    assert_eq!(fs::read(&path)?, original);
    for (index, (svg, category)) in [
        ("<svg xmlns='http://www.w3.org/2000/svg'><foreignObject><img xmlns='http://www.w3.org/1999/xhtml' srcset='data:image/png,abc 1x'/></foreignObject></svg>", "SVG srcset"),
        ("<svg xmlns='http://www.w3.org/2000/svg'><style>p{background:u<!-- split -->rl('file:///not-admitted.png')}</style></svg>", "SVG style markup"),
        ("<svg xmlns='http://www.w3.org/2000/svg'><style><![CDATA[p{fill:url(#safe)}]]></style></svg>", "CDATA/entities"),
        ("<svg xmlns='http://www.w3.org/2000/svg'><tref href='https://revayat.invalid/not-admitted.png'/></svg>", "SVG reference"),
        ("<svg xmlns='http://www.w3.org/2000/svg'><a rel='attachment' href='file:///not-admitted.pdf'/></svg>", "SVG attachment"),
        ("<?xml version='1.0' encoding='ISO-8859-1'?><svg xmlns='http://www.w3.org/2000/svg'><text>متن</text></svg>", "SVG encoding"),
    ].into_iter().enumerate() {
        let path = source(root.path(), &format!("<img src='data:image/svg+xml;base64,{}'>", STANDARD.encode(svg)));
        let before = fs::read(&path)?;
        let mut closed = ResourcePolicy::new(&path)?;
        let rejected = root.path().join(format!("unsupported-{index}"));
        let error = closed.stage_for_container(&rejected).unwrap_err();
        assert!(format!("{error:#}").contains(category), "{error:#}");
        assert!(closed.denied);
        assert!(!rejected.exists());
        assert_eq!(fs::read(path)?, before);
    }
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
    let mut p = ResourcePolicy::new(&path)?;
    assert_eq!((p.requests, p.total), (2, 6));
    let mut unsupported = ResourcePolicy::new(&path)?;
    let unsupported_stage = root.path().join("unsupported");
    let error = unsupported
        .stage_for_container(&unsupported_stage)
        .unwrap_err();
    assert!(format!("{error:#}").contains("XML stylesheet"));
    assert!(unsupported.denied);
    assert!(!unsupported_stage.exists());
    fs::write(
        root.path().join("svg.css"),
        "@import 'https://evil.invalid/steal.css';",
    )?;
    assert!(ResourcePolicy::new(&path).is_err());
    let stage = root.path().join("container");
    assert!(p.stage_for_container(&stage).is_err());
    assert!(p.denied);
    assert!(!stage.exists());
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
    let stage = root.path().join("container");
    let mut closed = ResourcePolicy::new(&path)?;
    closed.stage_for_container(&stage)?;
    assert_eq!(closed.resources.len(), 3);
    assert_eq!(fs::read_dir(stage.join(".revayat-assets"))?.count(), 3);
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
    if let Some(evidence) = std::env::var_os("SCIENTIFIC_EVIDENCE_DIR") {
        fs::create_dir_all(&evidence)?;
        let destination = Path::new(&evidence).join("admitted-data-image.pdf");
        anyhow::ensure!(
            !revayat_scientific::identity::is_link(&destination)?,
            "linked evidence output refused"
        );
        fs::copy(&output, destination)?;
    }
    let document = revayat_scientific::pdf::open_pdf(&output, false)?;
    let (_, images) = revayat_scientific::pdf_content::artwork(&document, 1)?;
    assert!(
        images.iter().any(|image| image.width == 8
            && image.height == 8
            && image.bbox[2] > image.bbox[0]
            && image.bbox[3] > image.bbox[1]),
        "the admitted data image must actually be painted into the native PDF: {images:?}"
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
    let path = source(
        root.path(),
        "<p data-image='file:///not-admitted.png' style='background-image:attr(data-image url)'>safe</p>",
    );
    let before = fs::read(&path)?;
    let mut closed = ResourcePolicy::new(&path)?;
    let rejected = root.path().join("attribute-rejected");
    let error = closed.stage_for_container(&rejected).unwrap_err();
    assert!(format!("{error:#}").contains("CSS attribute URL"));
    assert!(closed.denied);
    assert!(!rejected.exists());
    assert_eq!(fs::read(&path)?, before);
    let path = source(
        root.path(),
        "<style>a::after{content:target-counter(attr(href url),page)}</style><a href='#target'>read</a><p id='target'>safe</p>",
    );
    let before = fs::read(&path)?;
    let mut closed = ResourcePolicy::new(&path)?;
    let stage = root.path().join("counter");
    closed.stage_for_container(&stage)?;
    assert_eq!(fs::read(stage.join(".revayat-main.html"))?, before);
    assert_eq!(fs::read(path)?, before);
    let css = root.path().join("legacy.css");
    fs::write(&css, "@charset 'windows-1252';p{font-family:'متن'}")?;
    let css_before = fs::read(&css)?;
    let path = source(root.path(), "<link rel=stylesheet href='legacy.css'>");
    let mut closed = ResourcePolicy::new(&path)?;
    let rejected = root.path().join("encoding-rejected");
    let error = closed.stage_for_container(&rejected).unwrap_err();
    assert!(format!("{error:#}").contains("CSS encoding"));
    assert!(closed.denied);
    assert!(!rejected.exists());
    assert_eq!(fs::read(css)?, css_before);
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
