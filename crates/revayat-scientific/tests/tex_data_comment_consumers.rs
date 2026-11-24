use revayat_scientific::build;
use revayat_scientific::lint::{self, Source};
use revayat_scientific::tex::source_closure;
use revayat_scientific::text_order::source_plain;
use std::{fs, path::PathBuf};

#[derive(Clone, Copy, Debug)]
enum Placement {
    Local,
    InheritedChild,
    CallerReturn,
}

const PLACEMENTS: [Placement; 3] = [
    Placement::Local,
    Placement::InheritedChild,
    Placement::CallerReturn,
];

struct Document {
    _directory: tempfile::TempDir,
    main: PathBuf,
    origin: PathBuf,
    sources: Vec<PathBuf>,
}

fn document(placement: Placement, candidate: &str) -> Document {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    let mut sources = vec![main.clone()];
    let (candidate, origin) = match placement {
        Placement::Local => (candidate.to_owned(), main.clone()),
        Placement::InheritedChild | Placement::CallerReturn => {
            let body = candidate
                .strip_prefix(r"\newcommand{\sample}{")
                .unwrap()
                .strip_suffix('}')
                .unwrap();
            if matches!(placement, Placement::InheritedChild) {
                let child = root.join("owned.tex");
                fs::write(&child, format!("% Original child location\n\n{body}")).unwrap();
                sources.push(child.clone());
                (r"\newcommand{\sample}{\input{owned}}".to_owned(), child)
            } else {
                let child = root.join("declaration.tex");
                fs::write(&child, "% Pending declaration\n\\newcommand").unwrap();
                sources.push(child);
                (
                    format!("\\input declaration \\sample{{{body}}}"),
                    main.clone(),
                )
            }
        }
    };
    fs::write(
        &main,
        format!("\\begin{{document}}\n{candidate}\nOutsideVisible\n\\end{{document}}\n"),
    )
    .unwrap();
    fs::write(root.join("child.tex"), "IncludedBody").unwrap();
    image::RgbImage::from_pixel(4, 4, image::Rgb([160, 170, 180]))
        .save(root.join("figure.png"))
        .unwrap();
    Document {
        _directory: directory,
        main,
        origin,
        sources,
    }
}

fn expected_sources(fixture: &Document, child: bool) -> Vec<PathBuf> {
    let mut expected = fixture.sources.clone();
    if child {
        expected.push(fixture.main.parent().unwrap().join("child.tex"));
    }
    expected
}

fn check_real_image(fixture: &Document, child: bool, label: &str) {
    let source = Source::load(&fixture.main).unwrap_or_else(|error| panic!("{label}: {error:#}"));
    let Source::Tex(model) = &source else {
        unreachable!()
    };
    assert_eq!(
        model.closure.sources,
        expected_sources(fixture, child),
        "{label}"
    );
    let references = source.image_references();
    assert_eq!(references.len(), 1, "{label}: {references:?}");
    assert_eq!(references[0].1, "figure.png");
    let original = fs::read_to_string(&fixture.origin).unwrap();
    let offset = original.find(r"\includegraphics{figure.png}").unwrap();
    // The public location contract counts LF bytes; CR alone does not add one.
    let line = original[..offset]
        .bytes()
        .filter(|&byte| byte == b'\n')
        .count()
        + 1;
    let expected_location = (fixture.origin.clone(), line);
    assert_eq!(
        source.location(references[0].0),
        expected_location,
        "{label}"
    );
    let findings: Vec<_> = lint::check(&source, &[], None, "system-docs")
        .unwrap()
        .into_iter()
        .filter(|finding| {
            ["figure-direction", "missing-image", "code-direction"]
                .contains(&finding.check.as_str())
        })
        .collect();
    assert_eq!(findings.len(), 1, "{label}: {findings:#?}");
    assert_eq!(findings[0].check, "figure-direction");
    assert_eq!(
        (findings[0].path.clone(), findings[0].line),
        expected_location,
        "{label}"
    );
    let mut inputs = expected_sources(fixture, child);
    inputs.push(fixture.main.parent().unwrap().join("figure.png"));
    inputs.sort();
    assert_eq!(
        build::document_inputs(&fixture.main, &[], None).unwrap(),
        inputs,
        "{label}"
    );
}

fn check_text(fixture: &Document, child: bool, label: &str) {
    let closure =
        source_closure(&fixture.main, None).unwrap_or_else(|error| panic!("{label}: {error:#}"));
    assert_eq!(closure.sources, expected_sources(fixture, child), "{label}");
    assert!(closure.text.contains("CommentPayload") && closure.text.contains("OutsideVisible"));
    for (route, result) in [
        ("closure", closure.plain_text()),
        ("production", source_plain(&fixture.main)),
    ] {
        let plain = result.unwrap_or_else(|error| panic!("{label}/{route}: {error:#}"));
        // Derived comments alter recognition/matching, not retained raw output.
        for marker in ["CommentPayload", "RetainedBody", "OutsideVisible"] {
            assert!(
                plain.contains(marker),
                "{label}/{route}: missing {marker}: {plain}"
            );
        }
        assert_eq!(
            plain.contains("IncludedBody"),
            child,
            "{label}/{route}: {plain}"
        );
        assert!(!plain.contains("MathOnly"), "{label}/{route}: {plain}");
    }
}

#[test]
fn resumed_comments_hide_fake_assets_and_direction_syntax_at_original_locations() {
    for placement in PLACEMENTS {
        for newline in ["\n", "\r\n", "\r"] {
            let body = format!(
                "\\verb\\Literal\\% \\input{{absent}} \\includegraphics{{ghost.png}} \\begin{{LTR}} \\begin{{lstlisting}}{newline}\\includegraphics{{figure.png}} RetainedBody"
            );
            let fixture = document(placement, &format!("\\newcommand{{\\sample}}{{{body}}}"));
            check_real_image(&fixture, false, &format!("{placement:?}/{newline:?}"));
        }
    }
}

#[test]
fn resumed_comment_dollars_cannot_consume_later_math_or_conservative_inputs() {
    for placement in PLACEMENTS {
        for newline in ["\n", "\r\n", "\r"] {
            let body = format!(
                "\\verb\\Literal\\% $CommentPayload{newline}RetainedBody \\input{{child}} $MathOnly$"
            );
            let fixture = document(placement, &format!("\\newcommand{{\\sample}}{{{body}}}"));
            check_text(&fixture, true, &format!("{placement:?}/{newline:?}"));
        }
    }
}

#[test]
fn resumed_comments_stop_at_original_default_or_owner_bounds() {
    for candidate in [
        r"\newcommand{\sample}{\verb\Literal\% $CommentPayload} \input{child}\includegraphics{figure.png}$MathOnly$ RetainedBody",
        r"\newcommand{\sample}[1][\verb\Literal\% $CommentPayload]{\input{child}\includegraphics{figure.png}$MathOnly$ RetainedBody}",
    ] {
        let fixture = document(Placement::Local, candidate);
        check_real_image(&fixture, true, candidate);
        check_text(&fixture, true, candidate);
    }
}

#[test]
fn ordinary_raw_comments_and_literal_without_comment_keep_real_assets_visible() {
    for placement in PLACEMENTS {
        for body in [
            "\\verb|100%| \\input{absent} \\includegraphics{ghost.png}\n\\includegraphics{figure.png} RetainedBody",
            r"\verb\Literal\ \includegraphics{figure.png} RetainedBody",
        ] {
            let fixture = document(placement, &format!("\\newcommand{{\\sample}}{{{body}}}"));
            check_real_image(&fixture, false, &format!("{placement:?}/{body}"));
        }
    }
}
