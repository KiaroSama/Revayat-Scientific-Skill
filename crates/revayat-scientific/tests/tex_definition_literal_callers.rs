//! Production callers share the accepted literal view of owned definition data.
//! Keep genuine definition-body assets and actual listing openers observable.

use revayat_scientific::build;
use revayat_scientific::lint::{self, Finding, Source};
use revayat_scientific::tex::source_closure;
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
    source: Source,
    inputs: Vec<PathBuf>,
    origin: (PathBuf, usize),
}

fn document(body: &str, with_figure: bool, placement: Placement) -> Document {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    let mut inputs = vec![main.clone()];
    let declaration = body.strip_suffix(r"\sample").unwrap_or(body);
    let invocation = &body[declaration.len()..];
    let replacement = declaration
        .strip_prefix(r"\newcommand{\sample}{")
        .unwrap()
        .strip_suffix('}')
        .unwrap();
    let (body, origin) = match placement {
        Placement::Local => (body.to_owned(), (main.clone(), 2)),
        Placement::InheritedChild => {
            let child = root.join("owned.tex");
            fs::write(
                &child,
                format!("% Original child location\n\n{replacement}"),
            )
            .unwrap();
            inputs.push(child.clone());
            (
                format!("\\newcommand{{\\sample}}{{\\input{{owned}}}}{invocation}"),
                (child, 3),
            )
        }
        Placement::CallerReturn => {
            let child = root.join("declaration.tex");
            fs::write(&child, "% Pending declaration\n\\newcommand").unwrap();
            inputs.push(child);
            (
                format!("\\input declaration \\sample{{{replacement}}}{invocation}"),
                (main.clone(), 2),
            )
        }
    };
    if with_figure {
        image::RgbImage::from_pixel(4, 4, image::Rgb([160, 170, 180]))
            .save(root.join("figure.png"))
            .unwrap();
    }
    fs::write(
        &main,
        format!("\\begin{{document}}\n{body}\nOutsideVisible\n\\end{{document}}\n"),
    )
    .unwrap();
    let source = Source::load(&main).unwrap();
    let Source::Tex(model) = &source else {
        unreachable!()
    };
    assert_eq!(model.closure.sources, inputs, "{placement:?}");
    inputs.sort();
    Document {
        _directory: directory,
        main,
        source,
        inputs,
        origin,
    }
}

fn checked(source: &Source, checks: &[&str]) -> Vec<Finding> {
    lint::check(source, &[], None, "system-docs")
        .unwrap()
        .into_iter()
        .filter(|finding| checks.contains(&finding.check.as_str()))
        .collect()
}

#[test]
fn owned_inline_literal_image_is_inert_for_inventory_and_lint() {
    for placement in PLACEMENTS {
        let fixture = document(
            r"\newcommand{\sample}{\verb|\includegraphics{absent.png}|}",
            false,
            placement,
        );
        let references = fixture.source.image_references();
        let inputs = build::document_inputs(&fixture.main, &[], None);
        let findings = checked(&fixture.source, &["figure-direction", "missing-image"]);
        assert!(
            references.is_empty()
                && inputs.as_ref().is_ok_and(|paths| paths == &fixture.inputs)
                && findings.is_empty(),
            "{placement:?}: literal data reached a caller: references={references:?}, inputs={inputs:?}, findings={findings:#?}"
        );
    }
}

#[test]
fn genuine_lr_wrapped_definition_image_remains_visible() {
    for placement in PLACEMENTS {
        let fixture = document(
            r"\newcommand{\sample}{\LR{\includegraphics{figure.png}}}\sample",
            true,
            placement,
        );
        let references = fixture.source.image_references();
        assert_eq!(references.len(), 1, "{placement:?}: {references:?}");
        assert_eq!(references[0].1, "figure.png");
        assert_eq!(fixture.source.location(references[0].0), fixture.origin);
        let mut expected = fixture.inputs;
        expected.push(fixture.main.parent().unwrap().join("figure.png"));
        expected.sort();
        assert_eq!(
            build::document_inputs(&fixture.main, &[], None).unwrap(),
            expected
        );
        assert!(checked(&fixture.source, &["figure-direction", "missing-image"]).is_empty());
    }
}

#[test]
fn owned_inline_direction_payload_cannot_scope_real_unwrapped_image() {
    for placement in PLACEMENTS {
        let fixture = document(
            r"\newcommand{\sample}{\verb|\begin{LTR}|\includegraphics{figure.png}\verb|\end{LTR}|}",
            true,
            placement,
        );
        let references = fixture.source.image_references();
        assert_eq!(references.len(), 1, "{placement:?}: {references:?}");
        assert_eq!(references[0].1, "figure.png");
        assert_eq!(fixture.source.location(references[0].0), fixture.origin);
        let findings = checked(&fixture.source, &["figure-direction"]);
        assert_eq!(findings.len(), 1, "{placement:?}: {findings:#?}");
        assert_eq!((findings[0].path.clone(), findings[0].line), fixture.origin);
        assert!(checked(&fixture.source, &["missing-image"]).is_empty());
    }
}

#[test]
fn owned_inline_listing_payload_does_not_create_code_check() {
    for placement in PLACEMENTS {
        let fixture = document(
            r"\newcommand{\sample}{\verb|\begin{lstlisting}|}",
            false,
            placement,
        );
        let findings = checked(&fixture.source, &["code-direction"]);
        assert!(findings.is_empty(), "{placement:?}: {findings:#?}");
    }
}

#[test]
fn actual_unwrapped_definition_listing_still_requires_latin() {
    for placement in PLACEMENTS {
        let fixture = document(
            r"\newcommand{\sample}{\begin{lstlisting}code data\end{lstlisting}}",
            false,
            placement,
        );
        let findings = checked(&fixture.source, &["code-direction"]);
        assert_eq!(findings.len(), 1, "{placement:?}: {findings:#?}");
        assert_eq!((findings[0].path.clone(), findings[0].line), fixture.origin);
    }
}

#[test]
fn actual_latin_wrapped_definition_listing_retains_direction_scope() {
    for placement in PLACEMENTS {
        let fixture = document(
            r"\newcommand{\sample}{\begin{latin}\begin{lstlisting}code data\end{lstlisting}\end{latin}}",
            false,
            placement,
        );
        let findings = checked(&fixture.source, &["code-direction"]);
        assert!(findings.is_empty(), "{placement:?}: {findings:#?}");
    }
}

#[test]
fn raw_percent_inside_owned_literal_cannot_reactivate_commented_input() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    fs::write(
        &main,
        "\\newcommand{\\sample}{\\verb|100%| \\input{absent}\nRetainedBody} OutsideVisible",
    )
    .unwrap();
    let closure = source_closure(&main, None)
        .expect("a completed literal must not reactivate the rest of its raw comment");
    assert_eq!(closure.sources, [main]);
    assert!(closure.text.contains(r"\input{absent}"));
    assert!(closure.text.contains("OutsideVisible"));
}

#[test]
fn genuine_input_after_an_owned_literal_without_percent_is_discovered() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let main = root.join("main.tex");
    let data = root.join("data.tex");
    fs::write(&data, "IncludedBody").unwrap();
    fs::write(
        &main,
        "\\newcommand{\\sample}{\\verb|100x| \\input{data}\nRetainedBody} OutsideVisible",
    )
    .unwrap();
    let closure = source_closure(&main, None).unwrap();
    assert_eq!(closure.sources, [main, data]);
    assert!(closure.text.contains("IncludedBody"));
    assert!(closure.text.contains("OutsideVisible"));
}
