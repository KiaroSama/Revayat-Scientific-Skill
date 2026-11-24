use revayat_scientific::tex::{Segment, Snapshot, SourceClosure};
use std::{path::PathBuf, sync::Arc};

fn snapshot(name: &str, text: &str) -> Arc<Snapshot> {
    Arc::new(Snapshot::new(PathBuf::from(name), Arc::from(text)).unwrap())
}

fn assembled(parts: &[(&Arc<Snapshot>, usize, usize)], stride: usize) -> SourceClosure {
    let mut closure = SourceClosure {
        text: String::new(),
        segments: Vec::new(),
        sources: Vec::new(),
    };
    for &(snapshot, start, end) in parts {
        let output_start = closure.text.len();
        closure.text.push_str(&snapshot.text[start..end]);
        for original_offset in (start..end).step_by(stride) {
            closure.segments.push(Segment {
                start: output_start + original_offset - start,
                original_offset,
                snapshot: Arc::clone(snapshot),
            });
        }
        if !closure.sources.contains(&snapshot.path) {
            closure.sources.push(snapshot.path.clone());
        }
    }
    closure
}

fn check(closure: &SourceClosure, expected_outer: usize, label: &str, failures: &mut Vec<String>) {
    match closure.plain_text() {
        Ok(plain)
            if !plain.contains("MathOnly")
                && plain.matches("Alpha").count() == expected_outer
                && plain.matches("Omega").count() == expected_outer => {}
        actual => failures.push(format!("{label}: {actual:?}")),
    }
}

#[test]
fn inserted_independent_snapshot_does_not_inherit_an_outer_literal_mask() {
    let outer = snapshot("outer.tex", r"\newcommand{\outer}{\verb|AlphaOmega|}");
    let inner = snapshot("inner.tex", r"\newcommand{\inner}{$MathOnly$}");
    let split = outer.text.find("Omega").unwrap();
    let closure = assembled(
        &[
            (&outer, 0, split),
            (&inner, 0, inner.text.len()),
            (&outer, split, outer.text.len()),
        ],
        usize::MAX,
    );
    let mut failures = Vec::new();
    check(&closure, 1, "exact inserted-snapshot review", &mut failures);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn contiguous_snapshot_splits_keep_full_literal_masks_and_utf8() {
    let mut failures = Vec::new();
    for text in [
        r"\newcommand{\outer}{\verb|AlphaOmega|}",
        r"\newcommand{\outer}{\verb|$LiteralPayload$ فارسی 🙂|}",
    ] {
        let source = snapshot("contiguous.tex", text);
        for stride in [1, 7, 31] {
            let closure = assembled(&[(&source, 0, source.text.len())], stride);
            let expected = if text.contains("LiteralPayload") {
                "|$LiteralPayload$ فارسی 🙂|"
            } else {
                "|AlphaOmega|"
            };
            match closure.plain_text() {
                Ok(plain) if plain == expected => (),
                actual => failures.push(format!("contiguous/stride={stride}/{text}: {actual:?}")),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn repeated_and_sibling_visits_keep_their_own_literal_membership() {
    let outer = snapshot("outer.tex", r"\newcommand{\outer}{\verb|AlphaOmega|}");
    let inner = snapshot("inner.tex", r"\newcommand{\inner}{$MathOnly$}");
    let split = outer.text.find("Omega").unwrap();
    let repeated = assembled(
        &[
            (&outer, 0, split),
            (&inner, 0, inner.text.len()),
            (&outer, split, outer.text.len()),
            (&outer, 0, split),
            (&inner, 0, inner.text.len()),
            (&outer, split, outer.text.len()),
        ],
        usize::MAX,
    );
    let siblings = assembled(
        &[
            (&outer, 0, outer.text.len()),
            (&inner, 0, inner.text.len()),
            (&outer, 0, outer.text.len()),
        ],
        usize::MAX,
    );
    let mut failures = Vec::new();
    check(
        &repeated,
        2,
        "repeated visits of the same snapshot",
        &mut failures,
    );
    check(&siblings, 2, "sibling visit control", &mut failures);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn genuine_owned_math_remains_excluded_without_an_outer_literal() {
    let outer = snapshot("outer.tex", r"\newcommand{\outer}{AlphaOmega}");
    let inner = snapshot("inner.tex", r"\newcommand{\inner}{$MathOnly$}");
    let split = outer.text.find("Omega").unwrap();
    let closure = assembled(
        &[
            (&outer, 0, split),
            (&inner, 0, inner.text.len()),
            (&outer, split, outer.text.len()),
        ],
        usize::MAX,
    );
    let mut failures = Vec::new();
    check(&closure, 1, "genuine owned-math control", &mut failures);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
