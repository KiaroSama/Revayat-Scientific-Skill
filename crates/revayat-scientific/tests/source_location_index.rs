use revayat_scientific::source::TexSource;
use revayat_scientific::tex::{Segment, Snapshot, SourceClosure, source_closure};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

fn reference(closure: &SourceClosure, offset: isize) -> (PathBuf, usize) {
    if closure.segments.is_empty() {
        return (closure.sources[0].clone(), 1);
    }
    let index = closure
        .segments
        .iter()
        .rposition(|s| s.start as isize <= offset)
        .unwrap_or(0);
    let segment = &closure.segments[index];
    let text = &segment.snapshot.text;
    let position = segment.original_offset as i128 + offset as i128 - segment.start as i128;
    let position = if position < 0 {
        (text.len() as i128 + position).max(0)
    } else {
        position.min(text.len() as i128)
    } as usize;
    (
        segment.snapshot.path.clone(),
        text.as_bytes()[..position]
            .iter()
            .filter(|b| **b == b'\n')
            .count()
            + 1,
    )
}
fn simple(path: &Path, text: &str) -> SourceClosure {
    let snapshot = Arc::new(Snapshot::new(path.into(), Arc::from(text)).unwrap());
    SourceClosure {
        text: text.into(),
        segments: vec![Segment {
            start: 0,
            original_offset: 0,
            snapshot,
        }],
        sources: vec![path.into()],
    }
}
#[test]
fn test_repeated_queries_do_not_rescan_source_prefixes() {
    let closure = simple(Path::new("main.tex"), &"line\n".repeat(1000));
    let snapshot = &closure.segments[0].snapshot;
    let pointer = snapshot.newline_index().as_ptr();
    for i in 0..2000 {
        assert_eq!(
            closure.location((i % closure.text.len()) as isize),
            reference(&closure, (i % closure.text.len()) as isize)
        );
    }
    assert_eq!(snapshot.newline_index().as_ptr(), pointer);
    assert_eq!(snapshot.newline_index().len(), 1000);
}
#[test]
fn test_segment_start_keys_are_not_rebuilt_per_query() {
    let text = "line\n".repeat(200);
    let snapshot = Arc::new(Snapshot::new("main.tex".into(), Arc::from(text.as_str())).unwrap());
    let closure = SourceClosure {
        text: text.clone(),
        segments: (0..text.len())
            .step_by(5)
            .map(|i| Segment {
                start: i,
                original_offset: i,
                snapshot: snapshot.clone(),
            })
            .collect(),
        sources: vec!["main.tex".into()],
    };
    let pointer = closure.segments.as_ptr();
    let count = closure.segments.len();
    for i in 0..=text.len() {
        assert_eq!(
            closure.location(i as isize),
            reference(&closure, i as isize)
        );
    }
    assert_eq!(closure.segments.as_ptr(), pointer);
    assert_eq!(closure.segments.len(), count);
}
#[test]
fn test_every_offset_matches_old_mapping_for_nested_repeated_mixed_sources() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let source = root.join("main.tex");
    for a in ["\n", "\r\n"] {
        for b in ["\n", "\r\n"] {
            fs::write(
                &source,
                format!("Intro{a}\\input{{child}}{a}\\input{{child}} Tail"),
            )
            .unwrap();
            fs::write(
                root.join("child.tex"),
                format!("Child{b}\\input{{nested}} End"),
            )
            .unwrap();
            fs::write(root.join("nested.tex"), b"% EOF comment").unwrap();
            let closure = source_closure(&source, None).unwrap();
            for offset in 0..=closure.text.len() {
                assert_eq!(
                    closure.location(offset as isize),
                    reference(&closure, offset as isize)
                );
            }
            assert_eq!(
                closure.location(closure.text.find("Tail").unwrap() as isize),
                (source.clone(), 3)
            );
        }
    }
}
#[test]
fn test_empty_closure_and_newline_boundaries() {
    let temp = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(temp.path()).unwrap().join("empty.tex");
    fs::write(&path, b"").unwrap();
    assert_eq!(
        source_closure(&path, None).unwrap().location(0),
        (path.clone(), 1)
    );
    for text in ["x\ny", "\n", "\r\n", "no newline", "\n\n\n"] {
        fs::write(&path, text).unwrap();
        let closure = source_closure(&path, None).unwrap();
        for offset in -(text.len() as isize) - 2..text.len() as isize + 3 {
            assert_eq!(closure.location(offset), reference(&closure, offset));
        }
    }
}
#[test]
fn test_same_path_distinct_original_snapshots_have_distinct_indexes() {
    let first = "first\nline";
    let second = "no breaks in second";
    let path = PathBuf::from("same.tex");
    let closure = SourceClosure {
        text: format!("{first}{second}"),
        sources: vec![path.clone()],
        segments: vec![
            Segment {
                start: 0,
                original_offset: 0,
                snapshot: Arc::new(Snapshot::new(path.clone(), Arc::from(first)).unwrap()),
            },
            Segment {
                start: first.len(),
                original_offset: 0,
                snapshot: Arc::new(Snapshot::new(path, Arc::from(second)).unwrap()),
            },
        ],
    };
    for offset in 0..=closure.text.len() {
        assert_eq!(
            closure.location(offset as isize),
            reference(&closure, offset as isize)
        );
    }
    assert_eq!(closure.segments[0].snapshot.newline_index().len(), 1);
    assert!(closure.segments[1].snapshot.newline_index().is_empty());
}
#[test]
fn test_repeated_protection_and_waiver_queries_use_snapshot_indexes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("indexed.tex");
    fs::write(
        &path,
        "% fa-lint: allow arabic-letters\nكي \\en{123}\nمتن\n",
    )
    .unwrap();
    let source = TexSource::load(&path).unwrap();
    let protected = source.protected.as_ptr();
    let comments = source.comments.as_ptr();
    for _ in 0..50 {
        assert!(source.is_protected(source.text().find("123").unwrap()));
        assert!(!source.is_protected(source.text().find("كي").unwrap()));
        assert!(source.suppressed(source.text().find("كي").unwrap(), "arabic-letters"));
        assert!(!source.suppressed(source.text().find("كي").unwrap(), "eastern-digits"));
        assert!(!source.suppressed(source.text().find("متن").unwrap(), "arabic-letters"));
    }
    assert_eq!(source.protected.as_ptr(), protected);
    assert_eq!(source.comments.as_ptr(), comments);
}
#[test]
fn test_newline_index_has_bounded_compact_storage() {
    let text = "\n".repeat(10000);
    let closure = simple(Path::new("dense.tex"), &text);
    assert!(closure.segments[0].snapshot.index_bytes() < text.len() * 5);
    assert_eq!(
        closure.location(text.len() as isize),
        (PathBuf::from("dense.tex"), 10001)
    );
}
