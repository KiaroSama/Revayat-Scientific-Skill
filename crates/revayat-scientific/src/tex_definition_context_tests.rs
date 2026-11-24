use super::*;

#[test]
fn contextual_collection_keeps_raw_literal_delimiters_and_comments() {
    let short = r"\newcommand{\sample}{\verb|}";
    let structural = format!("{short}{{|\\end{{document}}}}");
    let plain = r"\newcommand{\sample}{\verb|x|\end{document}}";
    let percent = "\\newcommand{\\sample}{\\verb|{%}|\n}\\end{document}}";
    for (source, expected_end) in [
        (structural.as_str(), short.len()),
        (plain, plain.len()),
        (percent, percent.len()),
    ] {
        let analysis = Index::new(source).analyze().unwrap();
        assert_eq!(analysis.ranges, [(0, expected_end)], "{source}");
        assert!(
            analysis
                .regions
                .iter()
                .all(|region| region.kind != RegionKind::Literal)
        );
    }
    for literal in [r"\verb|%|", r"\verb\text\"] {
        let source = format!("{literal}\\newcommand{{\\sample}}{{\\par}}");
        let analysis = Index::new(&source).analyze().unwrap();
        assert_eq!(analysis.ranges, [(literal.len(), source.len())]);
        assert_eq!(
            analysis.regions,
            [Region {
                start: 0,
                end: literal.len(),
                kind: RegionKind::Literal
            }]
        );
    }
}

#[test]
fn original_line_tokens_distinguish_comments_and_consumed_paragraphs() {
    for newline in ["\n", "\r\n", "\r"] {
        let prefix = r"\newcommand{\sample}";
        for (gap, paragraph) in [
            (newline.to_owned(), false),
            (format!("{newline}% comment{newline}"), false),
            (format!("{newline}{newline}"), true),
            (format!("{newline}% comment{newline} \t{newline}"), true),
        ] {
            let source = format!("{prefix}{gap}{{\\end{{document}}}}");
            let analysis = Index::new(&source).analyze().unwrap();
            let expected_end = if paragraph {
                prefix.len() + gap.len()
            } else {
                source.len()
            };
            assert_eq!(analysis.ranges, [(0, expected_end)], "{source:?}");
        }
    }
    let blank = Index::new(" \t");
    assert_eq!(
        blank.resume(0, Continuation::AfterName),
        Completion::Complete(2)
    );
    assert!(blank.owns_eof(2));
    let empty = Index::new("");
    assert_eq!(
        empty.resume(0, Continuation::AfterName),
        Completion::Pending(Continuation::AfterName)
    );
    assert!(!empty.owns_eof(0));
}

#[test]
fn monotone_resumption_discards_consumed_candidates_without_losing_recovery() {
    let prefix = r"\renewcommand{\relax}";
    let nested = r"\newcommand{\sample}{\end{document}}";
    let source = format!("{prefix}{{{nested}}}");
    let index = Index::new(&source);
    assert_eq!(
        index.resume(0, Continuation::Command),
        Completion::Complete(prefix.len())
    );
    let mut cursor = index.cursor(0);
    let mut selected = Vec::new();
    let mut collected_until = prefix.len();
    while let Some(item) = index.next(&mut cursor, collected_until).unwrap() {
        if let Item::Definition { start, end } = item {
            selected.push((start, end));
            collected_until = end;
        }
    }
    assert_eq!(
        selected,
        [(prefix.len() + 1, prefix.len() + 1 + nested.len())]
    );
    for prefix in [
        r"\newcommand{",
        r"\newcommand{\outer}[",
        r"\newcommand{\outer}[1][",
        r"\newcommand{\outer}{",
    ] {
        let source = format!("{prefix}\\newcommand");
        let index = Index::new(&source);
        let mut cursor = index.cursor(0);
        assert!(matches!(
            index.next(&mut cursor, 0).unwrap(),
            Some(Item::Token { .. })
        ));
        index.advance(&mut cursor, prefix.len());
        while let Some(item) = index.next(&mut cursor, 0).unwrap() {
            assert!(!matches!(item, Item::Pending(_)), "{source}");
        }
    }
}
