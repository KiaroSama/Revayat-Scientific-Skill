use super::*;

#[test]
fn supported_eof_lookahead_states_resume_from_original_suffixes() {
    for (prefix, state, suffix) in [
        (r"\newcommand", Continuation::Command, r"\sample{\par}"),
        ("\\newcommand\n", Continuation::Command, r"\sample{\par}"),
        (r"\renewcommand", Continuation::Command, r"\sample{\par}"),
        (r"\newcommand*\sample", Continuation::AfterName, r"{\par}"),
        (r"\newcommand{\sample}", Continuation::AfterName, r"{\par}"),
        (
            r"\newcommand\sample[1]",
            Continuation::AfterFirstOption,
            r"[default]{#1\par}",
        ),
        (
            r"\renewcommand*{\sample}[1]",
            Continuation::AfterFirstOption,
            r"{#1\par}",
        ),
    ] {
        let local = Index::new(prefix).local();
        assert!(local.ranges.is_empty(), "{prefix}");
        assert_eq!(local.pending, Some(Pending { start: 0, state }), "{prefix}");
        let preceding = "earlier text ";
        let caller = format!("{preceding}{suffix} Visible\\par");
        let resumed = Index::new(&caller).resume(preceding.len(), state);
        assert_eq!(
            resumed,
            Completion::Complete(preceding.len() + suffix.len()),
            "{prefix} -> {suffix}"
        );
    }
}

#[test]
fn argument_collection_boundaries_do_not_become_eof_continuations() {
    for prefix in [
        r"\newcommand*",
        r"\newcommand{",
        r"\newcommand\sample[",
        r"\newcommand\sample[1][",
        r"\newcommand\sample[1][default]",
        r"\newcommand\sample{",
        r"\newcommandextra",
        r"\\newcommand",
    ] {
        assert_eq!(Index::new(prefix).local().pending, None, "{prefix}");
    }
    for (state, suffix, unfinished) in [
        (Continuation::Command, "*", false),
        (Continuation::Command, "{", true),
        (Continuation::AfterName, "[", true),
        (Continuation::AfterFirstOption, "[default]", false),
        (Continuation::AfterName, "{open", true),
    ] {
        assert_eq!(
            Index::new(suffix).resume(0, state),
            Completion::Invalid { unfinished },
            "{state:?}: {suffix}"
        );
    }
}

#[test]
fn empty_returns_and_successive_lookahead_phases_preserve_pending_state() {
    let mut state = Continuation::Command;
    for (text, expected) in [
        ("", Continuation::Command),
        (r"\sample", Continuation::AfterName),
        ("[1]", Continuation::AfterFirstOption),
    ] {
        assert_eq!(
            Index::new(text).resume(0, state),
            Completion::Pending(expected)
        );
        state = expected;
        let empty = Index::new("");
        for _ in 0..crate::tex::MAX_DEPTH {
            assert_eq!(empty.resume(0, state), Completion::Pending(state));
        }
    }
    assert_eq!(
        Index::new("{#1\\par} Visible\\par").resume(0, state),
        Completion::Complete("{#1\\par}".len())
    );
}

#[test]
fn continuation_queries_reuse_one_index_with_bounded_actual_work() {
    let item = "{body} ";
    let text = item.repeat(100_000);
    let mut visits = 0;
    let index = Index::new_observed(&text, &mut || visits += 1);
    let local = index.local_observed(&mut || visits += 1);
    assert!(local.ranges.is_empty());
    assert_eq!(local.pending, None);
    let indexed_visits = visits;
    assert!(indexed_visits <= text.len() * 32 + 16);
    for position in 0..crate::tex::MAX_FILES {
        let offset = position * 733 * item.len();
        let before = visits;
        assert_eq!(
            index.resume_observed(offset, Continuation::AfterName, &mut || visits += 1),
            Completion::Complete(offset + "{body}".len())
        );
        assert!(
            visits - before <= 64,
            "continuation revisited source text: {} work units",
            visits - before
        );
    }
}
