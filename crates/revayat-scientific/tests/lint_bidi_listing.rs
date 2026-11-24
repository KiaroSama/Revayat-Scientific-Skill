use revayat_scientific::lint::{self, Source};
use std::fs;

#[test]
fn listing_newlines_follow_the_element_default_and_inline_overrides() {
    for newline in ["\n", "\r\n", "\r"] {
        for tag in ["listing", "textarea", "xmp"] {
            for (style, expected) in [
                ("", 2),
                (" style=\"white-space: normal\"", 0),
                (" style=\"white-space: pre\"", 2),
            ] {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("source.html");
                fs::write(
                    &path,
                    format!(
                        "<!doctype html>\n<html lang=\"fa\"><body>\n<{tag}{style}>\u{2067}before{newline}after\u{2069}</{tag}>\n</body></html>"
                    ),
                )
                .unwrap();
                let findings: Vec<_> =
                    lint::check(&Source::load(&path).unwrap(), &[], None, "system-docs")
                        .unwrap()
                        .into_iter()
                        .filter(|finding| finding.check == "bidi-isolate")
                        .collect();
                assert_eq!(findings.len(), expected, "{tag}{style}, {newline:?}");
                if expected == 2 && newline == "\n" {
                    assert_eq!(
                        findings
                            .iter()
                            .map(|finding| finding.line)
                            .collect::<Vec<_>>(),
                        [3, 4],
                        "{tag}{style}"
                    );
                }
            }
        }
    }
}
