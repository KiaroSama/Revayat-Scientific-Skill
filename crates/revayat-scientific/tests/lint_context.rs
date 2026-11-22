use revayat_scientific::lint::{self, Source};
use std::fs;

#[test]
fn bidi_isolates_balance_within_checked_prose_lines() {
    let directory = tempfile::tempdir().unwrap();
    for (extension, prefix, suffix) in [
        (
            "html",
            "<!doctype html>\n<html lang=\"fa\"><body>\n",
            "</body></html>\n",
        ),
        (
            "tex",
            "\\documentclass{article}\n\\begin{document}\n",
            "\\end{document}\n",
        ),
    ] {
        let path = directory.path().join(format!("source.{extension}"));
        for (text, lines) in [
            ("\u{2067}Rust برای پژوهش\u{2069}\n", &[][..]),
            (
                "\u{200f}\u{2067}Rust برای پژوهش \u{2066}API\u{2069} \u{2068}نمونه\u{2069}\u{2069}\n",
                &[],
            ),
            ("\u{2067}Rust برای پژوهش\n", &[3]),
            ("\u{2066}Rust\n", &[3]),
            ("\u{2068}نمونه\n", &[3]),
            ("Rust برای پژوهش\u{2069}\n", &[3]),
            ("\u{2067}Rust برای پژوهش\nنمونه\u{2069}\n", &[3, 4]),
        ] {
            fs::write(&path, format!("{prefix}{text}{suffix}")).unwrap();
            let findings =
                lint::check(&Source::load(&path).unwrap(), &[], None, "system-docs").unwrap();
            let isolates: Vec<_> = findings
                .iter()
                .filter(|f| f.check == "bidi-isolate")
                .map(|f| (f.level.as_str(), f.line))
                .collect();
            let expected: Vec<_> = lines.iter().map(|&line| ("error", line)).collect();
            assert_eq!(isolates, expected, "{extension}: {text:?}");
        }
    }
}
