//! Static paragraph and literal whitespace information for isolate checks.
use super::ParsedHtml;

pub(super) fn preserved_newlines(tag: &str, style: &str, inherited: bool) -> bool {
    let mut preserve = matches!(tag, "pre" | "textarea" | "xmp" | "listing") || inherited;
    let mut important = false;
    // This tracks literal inline declarations, not a computed stylesheet cascade.
    for declaration in style.split(';') {
        let Some((name, value)) = declaration.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if !matches!(name.as_str(), "white-space" | "white-space-collapse") {
            continue;
        }
        let value = value.trim().to_ascii_lowercase();
        let priority = value.ends_with("!important");
        if important && !priority {
            continue;
        }
        let value = value.trim_end_matches("!important").trim();
        let selected = match value {
            "pre" | "pre-wrap" | "pre-line" if name == "white-space" => true,
            "normal" | "nowrap" if name == "white-space" => false,
            "break-spaces" | "preserve" | "preserve-breaks" => true,
            "collapse" | "preserve-spaces" | "discard" | "initial" => false,
            "inherit" | "unset" => inherited,
            _ => continue,
        };
        preserve = selected;
        important = priority;
    }
    preserve
}

impl ParsedHtml {
    pub(crate) fn bidi_prose_ranges(
        &self,
    ) -> impl Iterator<Item = (usize, usize, bool, bool)> + '_ {
        self.bidi_tokens.iter().map(|&(a, b, checked, preserve)| {
            (
                self.normalized_offset(a),
                self.normalized_offset(b),
                checked,
                preserve,
            )
        })
    }
}
