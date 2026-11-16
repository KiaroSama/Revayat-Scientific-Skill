//! Independent HTML5 interpretation gate for the source-span resource model.
//!
//! The span parser preserves source bytes. The HTML5 tree builder supplies a
//! separate resource inventory after tree repair, namespace integration and
//! raw-text handling. Any disagreement refuses rendering before resources can
//! escape the private staged view. Deprecated isindex and scripting-dependent
//! noscript are refused because renderer/parser versions disagree on their tree.
use super::{attributes, css_urls};
use crate::html::member;
use anyhow::{Result, ensure};
use scraper::{ElementRef, Html};
use std::collections::BTreeMap;

// The source parser has already enforced its 100000-element/512-depth limits.
// Document parsing may insert html, head and body; a fragment's deepest element
// gains html/body plus the document node, which ancestors() counts without self.
const MAX_REPAIRED_ELEMENTS: usize = 100_000 + 3;
const MAX_REPAIRED_ANCESTORS: usize = 512 + 2;

pub(crate) fn require_agreement(text: &str, expected: &[String]) -> Result<()> {
    require_bounded_agreement(text, expected, 16 * 1024 * 1024)
}
pub(crate) fn require_staged_agreement(text: &str, expected: &[String]) -> Result<()> {
    // URL expansion affects only the private derivative. Original admission has
    // already enforced 16 MiB; the derivative retains the existing resource cap.
    require_bounded_agreement(text, expected, crate::resource::MAX_RESOURCE_BYTES)
}
fn require_bounded_agreement(text: &str, expected: &[String], byte_limit: usize) -> Result<()> {
    let mut actual = urls(text, byte_limit)?;
    let mut expected = expected.to_vec();
    actual.sort();
    expected.sort();
    ensure!(
        actual == expected,
        "HTML5 resource interpretation disagrees with source resource spans; reviewed static markup required"
    );
    Ok(())
}
fn urls(text: &str, byte_limit: usize) -> Result<Vec<String>> {
    ensure!(
        text.len() <= byte_limit,
        "HTML5 input exceeds its admitted byte budget"
    );
    let document = Html::parse_document(text);
    let mut urls = Vec::new();
    let mut elements = 0;
    for node in document.tree.root().descendants() {
        let Some(element) = node.value().as_element() else {
            continue;
        };
        elements += 1;
        ensure!(
            elements <= MAX_REPAIRED_ELEMENTS,
            "HTML5 element budget exceeded"
        );
        ensure!(
            node.ancestors().take(MAX_REPAIRED_ANCESTORS + 1).count() <= MAX_REPAIRED_ANCESTORS,
            "HTML5 repaired nesting exceeds bounded source view"
        );
        let namespace = match element.name.ns.as_ref() {
            "http://www.w3.org/1999/xhtml" => "html",
            "http://www.w3.org/2000/svg" => "svg",
            "http://www.w3.org/1998/Math/MathML" => "math",
            _ => anyhow::bail!("HTML5 foreign namespace requires reviewed static markup"),
        };
        let tag = element.name().to_ascii_lowercase();
        let attrs: BTreeMap<String, String> = element
            .attrs
            .iter()
            .map(|(name, value)| {
                let key = name.prefix.as_ref().map_or_else(
                    || name.local.to_string(),
                    |prefix| format!("{prefix}:{}", name.local),
                );
                (key.to_ascii_lowercase(), value.to_string())
            })
            .collect();
        let get = |name: &str| attrs.get(name).map(String::as_str).unwrap_or("");
        ensure!(
            !member("script iframe object embed base isindex noscript", &tag)
                && !(tag == "meta" && get("http-equiv").eq_ignore_ascii_case("refresh")),
            "HTML5 active or parser-dependent content requires reviewed static markup"
        );
        ensure!(
            !get("rel")
                .split_ascii_whitespace()
                .any(|rel| rel.eq_ignore_ascii_case("attachment")),
            "PDF attachment requires explicit authorization; omitted by this renderer"
        );
        ensure!(
            get("xml:base").trim().is_empty(),
            "XML base requires reviewed static artwork"
        );
        ensure!(
            namespace != "svg" || !member("animate animatemotion animatetransform set", &tag),
            "animated SVG requires reviewed static artwork"
        );
        urls.extend(attributes(&tag, namespace, |name| get(name).to_owned())?);
        if tag == "style" {
            let text = ElementRef::wrap(node)
                .expect("element node")
                .text()
                .collect::<String>();
            urls.extend(css_urls(&text)?);
        }
        if namespace == "svg" {
            for name in [
                "fill",
                "stroke",
                "filter",
                "clip-path",
                "mask",
                "marker",
                "marker-start",
                "marker-mid",
                "marker-end",
                "cursor",
            ] {
                urls.extend(css_urls(get(name))?);
            }
        }
        ensure!(urls.len() <= 2048, "HTML5 resource count exceeds 2048");
    }
    Ok(urls)
}
