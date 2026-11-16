//! Resource-only span edits for HTML, CSS and XML SVG.
use crate::html::{HtmlNode, ParsedHtml, member};
use anyhow::{Context, Result, bail, ensure};
use cssparser::{ParseError, Parser, ParserInput, Token};
use std::{collections::BTreeSet, ops::Range};

type Edit = (Range<usize>, String);
fn apply(text: &str, mut edits: Vec<Edit>) -> Result<String> {
    edits.sort_by_key(|edit| edit.0.start);
    let mut out = String::new();
    let mut cursor = 0;
    for (range, replacement) in edits {
        ensure!(
            range.start >= cursor && range.end >= range.start && range.end <= text.len(),
            "overlapping container resource syntax"
        );
        out.push_str(&text[cursor..range.start]);
        out.push_str(&replacement);
        cursor = range.end;
    }
    out.push_str(&text[cursor..]);
    Ok(out)
}
fn escaped(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
fn direct(tag: &str, namespace: &str, name: &str, get: impl Fn(&str) -> String) -> bool {
    let tag = crate::resource_preflight::resource_tag(tag, namespace);
    match name {
        "src" => {
            member("img source video audio track", tag)
                || (tag == "input" && get("type").eq_ignore_ascii_case("image"))
        }
        "poster" => tag == "video",
        "background" => member("body table td th", tag),
        "href" | "xlink:href" => {
            (namespace == "svg"
                && member(
                    "image use feimage lineargradient radialgradient pattern textpath mpath color-profile font-face-uri glyphref altglyph cursor",
                    tag,
                ))
                || (tag == "link"
                    && get("rel").split_ascii_whitespace().any(|rel| {
                        member(
                            "stylesheet icon preload modulepreload",
                            &rel.to_ascii_lowercase(),
                        )
                    }))
        }
        _ => false,
    }
}
fn paint(name: &str) -> bool {
    member(
        "fill stroke filter clip-path mask marker marker-start marker-mid marker-end cursor",
        name,
    )
}
fn check_svg_link(
    tag: &str,
    namespace: &str,
    name: &str,
    value: &str,
    resource: bool,
) -> Result<()> {
    ensure!(
        namespace != "svg"
            || !member("href xlink:href", name)
            || tag == "a"
            || resource
            || value.trim().is_empty()
            || value.trim_start().starts_with('#'),
        "container SVG reference requires reviewed static artwork"
    );
    Ok(())
}
fn attribute(
    node: &HtmlNode,
    name: &str,
    value: &str,
    rewrite: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<Option<String>> {
    let tag = crate::resource_preflight::resource_tag(&node.tag, &node.namespace);
    if ((name == "srcset" && member("img source", tag))
        || (name == "imagesrcset" && node.tag == "link"))
        && !value.trim().is_empty()
    {
        bail!("container srcset requires reviewed static image references");
    }
    if name == "style" || (node.namespace == "svg" && paint(name)) {
        return Ok(Some(css(value, rewrite)?));
    }
    let resource = direct(&node.tag, &node.namespace, name, |key| {
        node.attr(key).into()
    });
    check_svg_link(&node.tag, &node.namespace, name, value, resource)?;
    if resource && !value.trim().is_empty() {
        return Ok(Some(rewrite(value)?));
    }
    Ok(None)
}
/// Raw attribute value spans, checked against the production HTML model before use.
fn attrs(text: &str, start: usize, end: usize) -> Result<Vec<(String, Range<usize>)>> {
    let bytes = text.as_bytes();
    let mut i = start + 1;
    while i < end && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'/' | b'>') {
        i += 1;
    }
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    while i + 1 < end {
        while i + 1 < end && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        if i + 1 >= end {
            break;
        }
        let name = i;
        while i + 1 < end && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'=' | b'/') {
            i += 1;
        }
        ensure!(
            i > name,
            "container HTML attribute requires reviewed static syntax"
        );
        let name = text[name..i].to_ascii_lowercase();
        ensure!(
            seen.insert(name.clone()),
            "container duplicate attribute requires reviewed static syntax"
        );
        while i + 1 < end && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes[i] != b'=' {
            continue;
        }
        i += 1;
        while i + 1 < end && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let value = i;
        if matches!(bytes[i], b'\'' | b'"') {
            let quote = bytes[i];
            i += 1;
            while i + 1 < end && bytes[i] != quote {
                i += 1;
            }
            ensure!(
                bytes[i] == quote,
                "container HTML attribute is unterminated"
            );
            i += 1;
        } else {
            while i + 1 < end && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
        }
        result.push((name, value..i));
    }
    Ok(result)
}
pub(super) fn html(text: &str, rewrite: &mut dyn FnMut(&str) -> Result<String>) -> Result<String> {
    let model = ParsedHtml::parse(text)?;
    crate::resource_preflight::html_urls(&model)?;
    let mut old_urls = Vec::new();
    let mut new_urls = Vec::new();
    let mut tracked = |url: &str| {
        let replacement = rewrite(url)?;
        old_urls.push(url.to_owned());
        new_urls.push(replacement.clone());
        Ok(replacement)
    };
    let mut edits = Vec::new();
    for node in &model.nodes {
        let start = model.original_offset(node.start);
        let end = model.original_offset(node.content);
        for (name, range) in attrs(text, start, end)? {
            let value = node
                .attrs
                .get(&name)
                .context("container HTML attribute disagrees with source model")?;
            if let Some(replacement) = attribute(node, &name, value, &mut tracked)?
                && replacement != *value
            {
                edits.push((range, format!("\"{}\"", escaped(&replacement))));
            }
        }
        if node.tag == "style" {
            let range =
                model.original_offset(node.content)..model.original_offset(node.content_end);
            let value = &text[range.clone()];
            ensure!(
                value == &model.text[node.content..node.content_end],
                "container foreign style entities require reviewed static CSS"
            );
            ensure!(
                node.namespace == "html" || !value.contains('<'),
                "container foreign style markup requires reviewed static CSS"
            );
            let replacement = css(value, &mut tracked)?;
            if replacement != value {
                edits.push((range, replacement));
            }
        }
    }
    crate::resource_preflight::require_html5_agreement(text, &old_urls)?;
    let output = apply(text, edits)?;
    crate::resource_preflight::require_staged_html5_agreement(&output, &new_urls)?;
    Ok(output)
}

pub(super) fn css(text: &str, rewrite: &mut dyn FnMut(&str) -> Result<String>) -> Result<String> {
    crate::resource_preflight::css_urls(text)?;
    let mut input = ParserInput::new(text);
    let mut parser = Parser::new(&mut input);
    let mut edits = Vec::new();
    css_tokens(&mut parser, rewrite, &mut edits, false, false).map_err(|error| {
        anyhow::anyhow!("container CSS URL rewrite requires static syntax: {error:?}")
    })?;
    apply(text, edits)
}
fn quoted(value: &str) -> String {
    let mut out = String::new();
    cssparser::serialize_string(value, &mut out).expect("writing a CSS string cannot fail");
    out
}
fn css_tokens<'i>(
    parser: &mut Parser<'i, '_>,
    rewrite: &mut dyn FnMut(&str) -> Result<String>,
    edits: &mut Vec<Edit>,
    image_strings: bool,
    target_attribute: bool,
) -> std::result::Result<(), ParseError<'i, String>> {
    let mut import = false;
    while !parser.is_exhausted() {
        let start = parser.position().byte_index();
        let token = parser.next_including_whitespace_and_comments()?.clone();
        if matches!(token, Token::WhiteSpace(_) | Token::Comment(_)) {
            continue;
        }
        let imported = import;
        import = false;
        let rewritten = match token {
            Token::AtKeyword(name) if name.eq_ignore_ascii_case("import") => {
                import = true;
                None
            }
            Token::AtKeyword(name) if name.eq_ignore_ascii_case("namespace") => {
                crate::resource_preflight::namespace_prelude(parser)?;
                None
            }
            Token::AtKeyword(name) if name.eq_ignore_ascii_case("charset") => {
                let encoding = parser.expect_string()?.to_string();
                if !encoding.eq_ignore_ascii_case("utf-8") {
                    return Err(
                        parser.new_custom_error("container CSS encoding must be UTF-8".to_owned())
                    );
                }
                None
            }
            Token::UnquotedUrl(url) => Some(format!(
                "url({})",
                quoted(&rewrite(&url).map_err(|error| parser.new_custom_error(error.to_string()))?)
            )),
            Token::QuotedString(url) if imported || image_strings => {
                Some(quoted(&rewrite(&url).map_err(|error| {
                    parser.new_custom_error(error.to_string())
                })?))
            }
            Token::Function(name)
                if name.eq_ignore_ascii_case("url") || name.eq_ignore_ascii_case("src") =>
            {
                let value = parser.parse_nested_block(|nested| {
                    let value = nested.expect_string()?.to_string();
                    nested.expect_exhausted()?;
                    Ok(value)
                })?;
                Some(format!(
                    "{}({})",
                    name,
                    quoted(
                        &rewrite(&value)
                            .map_err(|error| parser.new_custom_error(error.to_string()))?
                    )
                ))
            }
            Token::Function(name) => {
                if name.eq_ignore_ascii_case("attr") && !target_attribute {
                    return Err(parser.new_custom_error(
                        "container CSS attribute URL requires reviewed static CSS".to_owned(),
                    ));
                }
                parser.parse_nested_block(|nested| {
                    css_tokens(
                        nested,
                        rewrite,
                        edits,
                        member(
                            "image image-set -webkit-image-set",
                            &name.to_ascii_lowercase(),
                        ),
                        member(
                            "target-counter target-counters target-text",
                            &name.to_ascii_lowercase(),
                        ),
                    )
                })?;
                None
            }
            Token::CurlyBracketBlock | Token::ParenthesisBlock | Token::SquareBracketBlock => {
                parser.parse_nested_block(|nested| {
                    css_tokens(nested, rewrite, edits, false, false)
                })?;
                None
            }
            _ => None,
        };
        if let Some(value) = rewritten {
            edits.push((start..parser.position().byte_index(), value));
        }
    }
    Ok(())
}
pub(super) fn svg(text: &str, rewrite: &mut dyn FnMut(&str) -> Result<String>) -> Result<String> {
    crate::resource_preflight::svg_urls(text.as_bytes())?;
    if let Some(declaration) = text.trim_start_matches('\u{feff}').strip_prefix("<?xml")
        && declaration.starts_with(char::is_whitespace)
    {
        let attributes = declaration
            .split_once("?>")
            .context("container SVG declaration is incomplete")?
            .0;
        let fragment = format!("<declaration {attributes}/>");
        let parsed = roxmltree::Document::parse(&fragment)?;
        ensure!(
            parsed
                .root_element()
                .attribute("encoding")
                .is_none_or(|encoding| encoding.eq_ignore_ascii_case("utf-8")),
            "container SVG encoding must be UTF-8"
        );
    }
    let document = roxmltree::Document::parse(text)?;
    ensure!(
        !document
            .descendants()
            .any(|node| node.pi().is_some_and(|pi| pi.target == "xml-stylesheet")),
        "container XML stylesheet requires reviewed static SVG"
    );
    let mut edits = Vec::new();
    for node in document.descendants().filter(|node| node.is_element()) {
        let tag = node.tag_name().name().to_ascii_lowercase();
        ensure!(
            !node
                .attribute("rel")
                .unwrap_or("")
                .split_ascii_whitespace()
                .any(|rel| rel.eq_ignore_ascii_case("attachment")),
            "container SVG attachment requires explicit authorization"
        );
        for attr in node.attributes() {
            let name = attr.name().to_ascii_lowercase();
            ensure!(
                !((name == "srcset" && member("img source", &tag))
                    || (name == "imagesrcset" && tag == "link"))
                    || attr.value().trim().is_empty(),
                "container SVG srcset requires reviewed static image references"
            );
            let resource = direct(&tag, "svg", &name, |key| {
                node.attribute(key).unwrap_or("").into()
            });
            check_svg_link(&tag, "svg", &name, attr.value(), resource)?;
            let value = if name == "style" || paint(&name) {
                Some(css(attr.value(), rewrite)?)
            } else if resource {
                Some(rewrite(attr.value())?)
            } else {
                None
            };
            if let Some(value) = value
                && value != attr.value()
            {
                edits.push((attr.range_value(), escaped(&value)));
            }
        }
        if tag == "style" {
            ensure!(
                node.children().count() <= 1 && node.children().all(|child| child.is_text()),
                "container SVG style markup requires reviewed static SVG"
            );
            for child in node.children().filter(|node| node.is_text()) {
                let range = child.range();
                let value = child.text().unwrap_or("");
                ensure!(
                    text[range.clone()] == *value,
                    "container SVG style CDATA/entities require reviewed static SVG"
                );
                let rewritten = css(value, rewrite)?;
                if rewritten != value {
                    edits.push((
                        range,
                        rewritten
                            .replace('&', "&amp;")
                            .replace('<', "&lt;")
                            .replace('>', "&gt;"),
                    ));
                }
            }
        }
    }
    apply(text, edits)
}
