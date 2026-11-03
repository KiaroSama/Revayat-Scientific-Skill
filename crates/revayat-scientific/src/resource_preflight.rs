//! Token-based discovery of resource URLs which a browser can load without Fetch.
//!
//! Literal examples, RCDATA, comments and ordinary CSS strings never become URLs.
//! Malformed URL tokens and unsupported dynamic image sources require static CSS.
use crate::html::{ParsedHtml, member};
use anyhow::{Result, bail, ensure};
use cssparser::{ParseError, Parser, ParserInput, Token};
const MAX_CSS_TOKENS: usize = 2_000_000;
const MAX_CSS_DEPTH: usize = 128;

pub fn css_urls(text: &str) -> Result<Vec<String>> {
    let mut input = ParserInput::new(text);
    let mut parser = Parser::new(&mut input);
    let mut urls = Vec::new();
    css_tokens(&mut parser, &mut urls, 0, &mut 0, false).map_err(|error| {
        anyhow::anyhow!("CSS URL preflight requires reviewed static CSS: {error:?}")
    })?;
    Ok(urls)
}
fn css_tokens<'i>(
    parser: &mut Parser<'i, '_>,
    urls: &mut Vec<String>,
    depth: usize,
    steps: &mut usize,
    quoted_urls: bool,
) -> Result<(), ParseError<'i, String>> {
    if depth > MAX_CSS_DEPTH {
        return Err(parser.new_custom_error("CSS nesting exceeds 128"));
    }
    let mut import = false;
    let mut namespace_rule = false;
    while !parser.is_exhausted() {
        *steps += 1;
        if *steps > MAX_CSS_TOKENS {
            return Err(parser.new_custom_error("CSS token budget exceeded"));
        }
        let token = parser.next()?.clone();
        if namespace_rule {
            if token == Token::Semicolon {
                namespace_rule = false;
            }
            continue;
        }
        let import_value = import;
        import = false;
        match token {
            Token::AtKeyword(name) if name.eq_ignore_ascii_case("import") => import = true,
            Token::AtKeyword(name) if name.eq_ignore_ascii_case("namespace") => {
                namespace_rule = true
            }
            Token::UnquotedUrl(url) => urls.push(url.to_string()),
            Token::QuotedString(url) if import_value || quoted_urls => urls.push(url.to_string()),
            Token::Function(name)
                if name.eq_ignore_ascii_case("url") || name.eq_ignore_ascii_case("src") =>
            {
                parser.parse_nested_block(|nested| {
                    let url = nested.expect_string()?.to_string();
                    nested.expect_exhausted()?;
                    urls.push(url);
                    Ok(())
                })?;
            }
            Token::Function(name) => {
                if quoted_urls && member("var env attr", &name.to_ascii_lowercase()) {
                    return Err(parser
                        .new_custom_error("dynamic image string requires reviewed static CSS"));
                }
                let image_strings = member(
                    "image image-set -webkit-image-set",
                    &name.to_ascii_lowercase(),
                );
                parser.parse_nested_block(|nested| {
                    css_tokens(nested, urls, depth + 1, steps, image_strings)
                })?;
            }
            Token::CurlyBracketBlock | Token::ParenthesisBlock | Token::SquareBracketBlock => {
                parser.parse_nested_block(|nested| {
                    css_tokens(nested, urls, depth + 1, steps, false)
                })?;
            }
            token if token.is_parse_error() => {
                return Err(parser.new_custom_error("malformed CSS URL or string"));
            }
            _ => (),
        }
        if urls.len() > 2048 {
            return Err(parser.new_custom_error("CSS resource count exceeds 2048"));
        }
    }
    Ok(())
}
/// WHATWG srcset's URL collection preserves commas inside a data URL. Resource
/// descriptors are then consumed with their parenthesis state, never split as URLs.
pub fn srcset_urls(value: &str) -> Result<Vec<String>> {
    let bytes = value.as_bytes();
    let mut position = 0;
    let mut urls = Vec::new();
    while position < bytes.len() {
        while position < bytes.len()
            && (bytes[position].is_ascii_whitespace() || bytes[position] == b',')
        {
            position += 1;
        }
        if position == bytes.len() {
            break;
        }
        let start = position;
        while position < bytes.len() && !bytes[position].is_ascii_whitespace() {
            position += 1;
        }
        let raw = &value[start..position];
        let url = raw.trim_end_matches(',');
        ensure!(!url.is_empty(), "empty srcset URL");
        urls.push(url.to_owned());
        ensure!(urls.len() <= 2048, "srcset resource count exceeds 2048");
        if raw.ends_with(',') {
            continue;
        }
        let mut depth = 0usize;
        while position < bytes.len() {
            match bytes[position] {
                b'(' => {
                    depth += 1;
                    ensure!(depth <= 128, "srcset descriptor nesting exceeds 128");
                }
                b')' => {
                    ensure!(depth > 0, "unbalanced srcset descriptor");
                    depth -= 1;
                }
                b',' if depth == 0 => {
                    position += 1;
                    break;
                }
                _ => (),
            }
            position += 1;
        }
        ensure!(depth == 0, "unclosed srcset descriptor");
    }
    Ok(urls)
}
fn attributes(tag: &str, namespace: &str, get: impl Fn(&str) -> String) -> Result<Vec<String>> {
    let mut urls = Vec::new();
    let mut add = |name| {
        let value = get(name);
        if !value.trim().is_empty() {
            urls.push(value);
        }
    };
    if member("img source video audio track", tag)
        || (tag == "input" && get("type").eq_ignore_ascii_case("image"))
    {
        add("src");
    }
    if tag == "video" {
        add("poster");
    }
    if member("body table td th", tag) {
        add("background");
    }
    if tag == "link"
        && get("rel").split_ascii_whitespace().any(|r| {
            member(
                "stylesheet icon preload modulepreload",
                &r.to_ascii_lowercase(),
            )
        })
    {
        add("href");
    }
    if namespace == "svg"
        && member(
            "image use feimage lineargradient radialgradient pattern textpath mpath color-profile font-face-uri glyphref altglyph cursor",
            tag,
        )
    {
        add("href");
        add("xlink:href");
    }
    if member("img source", tag) {
        urls.extend(srcset_urls(&get("srcset"))?);
    }
    if tag == "link" {
        urls.extend(srcset_urls(&get("imagesrcset"))?);
    }
    urls.extend(css_urls(&get("style"))?);
    Ok(urls)
}
pub fn html_urls(model: &ParsedHtml) -> Result<Vec<String>> {
    let mut urls = Vec::new();
    for node in &model.nodes {
        ensure!(
            node.attr("xml:base").trim().is_empty(),
            "XML base requires reviewed static artwork"
        );
        if node.namespace == "svg"
            && member("animate animatemotion animatetransform set", &node.tag)
        {
            bail!("animated SVG requires reviewed static artwork");
        }
        urls.extend(attributes(&node.tag, &node.namespace, |name| {
            node.attr(name).into()
        })?);
        if node.tag == "style" {
            urls.extend(css_urls(&model.text[node.content..node.content_end])?);
        }
        if node.namespace == "svg" {
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
                urls.extend(css_urls(node.attr(name))?);
            }
        }
        ensure!(urls.len() <= 2048, "document resource count exceeds 2048");
    }
    Ok(urls)
}
pub fn svg_urls(bytes: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(bytes)?;
    let document = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: 100_000,
        },
    )?;
    ensure!(
        document
            .root_element()
            .tag_name()
            .name()
            .eq_ignore_ascii_case("svg"),
        "embedded SVG requires an SVG root"
    );
    let mut urls = Vec::new();
    for instruction in document.descendants().filter_map(|node| node.pi()) {
        if instruction.target == "xml-stylesheet" {
            let fragment = format!("<stylesheet {}/>", instruction.value.unwrap_or(""));
            let attributes = roxmltree::Document::parse(&fragment)?;
            if let Some(href) = attributes.root_element().attribute("href") {
                urls.push(href.to_owned());
            }
        }
    }
    for node in document.descendants().filter(|n| n.is_element()) {
        ensure!(
            node.attribute(("http://www.w3.org/XML/1998/namespace", "base"))
                .is_none_or(|value| value.trim().is_empty()),
            "XML base requires reviewed static artwork"
        );
        let tag = node.tag_name().name().to_ascii_lowercase();
        if member(
            "script iframe object embed base animate animatemotion animatetransform set",
            &tag,
        ) {
            bail!("active or animated SVG requires reviewed static artwork");
        }
        ensure!(
            !node
                .attributes()
                .any(|a| a.name().to_ascii_lowercase().starts_with("on")),
            "SVG event handlers require static artwork"
        );
        urls.extend(attributes(&tag, "svg", |name| {
            if name == "xlink:href" {
                node.attribute(("http://www.w3.org/1999/xlink", "href"))
            } else {
                node.attribute(name)
            }
            .unwrap_or("")
            .into()
        })?);
        if tag == "style" {
            urls.extend(css_urls(
                &node.children().filter_map(|n| n.text()).collect::<String>(),
            )?);
        }
        // SVG presentation attributes can carry paint-server and filter URLs.
        for attribute in [
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
            if let Some(value) = node.attribute(attribute) {
                urls.extend(css_urls(value)?);
            }
        }
        ensure!(urls.len() <= 2048, "SVG resource count exceeds 2048");
    }
    Ok(urls)
}
