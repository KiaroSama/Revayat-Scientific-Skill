//! Explicit subset of HTML5 implied closures, refusing ambiguous tree repairs.
use crate::html::{ParsedHtml, member};
use anyhow::{Result, bail};
pub(crate) const P_CLOSERS: &str = "address article aside blockquote center details dialog dir div dl fieldset figcaption figure footer form h1 h2 h3 h4 h5 h6 header hgroup hr listing main menu nav ol p pre search section summary table ul li dt dd xmp";
pub(crate) const FORMATTING: &str = "a b big code em font i nobr s small strike strong tt u";
const SCOPE: &str = "applet caption html table td th marquee object template";
const TABLE_PARTS: &str = "caption colgroup col thead tbody tfoot tr td th";
const TABLE_CONTEXT: &str = "table thead tbody tfoot tr colgroup";
const HEADINGS: &str = "h1 h2 h3 h4 h5 h6";
const HEAD_CONTENT: &str = "base basefont bgsound link meta title noframes style script template";
fn special(t: &str) -> bool {
    member(P_CLOSERS, t)
        || member(TABLE_PARTS, t)
        || member(HEADINGS, t)
        || member(SCOPE, t)
        || member(
            "area base basefont bgsound body br button embed head iframe img input keygen link meta noembed noframes noscript object optgroup option param plaintext script select source style textarea title track wbr",
            t,
        )
}
fn scoped(
    p: &ParsedHtml,
    target: impl Fn(&str) -> bool,
    fence: impl Fn(&str) -> bool,
) -> Option<usize> {
    for (i, &n) in p.stack.iter().enumerate().rev() {
        let node = &p.nodes[n];
        if node.namespace != "html" {
            return None;
        }
        if target(&node.tag) {
            return Some(i);
        }
        if fence(&node.tag) {
            return None;
        }
    }
    None
}
pub(crate) fn close_from(
    p: &mut ParsedHtml,
    index: Option<usize>,
    start: usize,
    end: usize,
) -> Result<()> {
    if let Some(index) = index {
        if p.stack[index + 1..]
            .iter()
            .any(|&n| member(FORMATTING, &p.nodes[n].tag))
        {
            bail!("HTML formatting reconstruction requires explicitly nested markup");
        }
        while p.stack.len() > index {
            let n = p.stack.pop().expect("nonempty");
            p.finish(n, start, end);
        }
    }
    Ok(())
}
fn close(p: &mut ParsedHtml, target: &str, fences: &str, start: usize) -> Result<()> {
    let index = scoped(p, |t| member(target, t), |t| member(fences, t));
    close_from(p, index, start, start)
}
pub(crate) fn before_start(p: &mut ParsedHtml, tag: &str, start: usize) -> Result<()> {
    if p.namespace_for(tag) != "html" {
        return Ok(());
    }
    if member("a button form select", tag)
        && p.stack
            .iter()
            .any(|&i| p.nodes[i].tag == tag && p.nodes[i].namespace == "html")
    {
        bail!("nested interactive HTML requires an explicitly reviewed static source");
    }
    if member("html body head", tag)
        && p.nodes
            .iter()
            .any(|n| n.tag == tag && n.namespace == "html")
    {
        bail!("duplicate HTML document containers require a normalized source");
    }
    if !member(HEAD_CONTENT, tag) {
        close(p, "head", "html body", start)?;
    }
    if member(P_CLOSERS, tag) {
        let index = scoped(p, |t| t == "p", |t| member(SCOPE, t) || t == "button");
        close_from(p, index, start, start)?;
    }
    if tag == "li" {
        let i = scoped(
            p,
            |t| t == "li",
            |t| special(t) && !member("address div p", t),
        );
        close_from(p, i, start, start)?;
    } else if member("dt dd", tag) {
        let i = scoped(
            p,
            |t| member("dt dd", t),
            |t| special(t) && !member("address div p", t),
        );
        close_from(p, i, start, start)?;
    } else if member(HEADINGS, tag) {
        let i = scoped(p, |t| member(HEADINGS, t), |t| member(SCOPE, t));
        if let Some(i) = i {
            if i + 1 != p.stack.len() {
                bail!("misnested HTML heading requires explicit end tags");
            }
            close_from(p, Some(i), start, start)?;
        }
    }
    if tag == "hr" && scoped(p, |t| t == "select", |t| member("html table", t)).is_some() {
        bail!("HTML select separators require an explicit renderer-compatible source");
    }
    if member("option optgroup", tag) {
        close(p, "option", "select optgroup html", start)?;
        if tag == "optgroup" {
            close(p, "optgroup", "select html", start)?;
        }
    }
    if scoped(p, |t| t == "select", |t| member("html table", t)).is_some()
        && !member("option optgroup hr script", tag)
    {
        bail!("unsupported HTML select content requires a static reviewed source");
    }
    let table = scoped(p, |t| t == "table", |t| t == "html");
    if table.is_none() && member(TABLE_PARTS, tag) {
        bail!("HTML table parts outside a table require normalization");
    }
    if table.is_some() && tag != "col" {
        close(p, "colgroup", "table td th", start)?;
    }
    if table.is_some() && member(TABLE_PARTS, tag) {
        close(p, "caption", "table", start)?;
        if member("td th tr thead tbody tfoot caption colgroup", tag) {
            close(p, "td th", "table", start)?;
        }
        if member("tr thead tbody tfoot caption colgroup", tag) {
            close(p, "tr", "table", start)?;
        }
        if member("thead tbody tfoot caption colgroup", tag) {
            close(p, "thead tbody tfoot caption colgroup", "table", start)?;
        }
    }
    if let Some(&index) = p.stack.last() {
        let parent = &p.nodes[index];
        if parent.namespace == "html" && member(TABLE_CONTEXT, &parent.tag) {
            let allowed = match parent.tag.as_str() {
                "table" => "caption colgroup col thead tbody tfoot tr td th",
                "thead" | "tbody" | "tfoot" => "tr td th",
                "tr" => "td th",
                "colgroup" => "col",
                _ => "",
            };
            if !member(allowed, tag) && !member("script style", tag) {
                bail!("HTML table foster parenting requires explicit cell structure");
            }
        }
    }
    Ok(())
}
pub(crate) fn before_text(p: &mut ParsedHtml, text: &str, start: usize) -> Result<()> {
    if text.trim().is_empty() {
        return Ok(());
    }
    close(p, "head", "html body", start)?;
    if p.stack
        .last()
        .is_some_and(|&i| p.nodes[i].namespace == "html" && member(TABLE_CONTEXT, &p.nodes[i].tag))
    {
        bail!("HTML table foster parenting requires text inside cells");
    }
    Ok(())
}
pub(crate) fn end_index(p: &ParsedHtml, tag: &str) -> Result<Option<usize>> {
    if member("body html", tag) {
        return Ok(None);
    }
    for (i, &n) in p.stack.iter().enumerate().rev() {
        if p.nodes[n].tag == tag && p.nodes[n].namespace != "html" {
            return Ok(Some(i));
        }
    }
    if member(HEADINGS, tag)
        && let Some(i) = scoped(p, |t| member(HEADINGS, t), |t| member(SCOPE, t))
        && p.nodes[p.stack[i]].tag != tag
    {
        bail!("mismatched HTML heading end tag requires normalization");
    }
    if member(FORMATTING, tag) {
        return Ok(scoped(p, |t| t == tag, |_| false));
    }
    let index = scoped(
        p,
        |t| t == tag,
        |t| {
            if tag == "li" {
                member(SCOPE, t) || member("ul ol menu", t)
            } else if tag == "p" {
                member(SCOPE, t) || t == "button"
            } else if member(TABLE_PARTS, tag) || member("table select", tag) {
                member("html table", t)
            } else if member("dt dd form", tag)
                || member(HEADINGS, tag)
                || (member(P_CLOSERS, tag)
                    && !member("p li dt dd hr table xmp", tag)
                    && !member(HEADINGS, tag))
                || tag == "button"
            {
                member(SCOPE, t)
            } else {
                special(t)
            }
        },
    );
    if tag == "form" && index.is_some_and(|i| i + 1 != p.stack.len()) {
        bail!("HTML form removal requires explicitly nested markup");
    }
    Ok(index)
}
