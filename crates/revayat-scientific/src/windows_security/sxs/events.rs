//! Strict bounded Application/SideBySide XML classification with no raw payload in diagnostics.
use super::{PrivateFailure, safe};
use anyhow::Result;
use roxmltree::{Document, Node, ParsingOptions};
const NS: &str = "http://schemas.microsoft.com/win/2004/08/events/event";
fn check(value: bool) -> Result<()> {
    if !value {
        return Err(PrivateFailure {
            stage: "event-evidence",
            original: anyhow::anyhow!("fixed SxS event evidence contract failed"),
        }
        .into());
    }
    Ok(())
}
fn one<'a, 'input>(parent: Node<'a, 'input>, name: &str) -> Result<Node<'a, 'input>> {
    let mut children = parent
        .children()
        .filter(|node| node.has_tag_name((NS, name)));
    let child = children.next();
    check(child.is_some() && children.next().is_none())?;
    Ok(child.unwrap())
}
fn leaf(node: Node<'_, '_>, scalar: bool, attributes: &[&str]) -> Result<()> {
    for attribute in node.attributes() {
        check(attribute.namespace().is_none() && attributes.contains(&attribute.name()))?;
    }
    for child in node.children() {
        check(child.is_text() && (scalar || child.text().is_some_and(|s| s.trim().is_empty())))?;
    }
    Ok(())
}
fn scalar(node: Node<'_, '_>) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .collect()
}
fn decimal(text: &str) -> Result<u32> {
    check(!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))?;
    text.parse()
        .map_err(|e: std::num::ParseIntError| safe(e.into(), "event-evidence"))
}
fn timestamp(value: &str) -> Result<[u32; 7]> {
    let bytes = value.as_bytes();
    check(
        (20..=28).contains(&bytes.len())
            && value.is_ascii()
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && bytes.last() == Some(&b'Z'),
    )?;
    let year = decimal(&value[..4])?;
    let month = decimal(&value[5..7])?;
    let day = decimal(&value[8..10])?;
    let hour = decimal(&value[11..13])?;
    let minute = decimal(&value[14..16])?;
    let second = decimal(&value[17..19])?;
    check(
        (1..=9999).contains(&year)
            && (1..=12).contains(&month)
            && hour < 24
            && minute < 60
            && second < 60,
    )?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    check(day >= 1 && day <= days)?;
    let fraction = if bytes.len() == 20 {
        0
    } else {
        check(bytes[19] == b'.' && (22..=28).contains(&bytes.len()))?;
        let digits = &value[20..value.len() - 1];
        decimal(digits)? * 10u32.pow(7 - digits.len() as u32)
    };
    Ok([year, month, day, hour, minute, second, fraction])
}
fn guid(value: &str) -> bool {
    let text = value
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(value);
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn boolean(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}
pub fn classify_event(xml: &str, image: &str, start: &str, end: &str) -> Result<Option<String>> {
    check(!xml.is_empty() && xml.encode_utf16().count() <= 32768 && !xml.contains("<!DOCTYPE"))?;
    let start = timestamp(start)?;
    let end = timestamp(end)?;
    check(start <= end)?;
    let document = Document::parse_with_options(
        xml,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: 2048,
        },
    )
    .map_err(|e| safe(e.into(), "event-evidence"))?;
    let mut elements = 0;
    for node in document.descendants() {
        check(
            node.ancestors()
                .filter(Node::is_element)
                .count()
                .saturating_sub(usize::from(node.is_element()))
                <= 6,
        )?;
        if node.is_element() {
            elements += 1;
            check(elements <= 256)?;
        }
    }
    let root = document.root_element();
    check(root.has_tag_name((NS, "Event")))?;
    let system = one(root, "System")?;
    let data = one(root, "EventData")?;
    for child in root.children().filter(Node::is_element) {
        check(child == system || child == data)?;
    }
    let provider = one(system, "Provider")?;
    let channel = one(system, "Channel")?;
    let event = one(system, "EventID")?;
    let created = one(system, "TimeCreated")?;
    leaf(provider, false, &["Name", "Guid", "EventSourceName"])?;
    leaf(channel, true, &[])?;
    leaf(event, true, &["Qualifiers"])?;
    leaf(created, false, &["SystemTime"])?;
    if let Some(value) = provider.attribute("Guid") {
        check(guid(value))?;
    }
    if let Some(value) = event.attribute("Qualifiers") {
        check(decimal(value)? <= 65535)?;
    }
    check(provider.attribute("Name") == Some("SideBySide") && scalar(channel) == "Application")?;
    let id = decimal(&scalar(event))?;
    check(id <= 65535)?;
    let time = timestamp(created.attribute("SystemTime").unwrap_or(""))?;
    check(time >= start && time <= end)?;
    let mut values = Vec::new();
    let mut matches = 0;
    let mut count = 0;
    for child in data.children().filter(Node::is_element) {
        count += 1;
        check(
            child.has_tag_name((NS, "Data"))
                && count <= 32
                && !child.children().any(|n| n.is_element()),
        )?;
        let value = scalar(child);
        check(value.encode_utf16().count() <= 16384)?;
        if super::ordinal_path_equal(&value, image)? {
            matches += 1;
        } else {
            values.push(value);
        }
    }
    check(matches <= 1)?;
    if matches == 0 {
        return Ok(None);
    }
    let text = values.join("\n").to_ascii_lowercase();
    let has = |literal| text.contains(literal);
    Ok(Some(format!(
        "WINDOWS_SXS_EVENT phase=modified-preflight event_id={id} matched_owned_image=True access_denied={} dependent_assembly_not_found={} reference_definition_mismatch={} manifest_invalid={} common_controls={} common_controls_resources={} vc90_crt={} ucrt={} amd64={} x86={} producer_verified=False cause_claimed=False",
        boolean(has("access is denied") || has("access denied")),
        boolean(has("dependent assembly") && has("could not be found")),
        boolean(has("does not match") || has("not match")),
        boolean(has("manifest") && has("invalid")),
        boolean(has("microsoft.windows.common-controls")),
        boolean(has("microsoft.windows.common-controls.resources")),
        boolean(has("microsoft.vc90.crt")),
        boolean(has("ucrt")),
        boolean(has("amd64")),
        boolean(has("x86"))
    )))
}
