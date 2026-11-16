//! Bounded Transitional OOXML inventory, creation and byte-preserving text edits.
//! Archive members are never extracted and relationships are never fetched.
use crate::{identity, publication};
use anyhow::{Context, Result, bail, ensure};
use roxmltree::{Document, Node};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use unicode_casefold::UnicodeCaseFold;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

pub const W: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
pub const R: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
pub const C: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
pub const MAIN_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";
pub const MAX_XML: usize = 16 * 1024 * 1024;
pub const MAX_MEMBER: u64 = 64 * 1024 * 1024;
pub const MAX_TOTAL: u64 = 256 * 1024 * 1024;

#[derive(Debug)]
pub struct Member {
    pub name: String,
    pub data: Vec<u8>,
}
#[derive(Debug)]
pub struct Package {
    pub members: Vec<Member>,
    pub relationships: Vec<Value>,
    pub unsupported: Vec<String>,
    pub stories: BTreeSet<String>,
    pub comment: Vec<u8>,
}
impl Package {
    pub fn member(&self, name: &str) -> Option<&[u8]> {
        self.members
            .iter()
            .find(|m| m.name == name)
            .map(|m| m.data.as_slice())
    }
}

fn ascii_lower(value: &str) -> String {
    value.to_ascii_lowercase()
}
fn case_key(value: &str) -> String {
    // Supplement the crate's full-fold table with current standard-library
    // lowercase mappings for scripts added in newer Unicode releases.
    value
        .chars()
        .flat_map(char::to_lowercase)
        .case_fold()
        .collect()
}
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains(['\\', ':'])
        && name.split('/').all(|p| !matches!(p, "" | "." | ".."))
}
fn xml(data: &[u8]) -> Result<Document<'_>> {
    ensure!(data.len() <= MAX_XML, "XML part exceeds 16 MiB limit");
    let text = std::str::from_utf8(data).context("XML parts must use UTF-8")?;
    let lower = text.to_ascii_lowercase();
    // XML declarations are disallowed even if whitespace obscures the token.
    let declaration = regex::Regex::new(r"(?i)<!\s*(?:DOCTYPE|ENTITY)")?;
    ensure!(
        !declaration.is_match(text),
        "DTD and entity declarations are not supported"
    );
    if let Some(rest) = lower.trim_start_matches('\u{feff}').strip_prefix("<?xml")
        && let Some(end) = rest.find("?>")
    {
        let encoding = regex::Regex::new(r#"encoding\s*=\s*["']([^"']+)["']"#)?;
        if let Some(found) = encoding.captures(&rest[..end]) {
            ensure!(
                matches!(&found[1], "utf-8" | "utf8"),
                "XML parts must use UTF-8; convert a copy before editing"
            );
        }
    }
    Document::parse(text).context("invalid XML structure")
}
fn is(node: Node<'_, '_>, namespace: &str, local: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == local
}
fn child<'a, 'input>(node: Node<'a, 'input>, local: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|n| is(*n, W, local))
}
fn content_types(
    root: Node<'_, '_>,
) -> Result<(BTreeMap<String, String>, BTreeMap<String, String>)> {
    let (mut overrides, mut defaults) = (BTreeMap::new(), BTreeMap::new());
    for node in root.children().filter(Node::is_element) {
        let override_type = is(node, C, "Override");
        if !override_type && !is(node, C, "Default") {
            continue;
        }
        let key = node
            .attribute(if override_type {
                "PartName"
            } else {
                "Extension"
            })
            .filter(|s| !s.is_empty())
            .context("missing package content type declaration")?;
        let value = node
            .attribute("ContentType")
            .filter(|s| !s.is_empty())
            .context("missing package content type declaration")?;
        let destination = if override_type {
            &mut overrides
        } else {
            &mut defaults
        };
        ensure!(
            destination
                .insert(ascii_lower(key), value.to_owned())
                .is_none(),
            "duplicate package content type declaration"
        );
    }
    Ok((overrides, defaults))
}
fn declared_type<'a>(
    part: &str,
    overrides: &'a BTreeMap<String, String>,
    defaults: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
    overrides
        .get(&ascii_lower(&format!("/{part}")))
        .or_else(|| defaults.get(&ascii_lower(part.rsplit('.').next().unwrap_or(part))))
        .map(String::as_str)
}
fn story_type(kind: &str) -> Option<&'static str> {
    match kind {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml" => Some("hdr"),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml" => Some("ftr"),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml" => {
            Some("footnotes")
        }
        "application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml" => {
            Some("endnotes")
        }
        "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml" => {
            Some("comments")
        }
        _ => None,
    }
}
fn legacy_story(name: &str) -> Option<&'static str> {
    let name = name.strip_prefix("word/")?.strip_suffix(".xml")?;
    match name {
        "document" => Some("document"),
        "footnotes" => Some("footnotes"),
        "endnotes" => Some("endnotes"),
        "comments" => Some("comments"),
        _ => {
            for (prefix, root) in [("header", "hdr"), ("footer", "ftr")] {
                if let Some(number) = name.strip_prefix(prefix)
                    && !number.is_empty()
                    && number.bytes().all(|b| b.is_ascii_digit())
                {
                    return Some(root);
                }
            }
            None
        }
    }
}
fn resolve_target(owner: &str, target: &str) -> Result<String> {
    let path = target.split(['?', '#']).next().unwrap_or("");
    ensure!(
        !path.starts_with("//") && !path.split('/').next().unwrap_or("").contains(':'),
        "unsafe internal relationship"
    );
    let mut decoded = Vec::new();
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(a), Some(b)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            decoded.push((a * 16 + b) as u8);
            i += 3;
            continue;
        }
        decoded.push(bytes[i]);
        i += 1;
    }
    let decoded =
        std::str::from_utf8(&decoded).context("invalid internal relationship encoding")?;
    ensure!(!decoded.contains('\\'), "unsafe internal relationship");
    let combined = if decoded.starts_with('/') {
        decoded.trim_start_matches('/').to_owned()
    } else if owner.is_empty() {
        decoded.to_owned()
    } else {
        format!("{owner}/{decoded}")
    };
    let mut parts = Vec::new();
    for part in combined.split('/') {
        match part {
            "" | "." => (),
            ".." => {
                ensure!(parts.pop().is_some(), "escaping internal relationship");
            }
            _ => parts.push(part),
        }
    }
    let resolved = parts.join("/");
    ensure!(safe_name(&resolved), "unsafe internal relationship");
    Ok(resolved)
}

pub fn read_package(path: &Path) -> Result<Package> {
    ensure!(
        fs::metadata(path)?.is_file() && fs::metadata(path)?.len() <= 128 * 1024 * 1024,
        "DOCX must be a regular ZIP file no larger than 128 MiB"
    );
    let mut archive = ZipArchive::new(File::open(path)?).context("invalid DOCX ZIP archive")?;
    ensure!(
        !archive.is_empty() && archive.len() <= 4096,
        "DOCX must contain 1 to 4096 archive members"
    );
    let mut seen = HashSet::new();
    let mut total = 0u64;
    // Check the complete central directory before allocating any expanded member.
    for index in 0..archive.len() {
        let member = archive.by_index(index)?;
        let name = member.name()?;
        ensure!(
            safe_name(if member.is_dir() {
                name.trim_end_matches('/')
            } else {
                &name
            }) && seen.insert(case_key(&name)),
            "unsafe or duplicate archive member name"
        );
        ensure!(
            !member.encrypted()
                && member.unix_mode().is_none_or(|m| m & 0o170000 != 0o120000)
                && matches!(
                    member.compression(),
                    CompressionMethod::Stored | CompressionMethod::Deflated
                ),
            "encrypted, linked or unsupported ZIP member"
        );
        total = total
            .checked_add(member.size())
            .context("DOCX expansion overflow")?;
        ensure!(
            member.size() <= MAX_MEMBER
                && total <= MAX_TOTAL
                && member.size() <= member.compressed_size().max(1).saturating_mul(1000),
            "DOCX exceeds archive expansion limits"
        );
    }
    let comment = archive.comment().to_vec();
    let mut members = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name()?.into_owned();
        let declared_size = entry.size();
        let mut data = Vec::with_capacity(declared_size as usize);
        entry
            .by_ref()
            .take(declared_size + 1)
            .read_to_end(&mut data)
            .context("DOCX member CRC or decompression failure")?;
        ensure!(
            data.len() as u64 == declared_size,
            "DOCX member size disagrees with its directory"
        );
        members.push(Member { name, data });
    }
    let mut roots = BTreeMap::new();
    for member in &members {
        if member.name.to_ascii_lowercase().ends_with(".xml")
            || member.name.to_ascii_lowercase().ends_with(".rels")
        {
            roots.insert(member.name.clone(), xml(&member.data)?);
        }
    }
    for name in ["[Content_Types].xml", "_rels/.rels", "word/document.xml"] {
        ensure!(
            roots.contains_key(name),
            "DOCX is missing required package parts"
        );
    }
    let content = roots["[Content_Types].xml"].root_element();
    ensure!(
        is(content, C, "Types"),
        "invalid package content types root"
    );
    let document = roots["word/document.xml"].root_element();
    ensure!(
        is(document, W, "document") && child(document, "body").is_some(),
        "unsupported WordprocessingML; convert Strict OOXML to a Transitional copy"
    );
    let (overrides, defaults) = content_types(content)?;
    for member in &members {
        if member.name == "[Content_Types].xml" || member.name.ends_with('/') {
            continue;
        }
        let declared = declared_type(&member.name, &overrides, &defaults)
            .context("archive member has no declared content type")?;
        if story_type(declared).is_some() && !roots.contains_key(&member.name) {
            roots.insert(member.name.clone(), xml(&member.data)?);
        }
    }
    let mut stories = BTreeSet::from(["word/document.xml".to_owned()]);
    for (name, root) in &roots {
        if let Some(declared) = declared_type(name, &overrides, &defaults) {
            if let Some(expected) = story_type(declared) {
                ensure!(
                    is(root.root_element(), W, expected),
                    "story root disagrees with its declared content type"
                );
                stories.insert(name.clone());
            } else if matches!(declared, "application/xml" | "text/xml")
                && let Some(expected) = legacy_story(name)
            {
                ensure!(
                    is(root.root_element(), W, expected),
                    "legacy story root disagrees with its canonical name"
                );
                stories.insert(name.clone());
            }
        }
    }
    let main = declared_type("word/document.xml", &overrides, &defaults)
        .context("missing main content type")?;
    ensure!(
        matches!(
            main,
            MAIN_TYPE | "application/vnd.ms-word.document.macroEnabled.main+xml"
        ),
        "unsupported main document content type"
    );
    let mut relationships = Vec::new();
    for (name, document) in &roots {
        if !name.to_ascii_lowercase().ends_with(".rels") {
            continue;
        }
        let root = document.root_element();
        ensure!(is(root, R, "Relationships"), "invalid relationships root");
        let owner = if name == "_rels/.rels" {
            ""
        } else {
            name.rsplit_once('/')
                .and_then(|(p, _)| p.rsplit_once('/'))
                .map(|(p, _)| p)
                .unwrap_or("")
        };
        let mut ids = HashSet::new();
        for rel in root.children().filter(Node::is_element) {
            let id = rel
                .attribute("Id")
                .filter(|s| !s.is_empty())
                .context("missing relationship identifier")?;
            let target = rel
                .attribute("Target")
                .filter(|s| !s.is_empty())
                .context("missing relationship target")?;
            let kind = rel
                .attribute("Type")
                .filter(|s| !s.is_empty())
                .context("missing relationship type")?;
            ensure!(
                is(rel, R, "Relationship") && ids.insert(id),
                "invalid or duplicate relationship"
            );
            let mode = rel.attribute("TargetMode").unwrap_or("Internal");
            ensure!(
                matches!(mode, "Internal" | "External"),
                "unknown relationship target mode"
            );
            let resolved = if mode == "Internal" {
                let resolved = resolve_target(owner, target)?;
                ensure!(
                    members.iter().any(|m| m.name == resolved),
                    "missing internal relationship"
                );
                Some(resolved)
            } else {
                None
            };
            relationships.push(json!({"part":name,"id":id,"type":kind,"target":target,"mode":mode,"resolved":resolved}));
        }
    }
    ensure!(
        relationships.iter().any(|r| r["part"] == "_rels/.rels"
            && r["resolved"] == "word/document.xml"
            && r["type"]
                .as_str()
                .is_some_and(|s| s.ends_with("/officeDocument"))),
        "DOCX has no main document relationship"
    );
    let declared: BTreeSet<_> = members
        .iter()
        .filter(|m| m.name != "[Content_Types].xml" && !m.name.ends_with('/'))
        .filter_map(|m| declared_type(&m.name, &overrides, &defaults))
        .map(ascii_lower)
        .collect();
    let relation_types: BTreeSet<_> = relationships
        .iter()
        .filter_map(|r| r["type"].as_str())
        .collect();
    let signature_types = ["origin", "xmlsignature+xml", "certificate"]
        .map(|s| format!("application/vnd.openxmlformats-package.digital-signature-{s}"));
    let signature_relations = ["origin", "signature", "certificate"].map(|s| {
        format!(
            "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/{s}"
        )
    });
    let vba_types = [
        "vbaProject",
        "vbaProjectSignature",
        "vbaProjectSignatureAgile",
        "vbaProjectSignatureV3",
    ]
    .map(|s| format!("application/vnd.ms-office.{s}").to_ascii_lowercase());
    let mut vba_relations: Vec<_> = [
        "vbaProject",
        "vbaProjectSignature",
        "vbaProjectSignatureAgile",
    ]
    .iter()
    .map(|s| format!("http://schemas.microsoft.com/office/2006/relationships/{s}"))
    .collect();
    vba_relations.extend([
        "http://schemas.microsoft.com/office/2014/relationships/vbaProjectSignatureAgile"
            .to_owned(),
        "http://schemas.microsoft.com/office/2020/07/relationships/vbaProjectSignatureV3"
            .to_owned(),
    ]);
    let mut unsupported = Vec::new();
    if members
        .iter()
        .any(|m| m.name.to_ascii_lowercase().contains("vba"))
        || main.contains("macroEnabled")
        || vba_types.iter().any(|s| declared.contains(s))
        || vba_relations
            .iter()
            .any(|s| relation_types.contains(s.as_str()))
    {
        unsupported.push("macros".into());
    }
    if members
        .iter()
        .any(|m| m.name.to_ascii_lowercase().starts_with("_xmlsignatures/"))
        || signature_types.iter().any(|s| declared.contains(s))
        || signature_relations
            .iter()
            .any(|s| relation_types.contains(s.as_str()))
    {
        unsupported.push("digital-signatures".into());
    }
    if relation_types.iter().any(|s| {
        ["/oleObject", "/package", "/aFChunk"]
            .iter()
            .any(|suffix| s.ends_with(suffix))
    }) {
        unsupported.push("embedded-or-alternate-content".into());
    }
    drop(roots);
    Ok(Package {
        members,
        relationships,
        unsupported,
        stories,
        comment,
    })
}

pub fn inspect_package(path: &Path) -> Result<Value> {
    let package = read_package(path)?;
    let mut nodes = Vec::new();
    let mut sections = Vec::new();
    let mut structures = BTreeMap::<String, u64>::new();
    let counted = [
        "tbl",
        "drawing",
        "fldSimple",
        "fldChar",
        "ins",
        "del",
        "commentReference",
        "footnoteReference",
        "endnoteReference",
        "hyperlink",
        "oMath",
    ];
    for member in &package.members {
        let lower = member.name.to_ascii_lowercase();
        if !lower.ends_with(".xml")
            && !lower.ends_with(".rels")
            && !package.stories.contains(&member.name)
        {
            continue;
        }
        let root = xml(&member.data)?;
        if package.stories.contains(&member.name) {
            for (index, node) in root.descendants().filter(|n| is(*n, W, "t")).enumerate() {
                nodes.push(
                    json!({"part":member.name,"index":index,"text":node.text().unwrap_or("")}),
                );
            }
        }
        for node in root.descendants().filter(Node::is_element) {
            if counted.contains(&node.tag_name().name()) {
                *structures.entry(node.tag_name().name().into()).or_default() += 1;
            }
            if is(node, W, "sectPr") {
                let mut geometry = BTreeMap::new();
                for field in ["pgSz", "pgMar", "cols"] {
                    if let Some(element) = child(node, field) {
                        geometry.insert(
                            field,
                            element
                                .attributes()
                                .map(|a| (a.name(), a.value()))
                                .collect::<BTreeMap<_, _>>(),
                        );
                    }
                }
                sections.push(json!({"part":member.name,"geometry_twips":geometry}));
            }
        }
    }
    let media:Vec<_>=package.members.iter().filter(|m|m.name.starts_with("word/media/")).map(|m|json!({"part":m.name,"bytes":m.data.len(),"sha256":format!("{:x}",Sha256::digest(&m.data))})).collect();
    Ok(
        json!({"format":"docx","validation":"structural-only","render_status":"not-performed","text_nodes":nodes,"sections":sections,"relationships":package.relationships,"media":media,"structures":structures,"unsupported":package.unsupported}),
    )
}
pub fn require_editable(unsupported: &[String]) -> Result<()> {
    ensure!(
        unsupported.is_empty(),
        "unsupported DOCX features: {}; retain the original and convert/review a separate copy",
        unsupported.join(", ")
    );
    Ok(())
}
fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
fn attr(text: &str) -> String {
    xml_escape(text)
        .replace('"', "&quot;")
        .replace('\r', "&#13;")
        .replace('\n', "&#10;")
        .replace('\t', "&#9;")
}
fn tag_end(data: &[u8], start: usize) -> Result<usize> {
    let mut quote = None;
    for (offset, &b) in data[start..].iter().enumerate() {
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
        } else if matches!(b, b'\'' | b'"') {
            quote = Some(b);
        } else if b == b'>' {
            return Ok(start + offset + 1);
        }
    }
    bail!("unterminated XML tag")
}
fn valid_text(text: &str, patch: bool) -> bool {
    (!patch && text.chars().count() <= 100000 || patch)
        && text.chars().all(|c| {
            (c >= ' ' || (!patch && matches!(c, '\t' | '\n'))) && c != '\u{fffe}' && c != '\u{ffff}'
        })
}

pub fn edit_package(
    source: &Path,
    destination: &Path,
    patches: &Value,
    protected_sources: &[PathBuf],
) -> Result<()> {
    edit_package_observed(source, destination, patches, protected_sources, |_| Ok(()))
}

#[derive(Debug)]
pub enum EditEvent<'a> {
    StoryIndexed {
        part: &'a str,
        text_nodes: usize,
    },
    Publication {
        boundary: publication::Boundary,
        path: &'a Path,
    },
}

/// Observe real indexing/publication boundaries, including recoverable failures.
pub fn edit_package_observed(
    source: &Path,
    destination: &Path,
    patches: &Value,
    protected_sources: &[PathBuf],
    mut observe: impl FnMut(EditEvent<'_>) -> Result<()>,
) -> Result<()> {
    let mut protected = vec![source.to_path_buf()];
    protected.extend_from_slice(protected_sources);
    let destination = publication::validate_destination(destination, &protected)?;
    let source_before = identity::file_identity(source, Some(128 * 1024 * 1024))?;
    let package = read_package(source)?;
    require_editable(&package.unsupported)?;
    let patches = patches
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 100000)
        .context("patch must be a nonempty array of at most 100000 edits")?;
    let mut seen = HashSet::new();
    let mut edits = BTreeMap::<&str, Vec<(usize, &str, &str)>>::new();
    for patch in patches {
        object(patch, &["part", "index", "expected", "text"], &[])?;
        let part = patch["part"].as_str().context("invalid patch part")?;
        let index = patch["index"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .context("invalid patch index")?;
        let expected = patch["expected"]
            .as_str()
            .context("invalid expected text type")?;
        let text = patch["text"].as_str().context("invalid patch text type")?;
        ensure!(
            package.stories.contains(part),
            "invalid patch story address"
        );
        ensure!(seen.insert((part, index)), "duplicate patch address");
        ensure!(
            valid_text(text, true),
            "patch text contains unsupported control/XML characters"
        );
        edits.entry(part).or_default().push((index, expected, text));
    }
    let mut changed = BTreeMap::new();
    let space_attribute = regex::Regex::new(r#"\bxml:space\s*=\s*(?:"[^"]*"|'[^']*')"#)?;
    for (part, items) in edits {
        let data = package.member(part).context("missing story part")?;
        let root = xml(data)?;
        let nodes: Vec<_> = root.descendants().filter(|n| is(*n, W, "t")).collect();
        observe(EditEvent::StoryIndexed {
            part,
            text_nodes: nodes.len(),
        })?;
        for node in &nodes {
            ensure!(
                node.children().all(|n| n.is_text()),
                "nested markup, comments or processing instructions inside text nodes are unsupported"
            );
        }
        let mut replacements = Vec::new();
        let mut output_size = data.len() as i128;
        for (index, expected, text) in items {
            let node = nodes
                .get(index)
                .context("stale patch: addressed node does not exist")?;
            ensure!(
                node.text().unwrap_or("") == expected,
                "stale patch: expected text does not match addressed node"
            );
            let first = node.range().start;
            let start = tag_end(data, first)?;
            let empty = data[first..start].ends_with(b"/>");
            let content_end = if empty {
                start
            } else {
                let closing = data[first..node.range().end]
                    .windows(2)
                    .rposition(|b| b == b"</")
                    .context("missing text closing tag")?;
                first + closing
            };
            let mut tag = std::str::from_utf8(&data[first..start])?.to_owned();
            if empty {
                tag.truncate(tag.len() - 2);
                tag.push('>');
            }
            if text.trim() != text {
                if space_attribute.is_match(&tag) {
                    tag = space_attribute
                        .replace(&tag, "xml:space=\"preserve\"")
                        .into_owned();
                } else {
                    tag.pop();
                    tag.push_str(" xml:space=\"preserve\">");
                }
            }
            let mut replacement = tag;
            replacement.push_str(&xml_escape(text));
            if empty {
                let name = std::str::from_utf8(&data[first + 1..start])?
                    .split(|c: char| c.is_whitespace() || c == '/' || c == '>')
                    .next()
                    .context("invalid text tag")?;
                replacement.push_str(&format!("</{name}>"));
            }
            output_size += replacement.len() as i128 - (content_end - first) as i128;
            replacements.push((first, content_end, replacement));
        }
        ensure!(
            output_size <= MAX_XML as i128,
            "XML part exceeds 16 MiB limit"
        );
        replacements.sort_by_key(|r| r.0);
        let mut output = Vec::with_capacity(output_size as usize);
        let mut cursor = 0;
        for (start, end, value) in replacements {
            output.extend_from_slice(&data[cursor..start]);
            output.extend_from_slice(value.as_bytes());
            cursor = end;
        }
        output.extend_from_slice(&data[cursor..]);
        xml(&output)?;
        changed.insert(part.to_owned(), output);
    }
    let directory = tempfile::Builder::new()
        .prefix(".revayat-docx-")
        .tempdir_in(destination.parent().context("output has no parent")?)?;
    let staged = directory.path().join("document.docx");
    let mut original = ZipArchive::new(File::open(source)?)?;
    let mut writer = ZipWriter::new(File::create(&staged)?);
    writer.set_raw_comment(package.comment.clone().into_boxed_slice())?;
    for index in 0..original.len() {
        let entry = original.by_index(index)?;
        let name = entry.name()?.into_owned();
        if let Some(data) = changed.get(&name) {
            let mut options = SimpleFileOptions::default().compression_method(entry.compression());
            if let Some(time) = entry.last_modified() {
                options = options.last_modified_time(time);
            }
            if let Some(mode) = entry.unix_mode() {
                options = options.unix_permissions(mode);
            }
            writer.start_file(&name, options)?;
            writer.write_all(data)?;
        } else {
            writer.raw_copy_file(entry)?;
        }
    }
    writer.finish()?.sync_all()?;
    read_package(&staged)?;
    ensure!(
        source_before == identity::file_identity(source, Some(128 * 1024 * 1024))?,
        "source changed during DOCX edit"
    );
    publication::publish_observed(
        &[(staged, destination)],
        &protected,
        Some(128 * 1024 * 1024),
        |boundary, path| {
            if boundary == publication::Boundary::BeforeCommit {
                ensure!(
                    source_before == identity::file_identity(source, Some(128 * 1024 * 1024))?,
                    "source changed before DOCX publication"
                );
            }
            observe(EditEvent::Publication { boundary, path })
        },
    )
}

pub fn write_report(report: &Value, destination: &Path, source: &Path) -> Result<()> {
    let protected = vec![source.to_path_buf()];
    let destination = publication::validate_destination(destination, &protected)?;
    let directory = tempfile::Builder::new()
        .prefix(".revayat-docx-")
        .tempdir_in(destination.parent().context("output has no parent")?)?;
    let staged = directory.path().join("report.json");
    let mut bytes = serde_json::to_vec_pretty(report)?;
    bytes.push(b'\n');
    fs::write(&staged, bytes)?;
    publication::publish_files(&[(staged, destination)], &protected, None)
}

#[path = "docx_cli.rs"]
mod command;
#[path = "docx_create.rs"]
mod create;
pub use command::cli;
use create::object;
pub use create::{create_document, load_json, paragraph_xml};
