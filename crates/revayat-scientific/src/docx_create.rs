//! New DOCX creation with strict JSON, script-aware runs and bounded images.
use super::*;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::{io::Cursor, path::Component, sync::LazyLock};

// Deserialize recursively without silently accepting duplicate object keys.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = seq.next_element::<Unique>()? {
                    values.push(v.0);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((k, v)) = map.next_entry::<String, Unique>()? {
                    if values.insert(k, v.0).is_some() {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}
pub fn load_json(path: &Path) -> Result<Value> {
    ensure!(
        fs::metadata(path)?.len() <= 8 * 1024 * 1024,
        "JSON input exceeds 8 MiB limit"
    );
    let mut data = Vec::new();
    File::open(path)?
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut data)?;
    ensure!(
        data.len() <= 8 * 1024 * 1024,
        "JSON input exceeds 8 MiB limit"
    );
    Ok(serde_json::from_slice::<Unique>(&data)
        .context("invalid content JSON")?
        .0)
}
pub(super) fn object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a serde_json::Map<String, Value>> {
    let value = value
        .as_object()
        .context("content entry must be an object")?;
    ensure!(
        required.iter().all(|key| value.contains_key(*key))
            && value
                .keys()
                .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str())),
        "missing or unknown content JSON fields"
    );
    Ok(value)
}
fn text(value: &Value) -> Result<&str> {
    let s = value.as_str().context("invalid document text")?;
    ensure!(valid_text(s, false), "invalid document text");
    Ok(s)
}
fn number(value: &Value, minimum: f64, maximum: f64) -> Result<f64> {
    let n = value.as_f64().context("invalid numeric content value")?;
    ensure!(
        n.is_finite() && n >= minimum && n <= maximum,
        "numeric content value is outside supported limits"
    );
    Ok(n)
}
fn boolean(value: Option<&Value>, fallback: bool) -> Result<bool> {
    match value {
        Some(v) => v
            .as_bool()
            .context("direction and style flags must be JSON booleans"),
        None => Ok(fallback),
    }
}
fn language(value: &str) -> Result<&str> {
    ensure!(
        regex::Regex::new(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$")?.is_match(value),
        "invalid language tag"
    );
    Ok(value)
}
fn selected_language<'a>(value: Option<&'a Value>, fallback: &'a str) -> Result<&'a str> {
    language(match value {
        Some(v) => v.as_str().context("invalid language tag")?,
        None => fallback,
    })
}
fn on_off(name: &str, enabled: bool) -> String {
    format!("<w:{name} w:val=\"{}\"/>", u8::from(enabled))
}

// Only inert OOXML defaults are retained from the MIT-licensed reference
// template. Creation, XML validation and archive I/O are entirely native Rust.
// Keeping the actual styles/numbering/theme also keeps style inheritance and
// built-in lists useful, without inventing partial replacements for them.
fn default_parts() -> Result<Vec<(String, Vec<u8>)>> {
    let mut archive = ZipArchive::new(Cursor::new(include_bytes!("../assets/docx-defaults.zip")))?;
    let mut parts = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        xml(&data)?;
        parts.push((entry.name()?.into_owned(), data));
    }
    Ok(parts)
}

fn paragraph_style_id(style: &str) -> Result<&'static str> {
    static STYLES: LazyLock<BTreeMap<String, String>> = LazyLock::new(|| {
        let parts = default_parts().expect("embedded OOXML defaults must validate");
        let data = &parts
            .iter()
            .find(|p| p.0 == "word/styles.xml")
            .expect("embedded styles part")
            .1;
        let document = xml(data).expect("embedded styles XML");
        let mut styles = BTreeMap::new();
        for node in document
            .descendants()
            .filter(|n| is(*n, W, "style") && n.attribute((W, "type")) == Some("paragraph"))
        {
            let identifier = node
                .attribute((W, "styleId"))
                .expect("embedded paragraph style identifier");
            let name = child(node, "name")
                .and_then(|n| n.attribute((W, "val")))
                .expect("embedded paragraph style name");
            styles.insert(name.to_ascii_lowercase(), identifier.to_owned());
            styles.insert(identifier.to_ascii_lowercase(), identifier.to_owned());
        }
        styles
    });
    STYLES
        .get(&style.to_ascii_lowercase())
        .map(String::as_str)
        .context("unknown or non-paragraph document style")
}

/// Generate one paragraph with explicit complex-script direction and matching
/// simple/complex flags; omitted formatting continues to inherit from its style.
pub fn paragraph_xml(
    spec: &Value,
    inherited_language: &str,
    inherited_rtl: bool,
) -> Result<String> {
    let owned;
    let spec = if spec.is_string() {
        owned = json!({"text":spec});
        &owned
    } else {
        spec
    };
    let map = object(
        spec,
        &[],
        &["type", "text", "runs", "style", "language", "rtl"],
    )?;
    ensure!(
        map.contains_key("text") != map.contains_key("runs"),
        "paragraph needs exactly text or runs"
    );
    let lang = selected_language(map.get("language"), inherited_language)?;
    let rtl = boolean(map.get("rtl"), inherited_rtl)?;
    let mut out = String::from("<w:p><w:pPr>");
    if let Some(style) = map.get("style") {
        let style = text(style)?;
        let style_id = paragraph_style_id(style)?;
        out.push_str(&format!("<w:pStyle w:val=\"{}\"/>", attr(style_id)));
    }
    out.push_str(&on_off("bidi", rtl));
    out.push_str("</w:pPr>");
    let default_runs;
    let runs = if let Some(runs) = map.get("runs") {
        runs.as_array().context("runs must be an array")?
    } else {
        default_runs = vec![json!({"text":map["text"]})];
        &default_runs
    };
    ensure!(
        runs.len() <= 10000,
        "runs must contain at most 10000 entries"
    );
    for item in runs {
        let item = object(
            item,
            &["text"],
            &["bold", "italic", "font", "size_pt", "language", "rtl"],
        )?;
        let value = text(&item["text"])?;
        let run_rtl = boolean(item.get("rtl"), rtl)?;
        out.push_str("<w:r><w:rPr>");
        out.push_str(&on_off("rtl", run_rtl));
        for (key, simple, complex) in [("bold", "b", "bCs"), ("italic", "i", "iCs")] {
            if let Some(value) = item.get(key) {
                let enabled = boolean(Some(value), false)?;
                out.push_str(&on_off(simple, enabled));
                out.push_str(&on_off(complex, enabled));
            }
        }
        if let Some(font) = item.get("font") {
            let font = attr(text(font)?);
            out.push_str(&format!(
                "<w:rFonts w:ascii=\"{font}\" w:hAnsi=\"{font}\" w:cs=\"{font}\"/>"
            ));
        }
        if let Some(size) = item.get("size_pt") {
            let size = (number(size, 1., 200.)? * 2.).floor() as u32;
            out.push_str(&format!(
                "<w:sz w:val=\"{size}\"/><w:szCs w:val=\"{size}\"/>"
            ));
        }
        let lang = attr(selected_language(item.get("language"), lang)?);
        out.push_str(&format!(
            "<w:lang w:val=\"{lang}\" w:bidi=\"{lang}\"/></w:rPr>"
        ));
        // OOXML represents tabs and line breaks with dedicated run children.
        let mut buffer = String::new();
        for ch in value.chars() {
            if matches!(ch, '\t' | '\n') {
                if !buffer.is_empty() {
                    out.push_str(&format!(
                        "<w:t xml:space=\"preserve\">{}</w:t>",
                        xml_escape(&buffer)
                    ));
                    buffer.clear();
                }
                out.push_str(if ch == '\t' { "<w:tab/>" } else { "<w:br/>" });
            } else {
                buffer.push(ch);
            }
        }
        if !buffer.is_empty() || value.is_empty() {
            out.push_str(&format!(
                "<w:t xml:space=\"preserve\">{}</w:t>",
                xml_escape(&buffer)
            ));
        }
        out.push_str("</w:r>");
    }
    out.push_str("</w:p>");
    Ok(out)
}

fn image_asset(root: &Path, value: &Value) -> Result<(PathBuf, Vec<u8>, u32, u32, &'static str)> {
    let value = value
        .as_str()
        .filter(|s| !s.is_empty())
        .context("image must name a relative approved file")?;
    let relative = Path::new(value);
    ensure!(
        !relative.is_absolute()
            && !value.contains('\\')
            && !value.contains(':')
            && relative
                .components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir)),
        "image must name an approved file relative to the content JSON"
    );
    let path = root.join(relative);
    for part in path.ancestors() {
        ensure!(
            !identity::is_link(part)?,
            "image path must not contain links or junctions"
        );
    }
    ensure!(
        path.canonicalize()?.starts_with(root.canonicalize()?) && fs::metadata(&path)?.is_file(),
        "image is missing or escapes the content directory"
    );
    ensure!(
        fs::metadata(&path)?.len() <= MAX_MEMBER,
        "image exceeds 64 MiB limit"
    );
    let mut data = Vec::new();
    File::open(&path)?
        .take(MAX_MEMBER + 1)
        .read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= MAX_MEMBER,
        "image exceeds 64 MiB limit"
    );
    let format = image::guess_format(&data)?;
    ensure!(
        matches!(format, image::ImageFormat::Png | image::ImageFormat::Jpeg),
        "create supports single-frame PNG/JPEG"
    );
    if format == image::ImageFormat::Png {
        // acTL introduces APNG animation, even when the first frame is static.
        let mut offset = 8usize;
        while offset + 12 <= data.len() {
            let length = u32::from_be_bytes(data[offset..offset + 4].try_into()?) as usize;
            ensure!(
                &data[offset + 4..offset + 8] != b"acTL",
                "create supports single-frame PNG/JPEG"
            );
            offset = offset
                .checked_add(length + 12)
                .context("invalid PNG chunk length")?;
        }
    }
    if let Ok(exif) = exif::Reader::new().read_from_container(&mut Cursor::new(&data))
        && let Some(orientation) = exif.get_field(exif::Tag::Orientation, exif::In::PRIMARY)
    {
        ensure!(
            orientation.value.get_uint(0).unwrap_or(1) == 1,
            "normalize a copy of image orientation before embedding"
        );
    }
    let mut reader = image::ImageReader::with_format(Cursor::new(&data), format);
    let (width, height) = reader.into_dimensions()?;
    ensure!(
        (width as u64) * (height as u64) <= 50_000_000,
        "create supports images up to 50 million pixels"
    );
    reader = image::ImageReader::with_format(Cursor::new(&data), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(width);
    limits.max_image_height = Some(height);
    limits.max_alloc = Some(256 * 1024 * 1024);
    reader.limits(limits);
    reader.decode().context("invalid image data")?;
    Ok((
        path,
        data,
        width,
        height,
        if format == image::ImageFormat::Png {
            "png"
        } else {
            "jpeg"
        },
    ))
}
fn xml_part(root: &str, body: &str) -> Vec<u8> {
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><w:{root} xmlns:w=\"{W}\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">{body}</w:{root}>").into_bytes()
}
fn twips(mm: f64) -> u64 {
    (mm / 25.4 * 1440.).round() as u64
}
fn zip_members(path: &Path, members: &[(String, Vec<u8>)]) -> Result<()> {
    let mut writer = ZipWriter::new(File::create(path)?);
    for (name, data) in members {
        writer.start_file(
            name,
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )?;
        writer.write_all(data)?;
    }
    writer.finish()?.sync_all()?;
    Ok(())
}

pub fn create_document(content_path: &Path, destination: &Path) -> Result<()> {
    let content = load_json(content_path)?;
    let content = object(&content, &["sections"], &["language", "rtl"])?;
    let sections = content["sections"]
        .as_array()
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .context("sections must contain 1 to 128 entries")?;
    let lang = selected_language(content.get("language"), "fa-IR")?;
    let rtl = boolean(content.get("rtl"), true)?;
    let mut protected = vec![content_path.to_path_buf()];
    let destination = publication::validate_destination(destination, &protected)?;
    let root = content_path
        .canonicalize()?
        .parent()
        .context("content has no parent")?
        .to_path_buf();
    let mut body = String::new();
    let mut members = default_parts()?;
    let mut overrides = String::new();
    let mut relations = String::new();
    for (part, _) in &members {
        let (kind, content_type) = match part.as_str() {
            "word/styles.xml" => (
                "styles",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
            ),
            "word/numbering.xml" => (
                "numbering",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml",
            ),
            "word/settings.xml" => (
                "settings",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml",
            ),
            "word/webSettings.xml" => (
                "webSettings",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml",
            ),
            "word/fontTable.xml" => (
                "fontTable",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml",
            ),
            "word/theme/theme1.xml" => (
                "theme",
                "application/vnd.openxmlformats-officedocument.theme+xml",
            ),
            _ => bail!("unsupported embedded OOXML default part"),
        };
        overrides.push_str(&format!(
            "<Override PartName=\"/{part}\" ContentType=\"{content_type}\"/>"
        ));
        relations.push_str(&format!("<Relationship Id=\"rIdDefault{kind}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/{kind}\" Target=\"{}\"/>",&part[5..]));
    }
    let mut image_count = 0;
    for (index, spec) in sections.iter().enumerate() {
        let spec = object(
            spec,
            &["width_mm", "height_mm", "margins_mm", "blocks"],
            &["header", "footer"],
        )?;
        let width = number(&spec["width_mm"], 25., 2000.)?;
        let height = number(&spec["height_mm"], 25., 2000.)?;
        let margins = object(
            &spec["margins_mm"],
            &["top", "bottom", "left", "right"],
            &[],
        )?;
        let top = number(&margins["top"], 0., 1000.)?;
        let bottom = number(&margins["bottom"], 0., 1000.)?;
        let left = number(&margins["left"], 0., 1000.)?;
        let right = number(&margins["right"], 0., 1000.)?;
        ensure!(
            left + right < width && top + bottom < height,
            "section margins leave no usable page area"
        );
        let mut section = String::from("<w:sectPr>");
        for (kind, tag) in [("header", "hdr"), ("footer", "ftr")] {
            let part = format!("word/{kind}{}.xml", index + 1);
            let id = format!("rId{kind}{}", index + 1);
            let story = if let Some(value) = spec.get(kind) {
                paragraph_xml(value, lang, rtl)?
            } else {
                "<w:p/>".to_owned()
            };
            members.push((part.clone(), xml_part(tag, &story)));
            overrides.push_str(&format!("<Override PartName=\"/{part}\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.{kind}+xml\"/>"));
            relations.push_str(&format!("<Relationship Id=\"{id}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/{kind}\" Target=\"{kind}{}.xml\"/>",index+1));
            section.push_str(&format!(
                "<w:{kind}Reference w:type=\"default\" r:id=\"{id}\"/>"
            ));
        }
        if index > 0 {
            section.push_str("<w:type w:val=\"nextPage\"/>");
        }
        section.push_str(&format!("<w:pgSz w:w=\"{}\" w:h=\"{}\" w:orient=\"{}\"/><w:pgMar w:top=\"{}\" w:bottom=\"{}\" w:left=\"{}\" w:right=\"{}\" w:header=\"720\" w:footer=\"720\" w:gutter=\"0\"/><w:cols w:space=\"720\"/></w:sectPr>",twips(width),twips(height),if width>height{"landscape"}else{"portrait"},twips(top),twips(bottom),twips(left),twips(right)));
        let blocks = spec["blocks"]
            .as_array()
            .filter(|a| a.len() <= 10000)
            .context("blocks must be an array of at most 10000 entries")?;
        for block in blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("paragraph") => body.push_str(&paragraph_xml(block, lang, rtl)?),
                Some("table") => {
                    let table = object(block, &["type", "rows"], &["language", "rtl"])?;
                    let rows = table["rows"]
                        .as_array()
                        .filter(|a| !a.is_empty() && a.len() <= 1000)
                        .context("table must have 1..1000 rectangular rows")?;
                    let columns = rows[0]
                        .as_array()
                        .filter(|a| !a.is_empty() && a.len() <= 100)
                        .context("table must have 1..100 columns")?
                        .len();
                    let rtl = boolean(table.get("rtl"), rtl)?;
                    let lang = selected_language(table.get("language"), lang)?;
                    body.push_str(&format!("<w:tbl><w:tblPr>{}<w:tblW w:w=\"0\" w:type=\"auto\"/></w:tblPr><w:tblGrid>",on_off("bidiVisual",rtl)));
                    let cell_width = twips(width - left - right) / columns as u64;
                    for _ in 0..columns {
                        body.push_str(&format!("<w:gridCol w:w=\"{cell_width}\"/>"));
                    }
                    body.push_str("</w:tblGrid>");
                    for row in rows {
                        let row = row
                            .as_array()
                            .filter(|a| a.len() == columns)
                            .context("table rows must be rectangular")?;
                        body.push_str("<w:tr>");
                        for value in row {
                            body.push_str(&format!("<w:tc><w:tcPr><w:tcW w:w=\"{cell_width}\" w:type=\"dxa\"/></w:tcPr>"));
                            body.push_str(&paragraph_xml(value, lang, rtl)?);
                            body.push_str("</w:tc>");
                        }
                        body.push_str("</w:tr>");
                    }
                    body.push_str("</w:tbl>");
                }
                Some("image") => {
                    let block = object(block, &["type", "path", "width_mm"], &[])?;
                    let (path, data, pixels_w, pixels_h, extension) =
                        image_asset(&root, &block["path"])?;
                    protected.push(path);
                    let image_width = number(&block["width_mm"], 1., width - left - right)?;
                    let cx = (image_width * 36000.).round() as u64;
                    let cy = (cx as f64 * pixels_h as f64 / pixels_w as f64).round() as u64;
                    image_count += 1;
                    let part = format!("word/media/image{image_count}.{extension}");
                    members.push((part.clone(), data));
                    relations.push_str(&format!("<Relationship Id=\"rIdImage{image_count}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"media/image{image_count}.{extension}\"/>"));
                    body.push_str(&format!("<w:p><w:r><w:drawing><wp:inline xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\" distT=\"0\" distB=\"0\" distL=\"0\" distR=\"0\"><wp:extent cx=\"{cx}\" cy=\"{cy}\"/><wp:docPr id=\"{image_count}\" name=\"Picture {image_count}\"/><wp:cNvGraphicFramePr/><a:graphic xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\"><a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/picture\"><pic:pic xmlns:pic=\"http://schemas.openxmlformats.org/drawingml/2006/picture\"><pic:nvPicPr><pic:cNvPr id=\"{image_count}\" name=\"image{image_count}.{extension}\"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed=\"rIdImage{image_count}\"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"{cx}\" cy=\"{cy}\"/></a:xfrm><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>"));
                }
                _ => bail!("unsupported block type; use paragraph, table or image"),
            }
        }
        if index + 1 == sections.len() {
            body.push_str(&section);
        } else {
            body.push_str("<w:p><w:pPr>");
            body.push_str(&section);
            body.push_str("</w:pPr></w:p>");
        }
    }
    let types = format!(
        "<Types xmlns=\"{C}\"><Default Extension=\"xml\" ContentType=\"application/xml\"/><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"png\" ContentType=\"image/png\"/><Default Extension=\"jpeg\" ContentType=\"image/jpeg\"/><Override PartName=\"/word/document.xml\" ContentType=\"{MAIN_TYPE}\"/>{overrides}</Types>"
    );
    members.push(("[Content_Types].xml".into(), types.into_bytes()));
    members.push(("_rels/.rels".into(),format!("<Relationships xmlns=\"{R}\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>").into_bytes()));
    members.push((
        "word/_rels/document.xml.rels".into(),
        format!("<Relationships xmlns=\"{R}\">{relations}</Relationships>").into_bytes(),
    ));
    members.push((
        "word/document.xml".into(),
        xml_part("document", &format!("<w:body>{body}</w:body>")),
    ));
    publication::validate_destination(&destination, &protected)?;
    let directory = tempfile::Builder::new()
        .prefix(".revayat-docx-")
        .tempdir_in(destination.parent().context("output has no parent")?)?;
    let staged = directory.path().join("created.docx");
    zip_members(&staged, &members)?;
    read_package(&staged)?;
    publication::publish_files(
        &[(staged, destination)],
        &protected,
        Some(128 * 1024 * 1024),
    )
}
