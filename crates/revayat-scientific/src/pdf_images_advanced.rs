//! Codec exports for image XObjects outside the small native PNG/JPEG
//! subset. Poppler receives a generated one-image PDF, never the source path.
use crate::{identity, pdf, pdf_navigation as nav, runtime};
use anyhow::{Context, Result, ensure};
use lopdf::{Document, Object, ObjectId, Stream, content::Content, dictionary};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
};

pub const MAX_IMAGE_OUTPUT: u64 = 512 * 1024 * 1024;
const MAX_RESOURCE_BYTES: usize = 128 * 1024 * 1024;

pub struct Extracted {
    pub extension: String,
    pub bytes: Vec<u8>,
    pub auxiliary: BTreeMap<String, Vec<u8>>,
    pub metadata: Value,
}
impl Extracted {
    pub fn native(extension: &str, bytes: Vec<u8>) -> Self {
        Self {
            extension: extension.into(),
            bytes,
            auxiliary: BTreeMap::new(),
            metadata: json!({"engine":"native-rust","color_conversion":"not-performed"}),
        }
    }
}
pub struct RetainedResources {
    pub files: BTreeMap<String, Vec<u8>>,
    pub records: Vec<Value>,
}

pub fn image_dimensions(stream: &Stream) -> Result<(u32, u32)> {
    let width = u32::try_from(stream.dict.get(b"Width")?.as_i64()?)?;
    let height = u32::try_from(stream.dict.get(b"Height")?.as_i64()?)?;
    ensure!(
        width > 0 && height > 0 && u64::from(width) * u64::from(height) <= 50_000_000,
        "image or mask dimensions exceed supported limits"
    );
    Ok((width, height))
}
fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn bounded_read(path: &Path) -> Result<Vec<u8>> {
    crate::images::plain_path(path)?;
    ensure!(
        fs::symlink_metadata(path)?.is_file() && fs::metadata(path)?.len() <= MAX_IMAGE_OUTPUT,
        "unsafe or oversized image codec output"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_IMAGE_OUTPUT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_IMAGE_OUTPUT,
        "image codec output grew beyond its limit"
    );
    Ok(bytes)
}
fn references(value: &Object, output: &mut Vec<ObjectId>, depth: usize) -> Result<()> {
    ensure!(depth <= 64, "image resource nesting exceeds limits");
    match value {
        Object::Reference(id) => output.push(*id),
        Object::Array(values) => {
            for value in values {
                references(value, output, depth + 1)?;
            }
        }
        Object::Dictionary(dict) => {
            for (_, value) in dict.iter() {
                references(value, output, depth + 1)?;
            }
        }
        Object::Stream(stream) => {
            for (_, value) in stream.dict.iter() {
                references(value, output, depth + 1)?;
            }
        }
        _ => (),
    }
    Ok(())
}
fn copy_graph(source: &Document, dest: &mut Document, start: &Object) -> Result<()> {
    let mut pending = Vec::new();
    references(start, &mut pending, 0)?;
    let mut seen = HashSet::new();
    let mut total = 0usize;
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        ensure!(seen.len() <= 16384, "image resource graph exceeds limits");
        let object = source.get_object(id)?;
        if let Object::Stream(stream) = object {
            total = total
                .checked_add(stream.content.len())
                .context("image dependency size overflow")?;
            ensure!(
                total <= pdf::MAX_PDF_BYTES as usize,
                "image dependency graph exceeds limits"
            );
        }
        references(object, &mut pending, 0)?;
        dest.objects.insert(id, object.clone());
        dest.max_id = dest.max_id.max(id.0);
    }
    Ok(())
}
fn builtin_color(name: &[u8]) -> bool {
    matches!(
        name,
        b"DeviceRGB" | b"RGB" | b"DeviceGray" | b"G" | b"DeviceCMYK" | b"CMYK" | b"Pattern"
    )
}
fn named_color(value: &Object) -> bool {
    match value {
        Object::Name(name) => !builtin_color(name),
        Object::Array(values) => match values.first().and_then(|v| v.as_name().ok()) {
            Some(b"Indexed" | b"I" | b"Pattern") => values.get(1).is_some_and(named_color),
            Some(b"Separation" | b"DeviceN") => values.get(2).is_some_and(named_color),
            _ => false,
        },
        _ => false,
    }
}
fn mask_contains(
    doc: &Document,
    root: ObjectId,
    target: ObjectId,
    seen: &mut HashSet<ObjectId>,
) -> Result<bool> {
    ensure!(seen.len() < 64, "cyclic or excessive image mask graph");
    if root == target {
        return Ok(true);
    }
    if !seen.insert(root) {
        return Ok(false);
    }
    let stream = doc.get_object(root)?.as_stream()?;
    for key in [b"SMask".as_slice(), b"Mask".as_slice()] {
        if let Ok(Object::Reference(next)) = stream.dict.get(key)
            && mask_contains(doc, *next, target, seen)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn scope_walk(
    doc: &Document,
    data: &[u8],
    resources: &lopdf::Dictionary,
    target: ObjectId,
    stack: &mut HashSet<ObjectId>,
    scopes: &mut Vec<lopdf::Dictionary>,
) -> Result<()> {
    ensure!(
        stack.len() < 64 && scopes.len() < 256,
        "image resource scope exceeds limits"
    );
    for operation in Content::decode(data)?.operations {
        if operation.operator != "Do" {
            continue;
        }
        let name = operation
            .operands
            .first()
            .context("missing image resource name")?
            .as_name()?;
        let xobjects = nav::resolved(doc, resources.get(b"XObject")?)?.as_dict()?;
        let id = xobjects.get(name)?.as_reference()?;
        let stream = doc.get_object(id)?.as_stream()?;
        match stream.dict.get(b"Subtype")?.as_name()? {
            b"Image" => {
                if mask_contains(doc, id, target, &mut HashSet::new())? {
                    scopes.push(resources.clone());
                }
            }
            b"Form" => {
                ensure!(stack.insert(id), "cyclic Form image resource scope");
                let child = stream
                    .dict
                    .get(b"Resources")
                    .ok()
                    .map(|v| -> Result<_> { Ok(nav::resolved(doc, v)?.as_dict()?) })
                    .transpose()?
                    .unwrap_or(resources);
                scope_walk(
                    doc,
                    &crate::pdf_content::decoded(stream)?,
                    child,
                    target,
                    stack,
                    scopes,
                )?;
                stack.remove(&id);
            }
            _ => (),
        }
    }
    Ok(())
}
fn color_scope(doc: &Document, id: ObjectId) -> Result<Option<lopdf::Dictionary>> {
    let stream = doc.get_object(id)?.as_stream()?;
    let needs_scope = stream
        .dict
        .get(b"ColorSpace")
        .ok()
        .map(|v| nav::resolved(doc, v))
        .transpose()?
        .is_some_and(named_color);
    if !needs_scope {
        return Ok(None);
    }
    let mut scopes = Vec::new();
    for page in pdf::page_ids(doc)? {
        let resources = crate::pdf_forms::inherited(doc, page, b"Resources")?
            .context("page has no resources")?;
        let resources = nav::resolved(doc, resources)?.as_dict()?;
        scope_walk(
            doc,
            &crate::pdf_content::page_stream(doc, page)?,
            resources,
            id,
            &mut HashSet::new(),
            &mut scopes,
        )?;
    }
    let mut colors = None;
    for scope in scopes {
        let candidate = nav::resolved(doc, scope.get(b"ColorSpace")?)?
            .as_dict()?
            .clone();
        if let Some(previous) = &colors {
            ensure!(
                previous == &candidate,
                "image uses ambiguous named color spaces"
            );
        } else {
            colors = Some(candidate);
        }
    }
    Ok(Some(colors.context(
        "named image color space has no source resource scope",
    )?))
}
fn resolved_color(
    doc: &Document,
    value: &Object,
    scope: Option<&lopdf::Dictionary>,
    depth: usize,
) -> Result<Object> {
    ensure!(depth < 32, "cyclic named image color space");
    let value = nav::resolved(doc, value)?;
    if let Object::Name(name) = value
        && !builtin_color(name)
    {
        return resolved_color(
            doc,
            scope
                .context("missing image color-space scope")?
                .get(name)?,
            scope,
            depth + 1,
        );
    }
    let mut result = value.clone();
    if let Object::Array(values) = &mut result {
        let index = match values.first().and_then(|v| v.as_name().ok()) {
            Some(b"Indexed" | b"I" | b"Pattern") => Some(1),
            Some(b"Separation" | b"DeviceN") => Some(2),
            _ => None,
        };
        if let Some(index) = index {
            let item = values.get(index).context("incomplete image color space")?;
            values[index] = resolved_color(doc, item, scope, depth + 1)?;
        }
    }
    Ok(result)
}
fn focused_pdf(doc: &Document, id: ObjectId, path: &Path, preserve_masks: bool) -> Result<()> {
    let mut stream = doc.get_object(id)?.as_stream()?.clone();
    if !preserve_masks {
        stream.dict.remove(b"SMask");
        stream.dict.remove(b"Mask");
    }
    image_dimensions(&stream)?;
    let scope = color_scope(doc, id)?;
    if let Ok(value) = stream.dict.get(b"ColorSpace") {
        stream
            .dict
            .set("ColorSpace", resolved_color(doc, value, scope.as_ref(), 0)?);
    }
    let mut focused = Document::with_version("1.7");
    let mut refs = Object::Stream(stream.clone());
    copy_graph(doc, &mut focused, &refs)?;
    focused.objects.insert(id, Object::Stream(stream));
    focused.max_id = focused.max_id.max(id.0);
    if let Some(colors) = &scope {
        refs = Object::Dictionary(colors.clone());
        copy_graph(doc, &mut focused, &refs)?;
    }
    let pages = focused.new_object_id();
    let content = focused.add_object(Stream::new(
        dictionary! {},
        b"q 100 0 0 100 0 0 cm /Extract Do Q".to_vec(),
    ));
    let mut resources = dictionary! {"XObject"=>dictionary!{"Extract"=>id}};
    if let Some(colors) = scope {
        resources.set("ColorSpace", colors);
    }
    let page=focused.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"Resources"=>resources,"Contents"=>content,"MediaBox"=>vec![0.into(),0.into(),100.into(),100.into()]});
    focused.objects.insert(
        pages,
        Object::Dictionary(
            dictionary! {"Type"=>"Pages","Kids"=>vec![Object::Reference(page)],"Count"=>1},
        ),
    );
    let catalog = focused.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
    focused.trailer.set("Root", catalog);
    focused.save(path)?;
    ensure!(
        fs::metadata(path)?.len() <= pdf::MAX_PDF_BYTES,
        "focused image document exceeds limit"
    );
    Ok(())
}

#[derive(Debug)]
struct ListedImage {
    number: usize,
    id: ObjectId,
    width: u32,
    height: u32,
    color: String,
    bpc: u32,
    encoding: String,
}
fn inventory(bytes: &[u8]) -> Result<Vec<ListedImage>> {
    let text = std::str::from_utf8(bytes).context("invalid image codec inventory")?;
    let mut images = Vec::new();
    for line in text.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.first().is_none_or(|s| s.parse::<u32>().is_err()) {
            continue;
        }
        ensure!(
            parts.len() >= 16 && parts[10] != "[inline]",
            "incomplete or inline image codec inventory"
        );
        let width = parts[3].parse::<u32>()?;
        let height = parts[4].parse::<u32>()?;
        ensure!(
            width > 0 && height > 0 && u64::from(width) * u64::from(height) <= 50_000_000,
            "image codec dimensions exceed limits"
        );
        images.push(ListedImage {
            number: parts[1].parse()?,
            id: (parts[10].parse()?, parts[11].parse()?),
            width,
            height,
            color: parts[5].into(),
            bpc: parts[7].parse()?,
            encoding: parts[8].into(),
        });
        ensure!(images.len() <= 64, "focused image inventory exceeds limits");
    }
    ensure!(
        !images.is_empty(),
        "image codec omitted the requested XObject"
    );
    Ok(images)
}
fn codec(
    program: &Path,
    arguments: impl IntoIterator<Item = impl Into<std::ffi::OsString>>,
    cwd: &Path,
) -> Result<Vec<u8>> {
    let mut command = runtime::CommandSpec::new(program);
    command.args = arguments.into_iter().map(Into::into).collect();
    command.cwd = Some(cwd.to_owned());
    command.timeout = std::time::Duration::from_secs(120);
    command.max_output = 1024 * 1024;
    let result = runtime::run(&command)?;
    ensure!(
        result.success() && result.stderr.iter().all(u8::is_ascii_whitespace),
        "image codec rejected a filter, color space or image stream"
    );
    Ok(result.stdout)
}
fn output_set(directory: &Path, prefix: &str) -> Result<BTreeMap<String, PathBuf>> {
    let mut total = 0u64;
    let mut selected = BTreeMap::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if !path
            .file_name()
            .is_some_and(|s| s.to_string_lossy().starts_with(prefix))
        {
            continue;
        }
        crate::images::plain_path(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file(),
            "codec output is not a regular owned file"
        );
        total = total
            .checked_add(metadata.len())
            .context("codec output size overflow")?;
        ensure!(
            total <= MAX_IMAGE_OUTPUT,
            "image codec output exceeds batch limit"
        );
        let name = path
            .file_name()
            .context("missing codec output name")?
            .to_str()
            .context("non-UTF8 codec output name")?
            .to_owned();
        selected.insert(name, path);
    }
    Ok(selected)
}
fn checked_dimensions(extension: &str, bytes: &[u8], expected: (u32, u32)) -> Result<()> {
    if matches!(extension, "png" | "tif" | "tiff" | "jpg" | "jpeg") {
        let reader = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
        ensure!(
            reader.into_dimensions()? == expected,
            "codec changed image dimensions"
        );
    }
    Ok(())
}

/// Keep the native JPEG/RGB/gray path. Call only when that path cannot represent
/// an admitted XObject; a decoder failure never publishes a partial batch.
pub fn extract_image(doc: &Document, id: ObjectId) -> Result<Extracted> {
    if let Some(image) = indexed::extract(doc, id)? {
        return Ok(image);
    }
    if let Some(image) = indexed::render_complex(doc, id)? {
        return Ok(image);
    }
    let expected = image_dimensions(doc.get_object(id)?.as_stream()?)?;
    let work = tempfile::Builder::new()
        .prefix(".revayat-pdf-image-codec-")
        .tempdir_in(std::env::temp_dir().canonicalize()?)?;
    let input = work.path().join("image.pdf");
    focused_pdf(doc, id, &input, true)?;
    let before = identity::file_identity(&input, Some(pdf::MAX_PDF_BYTES))?;
    let program = runtime::executable("pdfimages")
        .context("advanced PDF image extraction requires Poppler pdfimages")?;
    let listed = inventory(&codec(
        &program,
        [std::ffi::OsStr::new("-list"), input.as_os_str()],
        work.path(),
    )?)?;
    let row = listed
        .iter()
        .find(|r| r.id == id)
        .context("codec inventory does not identify requested image")?;
    ensure!(
        (row.width, row.height) == expected,
        "codec inventory disagrees with image dimensions"
    );
    ensure!(
        row.bpc <= 16,
        "image codec sample depth exceeds supported limits"
    );
    let prefix = work.path().join("encoded");
    codec(
        &program,
        [
            std::ffi::OsStr::new("-all"),
            input.as_os_str(),
            prefix.as_os_str(),
        ],
        work.path(),
    )?;
    let files = output_set(work.path(), "encoded-")?;
    let stem = format!("encoded-{:03}.", row.number);
    let mut formats = BTreeMap::new();
    for (name, path) in files {
        if let Some(extension) = name.strip_prefix(&stem) {
            ensure!(
                [
                    "png", "tif", "tiff", "jpg", "jpeg", "jp2", "jpx", "jb2e", "jb2g", "ccitt",
                    "params"
                ]
                .contains(&extension),
                "unsupported codec output extension"
            );
            formats.insert(extension.to_owned(), path);
        }
    }
    ensure!(
        !formats.is_empty(),
        "codec did not export the requested image"
    );
    let need_decoded = formats.contains_key("jb2e")
        || formats.contains_key("ccitt")
        || formats.contains_key("jp2")
        || formats.contains_key("jpx");
    let mut auxiliary = BTreeMap::new();
    let mut decoded = None;
    if need_decoded {
        let prefix = work.path().join("decoded");
        codec(
            &program,
            [
                std::ffi::OsStr::new("-png"),
                input.as_os_str(),
                prefix.as_os_str(),
            ],
            work.path(),
        )?;
        let files = output_set(work.path(), "decoded-")?;
        let name = format!("decoded-{:03}.png", row.number);
        let path = files
            .get(&name)
            .context("codec could not produce a viewable decoded image")?;
        let bytes = bounded_read(path)?;
        checked_dimensions("png", &bytes, expected)?;
        if formats.contains_key("jp2") || formats.contains_key("jpx") {
            auxiliary.insert(format!("image-{}.decoded.png", id.0), bytes);
        } else {
            decoded = Some(bytes);
        }
    }
    let (extension, bytes) = if let Some(bytes) = decoded {
        for (ext, path) in &formats {
            auxiliary.insert(format!("image-{}.codec.{ext}", id.0), bounded_read(path)?);
        }
        ("png".to_owned(), bytes)
    } else {
        let extension = ["jpg", "jpeg", "jp2", "jpx", "tif", "tiff", "png"]
            .into_iter()
            .find(|e| formats.contains_key(*e))
            .context("codec omitted a usable image representation")?
            .to_owned();
        let bytes = bounded_read(&formats[&extension])?;
        for (ext, path) in &formats {
            if ext != &extension {
                auxiliary.insert(format!("image-{}.codec.{ext}", id.0), bounded_read(path)?);
            }
        }
        (extension, bytes)
    };
    checked_dimensions(&extension, &bytes, expected)?;
    ensure!(
        bytes.len() as u64 + auxiliary.values().map(|b| b.len() as u64).sum::<u64>()
            <= MAX_IMAGE_OUTPUT,
        "image export exceeds output limit"
    );
    ensure!(
        before == identity::file_identity(&input, Some(pdf::MAX_PDF_BYTES))?,
        "focused image source changed during codec execution"
    );
    let companions: Vec<_> = auxiliary
        .iter()
        .map(|(name, bytes)| json!({"file":name,"bytes":bytes.len(),"sha256":digest(bytes)}))
        .collect();
    Ok(Extracted {
        extension,
        bytes,
        auxiliary,
        metadata: json!({"engine":"poppler-pdfimages","source_scope":"one-image-generated-document","source_color":row.color,"source_bpc":row.bpc,"source_encoding":row.encoding,"dimensions_verified":true,"decoded_preview":need_decoded,"companions":companions,"color_conversion":"codec-dependent; original color resources retained separately"}),
    })
}

#[path = "pdf_images_indexed.rs"]
mod indexed;

/// Preserve ICC profiles, Indexed lookup tables, tint transforms and JBIG2
/// global dictionaries independently of any exported representation's format.
pub fn retained_resources(doc: &Document, id: ObjectId) -> Result<RetainedResources> {
    let stream = doc.get_object(id)?.as_stream()?;
    let scope = color_scope(doc, id)?;
    let mut objects = Vec::new();
    if let Ok(color) = stream.dict.get(b"ColorSpace") {
        objects.push((
            "color-space",
            resolved_color(doc, color, scope.as_ref(), 0)?,
        ));
    }
    if let Ok(parameters) = stream.dict.get(b"DecodeParms") {
        objects.push(("decode-parameters", parameters.clone()));
    }
    let mut files = BTreeMap::new();
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    for (role, object) in objects {
        let mut pending = Vec::new();
        references(&object, &mut pending, 0)?;
        while let Some(resource) = pending.pop() {
            if !seen.insert(resource) {
                continue;
            }
            ensure!(seen.len() <= 16384, "image resource graph exceeds limits");
            let object = doc.get_object(resource)?;
            references(object, &mut pending, 0)?;
            if let Object::Stream(stream) = object {
                if stream
                    .dict
                    .get(b"Subtype")
                    .ok()
                    .and_then(|v| v.as_name().ok())
                    == Some(b"Image")
                {
                    continue;
                }
                ensure!(
                    stream.content.len() <= MAX_RESOURCE_BYTES,
                    "image resource stream exceeds limits"
                );
                let raw_name = format!("image-{}.resource-{}.stream", id.0, resource.0);
                let decoded_name = format!("image-{}.resource-{}.decoded", id.0, resource.0);
                let decoded = crate::pdf_content::decoded(stream)?;
                ensure!(
                    decoded.len() <= MAX_RESOURCE_BYTES,
                    "decoded image resource exceeds limits"
                );
                records.push(json!({"role":role,"xref":resource.0,"generation":resource.1,"original_stream":raw_name,"original_stream_sha256":digest(&stream.content),"decoded_file":decoded_name,"decoded_sha256":digest(&decoded),"pdf_dictionary":format!("{:?}",stream.dict)}));
                files.insert(raw_name, stream.content.clone());
                files.insert(decoded_name, decoded);
            }
        }
    }
    ensure!(
        files.values().map(Vec::len).sum::<usize>() <= MAX_IMAGE_OUTPUT as usize,
        "image resources exceed batch limit"
    );
    Ok(RetainedResources { files, records })
}
