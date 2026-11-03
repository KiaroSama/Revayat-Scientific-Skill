//! Atomic native grid and embedded-image extraction reports.
use crate::pdf_content::{artwork, decoded, parse_page};
use crate::{pdf, publication};
use anyhow::{Result, bail, ensure};
use lopdf::{Object, Stream};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
pub fn extract_tables(source: &Path, destination: &Path) -> Result<()> {
    let doc = pdf::open_pdf(source, false)?;
    let mut pages = Vec::new();
    for (index, id) in pdf::page_ids(&doc)?.into_iter().enumerate() {
        let p = parse_page(&doc, id)?;
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        for (a, b) in &p.lines {
            if (a[0] - b[0]).abs() < 0.01 && (a[1] - b[1]).abs() > 2. {
                xs.push(a[0]);
            }
            if (a[1] - b[1]).abs() < 0.01 && (a[0] - b[0]).abs() > 2. {
                ys.push(a[1]);
            }
        }
        xs.sort_by(f64::total_cmp);
        xs.dedup_by(|a, b| (*a - *b).abs() < 0.1);
        ys.sort_by(|a, b| b.total_cmp(a));
        ys.dedup_by(|a, b| (*a - *b).abs() < 0.1);
        ensure!(
            xs.len() <= 1000 && ys.len() <= 1000,
            "table grid exceeds limits"
        );
        let mut tables = Vec::new();
        if xs.len() >= 2 && ys.len() >= 2 {
            let mut cells = vec![vec![String::new(); xs.len() - 1]; ys.len() - 1];
            for span in p.texts {
                if let (Some(row), Some(col)) = (
                    ys.windows(2).position(|v| span.y <= v[0] && span.y >= v[1]),
                    xs.windows(2).position(|v| span.x >= v[0] && span.x < v[1]),
                ) {
                    cells[row][col].push_str(&span.text);
                }
            }
            tables.push(json!({"index":0,"bbox":[xs[0],*ys.last().unwrap(),*xs.last().unwrap(),ys[0]],"row_count":ys.len()-1,"column_count":xs.len()-1,"cells":cells}));
        }
        pages.push(json!({"page":index+1,"tables":tables}));
    }
    pdf::write_report(
        &json!({"format":"pdf-tables","detection":"heuristic-review-required","pages":pages}),
        destination,
        &[source.to_owned()],
    )
}
fn image_bytes(stream: &Stream) -> Result<(&'static str, Vec<u8>)> {
    let (width, height) = crate::pdf_images_advanced::image_dimensions(stream)?;
    let filters = stream.dict.get(b"Filter").ok();
    if filters.is_some_and(|f| matches!(f,Object::Name(n)if n==b"DCTDecode")) {
        let raw = stream.content.clone();
        let reader =
            image::ImageReader::with_format(std::io::Cursor::new(&raw), image::ImageFormat::Jpeg);
        ensure!(
            reader.into_dimensions()? == (width, height),
            "JPEG dimensions disagree with PDF image dictionary"
        );
        let _ = image::load_from_memory(&raw)?;
        return Ok(("jpeg", raw));
    }
    ensure!(
        !stream.dict.has(b"Decode"),
        "image Decode mapping requires codec extraction"
    );
    ensure!(
        stream.dict.get(b"BitsPerComponent")?.as_i64()? == 8,
        "unsupported extracted image depth; retain reviewed original stream"
    );
    let color = match stream.dict.get(b"ColorSpace")?.as_name()? {
        b"DeviceRGB" => png::ColorType::Rgb,
        b"DeviceGray" => png::ColorType::Grayscale,
        _ => bail!("complex PDF image color space requires reviewed extraction"),
    };
    let raw = decoded(stream)?;
    let expected = usize::try_from(
        u64::from(width) * u64::from(height) * if color == png::ColorType::Rgb { 3 } else { 1 },
    )?;
    ensure!(
        raw.len() == expected,
        "image predictor or sample data not supported losslessly"
    );
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(color);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&raw)?;
    }
    Ok(("png", out))
}
pub fn extract_images(source: &Path, directory: &Path) -> Result<()> {
    let doc = pdf::open_pdf(source, false)?;
    publication::validate_destination(&directory.join("images.json"), &[source.to_owned()])?;
    ensure!(
        !directory.exists() || directory.is_dir(),
        "image destination must be directory"
    );
    let mut placements = Vec::new();
    let mut pending = Vec::new();
    for n in 1..=pdf::page_ids(&doc)?.len() {
        let (_, images) = artwork(&doc, n)?;
        for image in images {
            if !pending.contains(&(image.xref, 0)) {
                pending.push((image.xref, 0));
            }
            placements.push(image);
        }
    }
    let mut outputs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut records = Vec::new();
    let mut cursor = 0;
    while cursor < pending.len() {
        let id = pending[cursor];
        cursor += 1;
        let stream = doc.get_object(id)?.as_stream()?;
        crate::pdf_images_advanced::image_dimensions(stream)?;
        let extracted = match image_bytes(stream) {
            Ok((extension, bytes)) => {
                crate::pdf_images_advanced::Extracted::native(extension, bytes)
            }
            Err(_) => crate::pdf_images_advanced::extract_image(&doc, id)?,
        };
        let ext = extracted.extension;
        let bytes = extracted.bytes;
        let resources = crate::pdf_images_advanced::retained_resources(&doc, id)?;
        outputs.extend(extracted.auxiliary);
        outputs.extend(resources.files);
        let name = format!("image-{}.{}", id.0, ext);
        let original = format!("image-{}.stream", id.0);
        let mask = stream
            .dict
            .get(b"SMask")
            .ok()
            .map(Object::as_reference)
            .transpose()?;
        if let Some(mask) = mask
            && !pending.contains(&mask)
        {
            pending.push(mask);
        }
        let hard_mask = stream
            .dict
            .get(b"Mask")
            .ok()
            .and_then(|v| v.as_reference().ok());
        if let Some(mask) = hard_mask
            && !pending.contains(&mask)
        {
            pending.push(mask);
        }
        records.push(json!({"xref":id.0,"width":stream.dict.get(b"Width")?.as_i64()?,"height":stream.dict.get(b"Height")?.as_i64()?,"smask":mask.map(|i|i.0).unwrap_or(0),"mask":hard_mask.map(|i|i.0).unwrap_or(0),"file":name,"original_stream":original,"original_stream_sha256":format!("{:x}",Sha256::digest(&stream.content)),"extracted_sha256":format!("{:x}",Sha256::digest(&bytes)),"pdf_dictionary":format!("{:?}",stream.dict),"extraction":extracted.metadata,"retained_resources":resources.records}));
        outputs.insert(name, bytes);
        outputs.insert(original, stream.content.clone());
        ensure!(
            outputs.values().map(Vec::len).sum::<usize>() <= 512 * 1024 * 1024,
            "image batch exceeds output limit"
        );
    }
    outputs.insert("images.json".to_owned(),serde_json::to_vec_pretty(&json!({"format":"pdf-images","images":records,"placements":placements,"pages":pdf::geometry(&doc)?}))?);
    for name in outputs.keys() {
        publication::validate_destination(&directory.join(name), &[source.to_owned()])?;
    }
    fs::create_dir_all(directory)?;
    let stage = tempfile::Builder::new()
        .prefix(".revayat-pdf-images-")
        .tempdir_in(directory)?;
    let mut entries = Vec::new();
    for (name, bytes) in outputs {
        let p = stage.path().join(&name);
        fs::write(&p, &bytes)?;
        ensure!(fs::read(&p)? == bytes, "staged image changed bytes");
        entries.push((p, directory.join(name)));
    }
    publication::publish_files(&entries, &[source.to_owned()], Some(pdf::MAX_PDF_BYTES))
}
