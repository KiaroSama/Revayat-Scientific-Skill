//! Indexed RGB/gray PNG export keeps the palette and packed samples, avoiding
//! Poppler's monochrome shortcut for one-bit Indexed color spaces.
use super::*;

pub(super) fn extract(doc: &Document, id: ObjectId) -> Result<Option<Extracted>> {
    let stream = doc.get_object(id)?.as_stream()?;
    let Some(color) = stream.dict.get(b"ColorSpace").ok() else {
        return Ok(None);
    };
    let scope = color_scope(doc, id)?;
    let color = resolved_color(doc, color, scope.as_ref(), 0)?;
    let Object::Array(values) = color else {
        return Ok(None);
    };
    if !values
        .first()
        .is_some_and(|v| matches!(v.as_name(), Ok(b"Indexed" | b"I")))
    {
        return Ok(None);
    }
    ensure!(values.len() == 4, "invalid Indexed image color-space array");
    let base = nav::resolved(doc, &values[1])?;
    let mut profile = None;
    let components = match base.as_name() {
        Ok(b"DeviceRGB" | b"RGB") => 3,
        Ok(b"DeviceGray" | b"G") => 1,
        _ => {
            let Object::Array(base) = base else {
                return Ok(None);
            };
            if !base
                .first()
                .is_some_and(|v| matches!(v.as_name(), Ok(b"ICCBased")))
            {
                return Ok(None);
            }
            let stream = nav::resolved(doc, base.get(1).context("missing Indexed ICC profile")?)?
                .as_stream()?;
            if stream.dict.get(b"N")?.as_i64()? != 3 {
                return Ok(None);
            }
            profile = Some(stream.decompressed_content_with_limit(MAX_RESOURCE_BYTES)?);
            3
        }
    };
    let high = u32::try_from(values[2].as_i64()?)?;
    ensure!(high <= 255, "Indexed palette exceeds 256 entries");
    let bits = u32::try_from(stream.dict.get(b"BitsPerComponent")?.as_i64()?)?;
    ensure!(
        matches!(bits, 1 | 2 | 4 | 8),
        "invalid Indexed sample depth"
    );
    let (width, height) = image_dimensions(stream)?;
    let palette_size = (high as usize + 1) * components;
    let lookup = nav::resolved(doc, &values[3])?;
    let palette = match lookup {
        Object::String(bytes, _) => bytes.clone(),
        Object::Stream(stream) => stream.decompressed_content_with_limit(palette_size)?,
        _ => return Err(anyhow::anyhow!("unsupported Indexed palette lookup")),
    };
    ensure!(
        palette.len() >= palette_size,
        "Indexed lookup table is truncated"
    );
    let entries = (high + 1).min(1 << bits) as usize;
    let mut rgb = Vec::with_capacity(entries * 3);
    for entry in palette[..entries * components].chunks_exact(components) {
        if components == 3 {
            rgb.extend_from_slice(entry);
        } else {
            rgb.extend([entry[0]; 3]);
        }
    }
    let row_bytes = (u64::from(width) * u64::from(bits)).div_ceil(8) as usize;
    let expected = row_bytes
        .checked_mul(height as usize)
        .context("Indexed image size overflow")?;
    let limit = expected
        .checked_add(height as usize)
        .context("Indexed predictor size overflow")?;
    let mut samples = stream.decompressed_content_with_limit(limit)?;
    ensure!(
        samples.len() == expected,
        "Indexed predictor or sample size disagrees with dimensions"
    );
    let sample_max = (1u32 << bits) - 1;
    let decode = if let Ok(value) = stream.dict.get(b"Decode") {
        let array = nav::resolved(doc, value)?.as_array()?;
        ensure!(array.len() == 2, "Indexed Decode needs two limits");
        let number = |v: &Object| -> Result<f64> {
            match nav::resolved(doc, v)? {
                Object::Integer(n) => Ok(*n as f64),
                Object::Real(n) => Ok(f64::from(*n)),
                _ => Err(anyhow::anyhow!("invalid Indexed Decode number")),
            }
        };
        [number(&array[0])?, number(&array[1])?]
    } else {
        [0., f64::from(sample_max)]
    };
    ensure!(
        decode.iter().all(|v| v.is_finite()),
        "nonfinite Indexed Decode limit"
    );
    let mut changed = false;
    for row in samples.chunks_exact_mut(row_bytes) {
        for x in 0..width as usize {
            let bit = x * bits as usize;
            let shift = 8 - bits - (bit % 8) as u32;
            let byte = bit / 8;
            let original = (u32::from(row[byte]) >> shift) & sample_max;
            let mapped = (decode[0]
                + f64::from(original) / f64::from(sample_max) * (decode[1] - decode[0]))
                .round()
                .clamp(0., f64::from(high)) as u32;
            ensure!(
                mapped < entries as u32,
                "Indexed Decode exceeds its representable sample range"
            );
            changed |= mapped != original;
            row[byte] = (u32::from(row[byte]) & !(sample_max << shift) | (mapped << shift)) as u8;
        }
    }
    let mut bytes = Vec::new();
    {
        let mut info = png::Info::with_size(width, height);
        info.icc_profile = profile.map(Into::into);
        let mut encoder = png::Encoder::with_info(&mut bytes, info)?;
        encoder.set_color(png::ColorType::Indexed);
        encoder.set_depth(match bits {
            1 => png::BitDepth::One,
            2 => png::BitDepth::Two,
            4 => png::BitDepth::Four,
            _ => png::BitDepth::Eight,
        });
        encoder.set_palette(rgb);
        encoder.write_header()?.write_image_data(&samples)?;
    }
    Ok(Some(Extracted {
        extension: "png".into(),
        bytes,
        auxiliary: BTreeMap::new(),
        metadata: json!({"engine":"native-rust-indexed","source_bpc":bits,"source_palette_entries":high+1,"exported_palette_entries":entries,"decode_mapping_applied":changed,"color_conversion":"not-performed"}),
    }))
}

/// Convert each palette color in a large constant swatch, then reuse the native
/// packed-sample encoder. Sampling swatch interiors avoids mixing neighboring
/// source pixels during color conversion and leaves independent masks intact.
pub(super) fn render_complex(doc: &Document, id: ObjectId) -> Result<Option<Extracted>> {
    let original = doc.get_object(id)?.as_stream()?;
    let Some(color) = original.dict.get(b"ColorSpace").ok() else {
        return Ok(None);
    };
    let scope = color_scope(doc, id)?;
    let color = resolved_color(doc, color, scope.as_ref(), 0)?;
    let Object::Array(values) = color else {
        return Ok(None);
    };
    if !values
        .first()
        .is_some_and(|v| matches!(v.as_name(), Ok(b"Indexed" | b"I")))
    {
        return Ok(None);
    }
    ensure!(values.len() == 4, "invalid Indexed color space");
    let entries = usize::try_from(values[2].as_i64()?)?
        .checked_add(1)
        .context("Indexed palette overflow")?;
    ensure!(entries <= 256, "Indexed palette exceeds 256 entries");
    let block = 64usize;
    let width = entries * block;
    let height = block;
    let mut samples = Vec::with_capacity(width * height);
    for _ in 0..height {
        for index in 0..entries {
            samples.extend(std::iter::repeat_n(index as u8, block));
        }
    }
    let mut dictionary = original.dict.clone();
    for key in [
        b"Filter".as_slice(),
        b"DecodeParms",
        b"Decode",
        b"Mask",
        b"SMask",
    ] {
        dictionary.remove(key);
    }
    dictionary.set("Width", width as i64);
    dictionary.set("Height", height as i64);
    dictionary.set("BitsPerComponent", 8);
    dictionary.set("Interpolate", false);
    let mut palette_document = doc.clone();
    palette_document
        .objects
        .insert(id, Object::Stream(Stream::new(dictionary, samples)));
    let work = tempfile::Builder::new()
        .prefix(".revayat-pdf-indexed-")
        .tempdir_in(std::env::temp_dir().canonicalize()?)?;
    let input = work.path().join("palette.pdf");
    focused_pdf(&palette_document, id, &input, false)?;
    let before = identity::file_identity(&input, Some(pdf::MAX_PDF_BYTES))?;
    let prefix = work.path().join("color");
    let program = runtime::executable("pdftoppm")
        .context("complex Indexed palette requires Poppler pdftoppm")?;
    codec(
        &program,
        [
            "-f".into(),
            "1".into(),
            "-singlefile".into(),
            "-png".into(),
            "-scale-to-x".into(),
            width.to_string().into(),
            "-scale-to-y".into(),
            height.to_string().into(),
            input.clone().into_os_string(),
            prefix.clone().into_os_string(),
        ],
        work.path(),
    )?;
    let bytes = bounded_read(&prefix.with_extension("png"))?;
    checked_dimensions("png", &bytes, (width as u32, height as u32))?;
    let colors = image::load_from_memory(&bytes)?.to_rgb8();
    let mut rgb = Vec::with_capacity(entries * 3);
    for index in 0..entries {
        rgb.extend(
            colors
                .get_pixel((index * block + block / 2) as u32, (block / 2) as u32)
                .0,
        );
    }
    ensure!(
        before == identity::file_identity(&input, Some(pdf::MAX_PDF_BYTES))?,
        "focused Indexed palette changed during rendering"
    );
    let mut restored = original.clone();
    restored.dict.set(
        "ColorSpace",
        Object::Array(vec![
            Object::Name(b"Indexed".to_vec()),
            Object::Name(b"DeviceRGB".to_vec()),
            ((entries - 1) as i64).into(),
            Object::String(rgb, lopdf::StringFormat::Hexadecimal),
        ]),
    );
    palette_document
        .objects
        .insert(id, Object::Stream(restored));
    let mut image = extract(&palette_document, id)?
        .context("converted Indexed palette could not be encoded")?;
    image.metadata = json!({"engine":"poppler-pdftoppm-indexed-palette","color_conversion":"source palette color space to renderer RGB","mask_composition":false,"packed_sample_positions_preserved":true,"original_stream_and_color_resources_retained":true});
    Ok(Some(image))
}
