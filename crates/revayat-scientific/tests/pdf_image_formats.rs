//! Actual Poppler codec interoperability. No raster fixture is created with a
//! runtime scripting dependency; all PDFs are assembled natively with lopdf.
#[path = "common/pdf.rs"]
mod common;
use common::Fixture;
use lopdf::{Document, Object, ObjectId, Stream, dictionary};
use revayat_scientific::{pdf, pdf_content as content};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, io::Cursor, path::Path};

fn image(color: Object, bits: i64, bytes: Vec<u8>) -> Stream {
    Stream::new(
        dictionary! {"Type"=>"XObject","Subtype"=>"Image","Width"=>8,"Height"=>2,"BitsPerComponent"=>bits,"ColorSpace"=>color},
        bytes,
    )
}
fn wrap(mut doc: Document, ids: &[ObjectId], colors: Option<lopdf::Dictionary>) -> Document {
    let pages = doc.new_object_id();
    let mut xobjects = lopdf::Dictionary::new();
    let mut data = Vec::new();
    for (index, id) in ids.iter().enumerate() {
        xobjects.set(format!("I{index}"), *id);
        data.extend(format!("q 80 0 0 20 0 0 cm /I{index} Do Q\n").bytes());
    }
    let stream = doc.add_object(Stream::new(dictionary! {}, data));
    let mut resources = dictionary! {"XObject"=>xobjects};
    if let Some(colors) = colors {
        resources.set("ColorSpace", colors);
    }
    let page=doc.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"Resources"=>resources,"Contents"=>stream,"MediaBox"=>vec![0.into(),0.into(),100.into(),100.into()]});
    doc.objects.insert(
        pages,
        Object::Dictionary(
            dictionary! {"Type"=>"Pages","Kids"=>vec![Object::Reference(page)],"Count"=>1},
        ),
    );
    let root = doc.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
    doc.trailer.set("Root", root);
    doc
}
fn report(directory: &Path) -> Value {
    serde_json::from_slice(&fs::read(directory.join("images.json")).unwrap()).unwrap()
}
fn record(report: &Value, id: ObjectId) -> &Value {
    report["images"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["xref"] == id.0)
        .unwrap()
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn assert_source_record(f: &Fixture, directory: &Path, id: ObjectId, original: &[u8]) -> Value {
    let inventory = report(directory);
    let record = record(&inventory, id);
    assert_eq!(record["width"], 8);
    assert_eq!(record["height"], 2);
    assert_eq!(
        fs::read(directory.join(record["original_stream"].as_str().unwrap())).unwrap(),
        original
    );
    assert_eq!(record["original_stream_sha256"], hash(original));
    let extracted = fs::read(directory.join(record["file"].as_str().unwrap())).unwrap();
    assert_eq!(record["extracted_sha256"], hash(&extracted));
    assert!(pdf::open_pdf(&f.source, false).is_ok());
    inventory
}

#[test]
fn native_jpeg_stays_byte_identical_and_checks_encoded_dimensions() {
    let f = Fixture::new();
    let mut jpeg = Cursor::new(Vec::new());
    image::RgbImage::from_pixel(8, 2, image::Rgb([12, 34, 56]))
        .write_to(&mut jpeg, image::ImageFormat::Jpeg)
        .unwrap();
    let bytes = jpeg.into_inner();
    let mut document = Document::with_version("1.7");
    let mut stream = image(Object::Name(b"DeviceRGB".to_vec()), 8, bytes.clone());
    stream.dict.set("Filter", "DCTDecode");
    let id = document.add_object(stream);
    f.save(wrap(document, &[id], None));
    let before = fs::read(&f.source).unwrap();
    let directory = f.temp.path().join("images");
    content::extract_images(&f.source, &directory).unwrap();
    let inventory = assert_source_record(&f, &directory, id, &bytes);
    let item = record(&inventory, id);
    assert_eq!(item["extraction"]["engine"], "native-rust");
    assert_eq!(
        fs::read(directory.join(item["file"].as_str().unwrap())).unwrap(),
        bytes
    );
    assert_eq!(fs::read(&f.source).unwrap(), before);
}

#[test]
fn oversized_masks_are_rejected_before_any_codec_or_destination_write() {
    let f = Fixture::new();
    let mut document = Document::with_version("1.7");
    let mut mask = image(Object::Name(b"DeviceGray".to_vec()), 8, vec![255]);
    mask.dict.set("Width", 50_000_001_i64);
    let mask = document.add_object(mask);
    let mut base = image(Object::Name(b"DeviceRGB".to_vec()), 8, vec![0; 48]);
    base.dict.set("SMask", mask);
    let id = document.add_object(base);
    f.save(wrap(document, &[id], None));
    let directory = f.temp.path().join("images");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("images.json"), b"approved inventory").unwrap();
    assert!(content::extract_images(&f.source, &directory).is_err());
    assert_eq!(
        fs::read(directory.join("images.json")).unwrap(),
        b"approved inventory"
    );
    assert_eq!(fs::read_dir(directory).unwrap().count(), 1);
}

#[test]
#[ignore = "requires scientific image codec tier: real Poppler pdfimages"]
fn cmyk_samples_export_as_four_channel_tiff_without_rgb_conversion() {
    let f = Fixture::new();
    let samples = [[0, 255, 255, 0], [255, 0, 255, 0]]
        .into_iter()
        .flat_map(|p| p.repeat(8))
        .collect::<Vec<_>>();
    let mut document = Document::with_version("1.7");
    let mut stream = image(Object::Name(b"DeviceCMYK".to_vec()), 8, samples.clone());
    stream.compress().unwrap();
    let original = stream.content.clone();
    let id = document.add_object(stream);
    f.save(wrap(document, &[id], None));
    let before = fs::read(&f.source).unwrap();
    let directory = f.temp.path().join("images");
    content::extract_images(&f.source, &directory).unwrap();
    let inventory = assert_source_record(&f, &directory, id, &original);
    let record = record(&inventory, id);
    assert_eq!(record["extraction"]["source_color"], "cmyk");
    let path = directory.join(record["file"].as_str().unwrap());
    let mut decoder = tiff::decoder::Decoder::new(fs::File::open(path).unwrap()).unwrap();
    assert_eq!(decoder.dimensions().unwrap(), (8, 2));
    assert_eq!(decoder.colortype().unwrap(), tiff::ColorType::CMYK(8));
    match decoder.read_image().unwrap() {
        tiff::decoder::DecodingResult::U8(found) => assert_eq!(found, samples),
        _ => panic!("CMYK sample depth changed"),
    };
    assert_eq!(fs::read(&f.source).unwrap(), before);
}

#[test]
fn indexed_packed_samples_keep_visible_colors_and_original_lookup_stream() {
    let f = Fixture::new();
    let mut document = Document::with_version("1.7");
    let palette = vec![255, 0, 0, 0, 255, 0];
    let palette_id = document.add_object(Stream::new(dictionary! {}, palette.clone()));
    let color = Object::Array(vec![
        Object::Name(b"Indexed".to_vec()),
        Object::Name(b"DeviceRGB".to_vec()),
        1.into(),
        palette_id.into(),
    ]);
    let raw = vec![0x00, 0xff];
    let id = document.add_object(image(color, 1, raw.clone()));
    f.save(wrap(document, &[id], None));
    let directory = f.temp.path().join("images");
    content::extract_images(&f.source, &directory).unwrap();
    let inventory = assert_source_record(&f, &directory, id, &raw);
    let record = record(&inventory, id);
    let pixels = image::open(directory.join(record["file"].as_str().unwrap()))
        .unwrap()
        .to_rgb8();
    assert_eq!(pixels.get_pixel(0, 0).0, [255, 0, 0]);
    assert!(pixels.rows().next().unwrap().all(|p| p.0 == [255, 0, 0]));
    assert!(pixels.rows().nth(1).unwrap().all(|p| p.0 == [0, 255, 0]));
    let resource = record["retained_resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["xref"] == palette_id.0)
        .unwrap();
    assert_eq!(
        fs::read(directory.join(resource["decoded_file"].as_str().unwrap())).unwrap(),
        palette
    );
}

#[test]
#[ignore = "requires scientific image codec tier: real Poppler pdfimages"]
fn named_color_spaces_and_icc_profile_streams_retain_source_identity() {
    let f = Fixture::new();
    let profile = include_bytes!("../../../tests/fixtures/native-image-srgb.icc").to_vec();
    let mut document = Document::with_version("1.7");
    let mut icc = Stream::new(
        dictionary! {"N"=>3,"Alternate"=>"DeviceRGB"},
        profile.clone(),
    );
    icc.compress().unwrap();
    let encoded = icc.content.clone();
    let profile_id = document.add_object(icc);
    let color = Object::Array(vec![Object::Name(b"ICCBased".to_vec()), profile_id.into()]);
    let colors = dictionary! {"ScientificRGB"=>color};
    let raw = vec![10; 48];
    let id = document.add_object(image(
        Object::Name(b"ScientificRGB".to_vec()),
        8,
        raw.clone(),
    ));
    f.save(wrap(document, &[id], Some(colors)));
    let directory = f.temp.path().join("images");
    content::extract_images(&f.source, &directory).unwrap();
    let inventory = assert_source_record(&f, &directory, id, &raw);
    let item = record(&inventory, id);
    let resource = item["retained_resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["xref"] == profile_id.0)
        .unwrap();
    assert_eq!(
        fs::read(directory.join(resource["original_stream"].as_str().unwrap())).unwrap(),
        encoded
    );
    assert_eq!(
        fs::read(directory.join(resource["decoded_file"].as_str().unwrap())).unwrap(),
        profile
    );
    assert_eq!(resource["decoded_sha256"], hash(&profile));
    let decoded = image::open(directory.join(item["file"].as_str().unwrap())).unwrap();
    assert_eq!((decoded.width(), decoded.height()), (8, 2));
}

#[test]
#[ignore = "requires scientific image codec tier: real Poppler pdfimages"]
fn hard_stencil_and_four_bit_soft_masks_are_exported_as_independent_images() {
    for soft in [false, true] {
        let f = Fixture::new();
        let mut document = Document::with_version("1.7");
        let bytes = if soft {
            vec![0x05, 0xaf, 0x05, 0xaf, 0x05, 0xaf, 0x05, 0xaf]
        } else {
            vec![0x55, 0xaa]
        };
        let mut mask = if soft {
            image(Object::Name(b"DeviceGray".to_vec()), 4, bytes.clone())
        } else {
            Stream::new(
                dictionary! {"Type"=>"XObject","Subtype"=>"Image","Width"=>8,"Height"=>2,"ImageMask"=>true},
                bytes.clone(),
            )
        };
        mask.dict.set("Decode", vec![0.into(), 1.into()]);
        let mask_id = document.add_object(mask);
        let mut base = image(Object::Name(b"DeviceRGB".to_vec()), 8, vec![100; 48]);
        base.dict.set(if soft { "SMask" } else { "Mask" }, mask_id);
        let id = document.add_object(base);
        f.save(wrap(document, &[id], None));
        let directory = f.temp.path().join("images");
        content::extract_images(&f.source, &directory).unwrap();
        let inventory = assert_source_record(&f, &directory, mask_id, &bytes);
        assert_eq!(
            record(&inventory, id)[if soft { "smask" } else { "mask" }],
            mask_id.0
        );
        let pixels =
            image::open(directory.join(record(&inventory, mask_id)["file"].as_str().unwrap()))
                .unwrap()
                .to_luma8();
        assert_eq!(pixels.dimensions(), (8, 2));
        let colors: std::collections::BTreeSet<_> = pixels.pixels().map(|p| p.0[0]).collect();
        assert_eq!(colors.len(), if soft { 4 } else { 2 });
    }
}

#[test]
#[ignore = "requires scientific image codec tier: real Poppler pdfimages with JPEG2000"]
fn jpeg2000_codestream_is_byte_preserved_and_decoded_preview_is_verified() {
    let f = Fixture::new();
    let bytes = include_bytes!("../../../tests/fixtures/native-image.jp2").to_vec();
    let mut document = Document::with_version("1.7");
    let mut stream = image(Object::Name(b"DeviceRGB".to_vec()), 8, bytes.clone());
    stream.dict.set("Filter", "JPXDecode");
    let id = document.add_object(stream);
    f.save(wrap(document, &[id], None));
    let directory = f.temp.path().join("images");
    content::extract_images(&f.source, &directory).unwrap();
    let inventory = assert_source_record(&f, &directory, id, &bytes);
    let record = record(&inventory, id);
    assert_eq!(
        fs::read(directory.join(record["file"].as_str().unwrap())).unwrap(),
        bytes
    );
    let preview = directory.join(format!("image-{}.decoded.png", id.0));
    let pixels = image::open(preview).unwrap().to_rgb8();
    assert!(pixels.rows().next().unwrap().all(|p| p.0 == [255, 0, 0]));
    assert!(pixels.rows().nth(1).unwrap().all(|p| p.0 == [0, 255, 0]));
}

fn segment(number: u32, kind: u8, page: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = number.to_be_bytes().to_vec();
    bytes.extend([kind, 0, page]);
    bytes.extend((payload.len() as u32).to_be_bytes());
    bytes.extend(payload);
    bytes
}
fn white_mmr() -> Vec<u8> {
    let bits = "11000000000001000000000001";
    let mut data = Vec::new();
    for chunk in bits.as_bytes().chunks(8) {
        let mut byte = 0;
        for (i, b) in chunk.iter().enumerate() {
            byte |= u8::from(*b == b'1') << (7 - i);
        }
        data.push(byte);
    }
    data
}
fn white_jbig2() -> Vec<u8> {
    let mut page = Vec::new();
    for n in [8_u32, 2, 0, 0] {
        page.extend(n.to_be_bytes());
    }
    page.extend([0, 0, 0]);
    let mut region = Vec::new();
    for n in [8_u32, 2, 0, 0] {
        region.extend(n.to_be_bytes());
    }
    region.extend([0, 1]);
    region.extend(white_mmr());
    [segment(1, 48, 1, &page), segment(2, 38, 1, &region)].concat()
}

#[test]
#[ignore = "requires scientific image codec tier: real Poppler pdfimages with JBIG2"]
fn jbig2_segments_and_global_dictionary_are_retained_with_viewable_bitmap() {
    let f = Fixture::new();
    let mut document = Document::with_version("1.7");
    let globals = document.add_object(Stream::new(
        dictionary! {},
        segment(0, 0, 0, &[0, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
    ));
    let bytes = white_jbig2();
    let mut stream = image(Object::Name(b"DeviceGray".to_vec()), 1, bytes.clone());
    stream.dict.set("Filter", "JBIG2Decode");
    stream
        .dict
        .set("DecodeParms", dictionary! {"JBIG2Globals"=>globals});
    let id = document.add_object(stream);
    f.save(wrap(document, &[id], None));
    let diagnostic = std::process::Command::new("pdfimages")
        .arg("-png")
        .arg(&f.source)
        .arg(f.temp.path().join("independent-jbig2"))
        .output()
        .unwrap();
    assert!(
        diagnostic.status.success() && diagnostic.stderr.is_empty(),
        "synthetic JBIG2 fixture: {}",
        String::from_utf8_lossy(&diagnostic.stderr)
    );
    let directory = f.temp.path().join("images");
    content::extract_images(&f.source, &directory).unwrap();
    let inventory = assert_source_record(&f, &directory, id, &bytes);
    let record = record(&inventory, id);
    assert!(
        record["retained_resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["xref"] == globals.0)
    );
    let pixels = image::open(directory.join(record["file"].as_str().unwrap()))
        .unwrap()
        .to_luma8();
    assert_eq!(pixels.dimensions(), (8, 2));
    assert!(pixels.pixels().all(|p| p.0 == [255]));
    assert!(
        directory
            .join(format!("image-{}.codec.jb2e", id.0))
            .is_file()
    );
}

#[test]
#[ignore = "requires scientific image codec tier: real Poppler pdfimages with CCITT"]
fn ccitt_group_four_bitstream_and_decode_parameters_are_retained() {
    let f = Fixture::new();
    let mut document = Document::with_version("1.7");
    let bytes = white_mmr();
    let mut stream = image(Object::Name(b"DeviceGray".to_vec()), 1, bytes.clone());
    stream.dict.set("Filter", "CCITTFaxDecode");
    stream.dict.set(
        "DecodeParms",
        dictionary! {"K"=>-1,"Columns"=>8,"Rows"=>2,"BlackIs1"=>false},
    );
    let id = document.add_object(stream);
    f.save(wrap(document, &[id], None));
    let directory = f.temp.path().join("images");
    content::extract_images(&f.source, &directory).unwrap();
    let inventory = assert_source_record(&f, &directory, id, &bytes);
    let record = record(&inventory, id);
    let pixels = image::open(directory.join(record["file"].as_str().unwrap()))
        .unwrap()
        .to_luma8();
    assert_eq!(pixels.dimensions(), (8, 2));
    assert!(pixels.pixels().all(|p| p.0 == [255]));
    assert_eq!(
        fs::read(directory.join(format!("image-{}.codec.ccitt", id.0))).unwrap(),
        bytes
    );
    assert!(
        directory
            .join(format!("image-{}.codec.params", id.0))
            .is_file()
    );
}

#[test]
#[ignore = "requires scientific image codec tier: real Poppler pdfimages"]
fn unknown_filter_fails_closed_and_leaves_entire_existing_delivery_untouched() {
    let f = Fixture::new();
    let mut document = Document::with_version("1.7");
    let good = document.add_object(image(Object::Name(b"DeviceRGB".to_vec()), 8, vec![10; 48]));
    let mut stream = image(Object::Name(b"DeviceRGB".to_vec()), 8, vec![20; 48]);
    stream.dict.set("Filter", "NotARegisteredPDFCodec");
    let bad = document.add_object(stream);
    f.save(wrap(document, &[good, bad], None));
    let before = fs::read(&f.source).unwrap();
    let directory = f.temp.path().join("images");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("images.json"), b"approved inventory").unwrap();
    fs::write(
        directory.join(format!("image-{}.png", good.0)),
        b"approved image",
    )
    .unwrap();
    assert!(content::extract_images(&f.source, &directory).is_err());
    assert_eq!(
        fs::read(directory.join("images.json")).unwrap(),
        b"approved inventory"
    );
    assert_eq!(
        fs::read(directory.join(format!("image-{}.png", good.0))).unwrap(),
        b"approved image"
    );
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);
    assert_eq!(fs::read(&f.source).unwrap(), before);
}

#[test]
fn indexed_rgb_palette_embeds_its_original_icc_profile_in_png() {
    let f = Fixture::new();
    let profile = include_bytes!("../../../tests/fixtures/native-image-srgb.icc").to_vec();
    let mut document = Document::with_version("1.7");
    let icc = document.add_object(Stream::new(dictionary! {"N"=>3}, profile.clone()));
    let base = Object::Array(vec![Object::Name(b"ICCBased".to_vec()), icc.into()]);
    let color = Object::Array(vec![
        Object::Name(b"Indexed".to_vec()),
        base,
        1.into(),
        Object::String(vec![255, 0, 0, 0, 255, 0], lopdf::StringFormat::Hexadecimal),
    ]);
    let id = document.add_object(image(color, 1, vec![0, 255]));
    f.save(wrap(document, &[id], None));
    let directory = f.temp.path().join("images");
    content::extract_images(&f.source, &directory).unwrap();
    let inventory = report(&directory);
    let item = record(&inventory, id);
    assert_eq!(item["extraction"]["engine"], "native-rust-indexed");
    let reader = png::Decoder::new(std::io::BufReader::new(
        fs::File::open(directory.join(item["file"].as_str().unwrap())).unwrap(),
    ))
    .read_info()
    .unwrap();
    assert_eq!(
        reader.info().icc_profile.as_deref(),
        Some(profile.as_slice())
    );
    assert_eq!(reader.info().bit_depth, png::BitDepth::One);
    assert_eq!(reader.info().color_type, png::ColorType::Indexed);
}

#[test]
#[ignore = "requires scientific image codec tier: real Poppler pdftoppm"]
fn indexed_cmyk_palette_gets_color_managed_rgb_copy_without_composing_soft_mask() {
    let f = Fixture::new();
    let mut document = Document::with_version("1.7");
    let mask = document.add_object(image(Object::Name(b"DeviceGray".to_vec()), 8, vec![0; 16]));
    let color = Object::Array(vec![
        Object::Name(b"Indexed".to_vec()),
        Object::Name(b"DeviceCMYK".to_vec()),
        1.into(),
        Object::String(
            vec![0, 255, 255, 0, 255, 0, 255, 0],
            lopdf::StringFormat::Hexadecimal,
        ),
    ]);
    let raw = vec![0, 255];
    let mut stream = image(color, 1, raw.clone());
    stream.dict.set("SMask", mask);
    let id = document.add_object(stream);
    f.save(wrap(document, &[id], None));
    let directory = f.temp.path().join("images");
    content::extract_images(&f.source, &directory).unwrap();
    let inventory = assert_source_record(&f, &directory, id, &raw);
    let item = record(&inventory, id);
    assert_eq!(item["smask"], mask.0);
    assert_eq!(item["extraction"]["mask_composition"], false);
    let pixels = image::open(directory.join(item["file"].as_str().unwrap()))
        .unwrap()
        .to_rgb8();
    let red = pixels.get_pixel(0, 0).0;
    let green = pixels.get_pixel(0, 1).0;
    assert!(
        red[0] > 180 && red[1] < 100 && red[2] < 100,
        "source CMYK red must remain visibly red: {red:?}"
    );
    assert!(
        green[1] > green[0] + 40 && green[1] > green[2] + 30,
        "source CMYK green must remain visibly green: {green:?}"
    );
    assert!(
        inventory["images"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["xref"] == mask.0)
    );
}
