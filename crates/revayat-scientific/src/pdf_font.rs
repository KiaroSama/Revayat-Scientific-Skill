//! Native Unicode appearance shaping with a licensed static embedded Vazirmatn.
use anyhow::{Context, Result, ensure};
use lopdf::{Document, Object, ObjectId, Stream, content::Operation, dictionary};
use read_fonts::TableProvider;
use std::collections::BTreeMap;
use unicode_bidi::BidiInfo;
pub const REGULAR: &[u8] = include_bytes!("../assets/fonts/Vazirmatn-Regular.ttf");
pub const BOLD: &[u8] = include_bytes!("../assets/fonts/Vazirmatn-Bold.ttf");
pub const LICENSE: &[u8] = include_bytes!("../assets/fonts/OFL.txt");
fn utf16_hex(text: &str) -> String {
    text.encode_utf16().map(|n| format!("{n:04X}")).collect()
}
fn pdf_unicode(text: &str) -> Object {
    let mut bytes = vec![0xfe, 0xff];
    for n in text.encode_utf16() {
        bytes.extend(n.to_be_bytes());
    }
    Object::String(bytes, lopdf::StringFormat::Hexadecimal)
}
struct Glyph {
    gid: u16,
    x: f64,
    y: f64,
}
struct Line {
    glyphs: Vec<Glyph>,
    width: f64,
    rtl: bool,
}
fn shape(text: &str, size: f64) -> Result<(Vec<Line>, BTreeMap<u16, String>)> {
    let face = harfrust::Font::new(REGULAR, 0).context("bundled shaping font invalid")?;
    let scale = size / f64::from(face.units_per_em());
    let mut lines = Vec::new();
    let mut mapping = BTreeMap::new();
    for line in text.split('\n') {
        let bidi = BidiInfo::new(line, None);
        let mut glyphs = Vec::new();
        let mut x = 0.;
        let mut rtl = false;
        for para in &bidi.paragraphs {
            rtl = para.level.is_rtl();
            let (levels, runs) = bidi.visual_runs(para, para.range.clone());
            for run in runs {
                let input = &line[run.clone()];
                let mut buffer = harfrust::Buffer::new();
                buffer.push_str(input);
                buffer.guess_segment_properties();
                buffer.set_direction(if levels[run.start].is_rtl() {
                    harfrust::Direction::RightToLeft
                } else {
                    harfrust::Direction::LeftToRight
                });
                harfrust::shape(
                    &harfrust::ShaperFont::new(&face),
                    &mut buffer,
                    Default::default(),
                )?;
                let shaped = buffer;
                let mut clusters: Vec<usize> = shaped
                    .glyph_infos()
                    .iter()
                    .map(|g| g.cluster as usize)
                    .collect();
                clusters.push(input.len());
                clusters.sort_unstable();
                clusters.dedup();
                for (info, pos) in shaped.glyph_infos().iter().zip(shaped.glyph_positions()) {
                    let gid = u16::try_from(info.glyph_id)?;
                    ensure!(
                        gid != 0,
                        "form value contains a glyph absent from bundled Vazirmatn"
                    );
                    let start = info.cluster as usize;
                    let end = *clusters
                        .iter()
                        .find(|&&c| c > start)
                        .unwrap_or(&input.len());
                    let chars = input
                        .get(start..end)
                        .context("invalid shaping cluster boundary")?;
                    mapping.entry(gid).or_insert_with(|| chars.to_owned());
                    glyphs.push(Glyph {
                        gid,
                        x: x + f64::from(pos.x_offset) * scale,
                        y: f64::from(pos.y_offset) * scale,
                    });
                    x += f64::from(pos.x_advance) * scale;
                }
            }
        }
        lines.push(Line {
            glyphs,
            width: x,
            rtl,
        });
    }
    Ok((lines, mapping))
}
fn embed(doc: &mut Document, mapping: &BTreeMap<u16, String>) -> Result<ObjectId> {
    let face = read_fonts::FontRef::new(REGULAR)?;
    let head = face.head()?;
    let hhea = face.hhea()?;
    let os2 = face.os2()?;
    let hmtx = face.hmtx()?;
    let scale = 1000. / f64::from(head.units_per_em());
    let number = |v: i16| Object::Real((f64::from(v) * scale) as f32);
    let file = doc.add_object(Stream::new(
        dictionary! {"Length1"=>REGULAR.len()as i64},
        REGULAR.to_vec(),
    ));
    let descriptor=doc.add_object(dictionary!{"Type"=>"FontDescriptor","FontName"=>"Vazirmatn","Flags"=>32,"FontBBox"=>vec![number(head.x_min()),number(head.y_min()),number(head.x_max()),number(head.y_max())],"ItalicAngle"=>0,"Ascent"=>number(hhea.ascender().to_i16()),"Descent"=>number(hhea.descender().to_i16()),"CapHeight"=>number(os2.s_cap_height().unwrap_or(hhea.ascender().to_i16())),"StemV"=>80,"FontFile2"=>file});
    let mut widths = Vec::new();
    for &gid in mapping.keys() {
        widths.push(Object::Integer(i64::from(gid)));
        widths.push(Object::Array(vec![Object::Real(
            (f64::from(
                hmtx.advance(read_fonts::types::GlyphId::new(u32::from(gid)))
                    .unwrap_or(0),
            ) * scale) as f32,
        )]));
    }
    let cid=doc.add_object(dictionary!{"Type"=>"Font","Subtype"=>"CIDFontType2","BaseFont"=>"Vazirmatn","CIDSystemInfo"=>dictionary!{"Registry"=>Object::string_literal("Adobe"),"Ordering"=>Object::string_literal("Identity"),"Supplement"=>0},"FontDescriptor"=>descriptor,"DW"=>1000,"W"=>widths,"CIDToGIDMap"=>"Identity"});
    let mut cmap = String::from(
        "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /Vazirmatn-UCS def\n/CMapType 2 def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
    );
    let entries: Vec<_> = mapping.iter().collect();
    for chunk in entries.chunks(100) {
        cmap.push_str(&format!("{} beginbfchar\n", chunk.len()));
        for (gid, text) in chunk {
            cmap.push_str(&format!("<{gid:04X}> <{}>\n", utf16_hex(text)));
        }
        cmap.push_str("endbfchar\n");
    }
    cmap.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
    let unicode = doc.add_object(Stream::new(dictionary! {}, cmap.into_bytes()));
    Ok(doc.add_object(dictionary!{"Type"=>"Font","Subtype"=>"Type0","BaseFont"=>"Vazirmatn","Encoding"=>"Identity-H","DescendantFonts"=>vec![cid.into()],"ToUnicode"=>unicode}))
}
/// Return a Type0 font and positioned glyph operations. ActualText retains the
/// exact logical field value independently of visual Arabic shaping and bidi.
pub fn appearance(
    doc: &mut Document,
    text: &str,
    width: f64,
    height: f64,
) -> Result<(ObjectId, Vec<Operation>)> {
    let line_count = text.split('\n').count();
    let size = (height / (line_count as f64 * 1.25)).clamp(4., 12.);
    let (lines, mapping) = shape(text, size)?;
    let font = embed(doc, &mapping)?;
    let mut operations = vec![
        Operation::new("q", vec![]),
        Operation::new(
            "re",
            vec![
                0.into(),
                0.into(),
                (width as f32).into(),
                (height as f32).into(),
            ],
        ),
        Operation::new("W", vec![]),
        Operation::new("n", vec![]),
        Operation::new(
            "BDC",
            vec![
                Object::Name(b"Span".to_vec()),
                Object::Dictionary(dictionary! {"ActualText"=>pdf_unicode(text)}),
            ],
        ),
        Operation::new("BT", vec![]),
        Operation::new(
            "Tf",
            vec![Object::Name(b"RvForm".to_vec()), (size as f32).into()],
        ),
        Operation::new("g", vec![0.into()]),
    ];
    for (index, line) in lines.into_iter().enumerate() {
        let start = if line.rtl {
            (width - line.width - 2.).max(2.)
        } else {
            2.
        };
        let baseline = if line_count == 1 {
            (height - size) * 0.5 + 2.
        } else {
            height - size - 2. - index as f64 * size * 1.25
        };
        for glyph in line.glyphs {
            operations.push(Operation::new(
                "Tm",
                vec![
                    1.into(),
                    0.into(),
                    0.into(),
                    1.into(),
                    ((start + glyph.x) as f32).into(),
                    ((baseline + glyph.y) as f32).into(),
                ],
            ));
            operations.push(Operation::new(
                "Tj",
                vec![Object::String(
                    glyph.gid.to_be_bytes().to_vec(),
                    lopdf::StringFormat::Hexadecimal,
                )],
            ));
        }
    }
    operations.extend([
        Operation::new("ET", vec![]),
        Operation::new("EMC", vec![]),
        Operation::new("Q", vec![]),
    ]);
    Ok((font, operations))
}
