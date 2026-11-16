//! Source-independent PDF text geometry and Unicode bidi reconstruction.
//! Explicit ActualText and multi-character ToUnicode glyph clusters are opaque;
//! they never undergo character reversal. Raw content order remains available.
use crate::pdf_navigation::resolved;
use anyhow::{Context, Result, ensure};
use lopdf::{Dictionary, Document, Object};
use unicode_bidi::{BidiClass, BidiInfo, Level, bidi_class};

#[derive(Clone, Copy)]
pub struct Style {
    pub size: f64,
    pub character_spacing: f64,
    pub word_spacing: f64,
    pub horizontal_scale: f64,
}
#[derive(Clone, Debug)]
pub struct DecodedGlyph {
    pub text: String,
    pub origin: f64,
    pub advance: f64,
}
#[derive(Clone, Debug)]
pub struct Glyph {
    pub text: String,
    pub x: f64,
    pub y: f64,
    pub advance: f64,
    pub size: f64,
    pub axis: [f64; 2],
    pub actual: bool,
}
fn num(o: &Object) -> Result<f64> {
    Ok(match o {
        Object::Integer(n) => *n as f64,
        _ => f64::from(o.as_float()?),
    })
}
fn width(doc: &Document, font: &Dictionary, code: u32, cid: bool) -> Result<f64> {
    if cid {
        let descendants = resolved(doc, font.get(b"DescendantFonts")?)?.as_array()?;
        let descendant = resolved(
            doc,
            descendants.first().context("CID font descendant missing")?,
        )?
        .as_dict()?;
        let default = descendant
            .get(b"DW")
            .ok()
            .map(num)
            .transpose()?
            .unwrap_or(1000.);
        if let Ok(w) = descendant.get(b"W") {
            let w = resolved(doc, w)?.as_array()?;
            ensure!(w.len() <= 200000, "CID font width table exceeds limit");
            let mut i = 0;
            while i < w.len() {
                let start = u32::try_from(w[i].as_i64()?)?;
                let next = w.get(i + 1).context("incomplete CID width array")?;
                match resolved(doc, next)? {
                    Object::Array(values) => {
                        if code >= start && ((code - start) as usize) < values.len() {
                            return num(&values[(code - start) as usize]);
                        }
                        i += 2;
                    }
                    end => {
                        let end = u32::try_from(end.as_i64()?)?;
                        let value = w.get(i + 2).context("incomplete CID width range")?;
                        if (start..=end).contains(&code) {
                            return num(value);
                        }
                        i += 3;
                    }
                }
            }
        }
        Ok(default)
    } else {
        let first = font.get(b"FirstChar").and_then(Object::as_i64).unwrap_or(0);
        if let Ok(w) = font.get(b"Widths") {
            let a = resolved(doc, w)?.as_array()?;
            if let Some(w) = a.get((i64::from(code) - first).max(0) as usize)
                && i64::from(code) >= first
            {
                return num(w);
            }
        }
        if let Ok(descriptor) = font.get(b"FontDescriptor")
            && let Ok(w) = resolved(doc, descriptor)?.as_dict()?.get(b"MissingWidth")
        {
            return num(w);
        }
        // Standard fourteen-font fallback is used only when no width array is
        // present. It affects whitespace inference, never Unicode selection.
        Ok(if code == 32 { 250. } else { 500. })
    }
}
pub const MAX_GLYPHS: usize = 2_000_000;
pub fn decode_glyphs(
    doc: &Document,
    resources: &Dictionary,
    font_name: &[u8],
    objects: &[Object],
    style: Style,
    actual: bool,
) -> Result<(Vec<DecodedGlyph>, f64)> {
    decode_glyphs_with_limit(
        doc, resources, font_name, objects, style, actual, MAX_GLYPHS,
    )
}
pub fn decode_glyphs_with_limit(
    doc: &Document,
    resources: &Dictionary,
    font_name: &[u8],
    objects: &[Object],
    style: Style,
    actual: bool,
    max_glyphs: usize,
) -> Result<(Vec<DecodedGlyph>, f64)> {
    ensure!(
        max_glyphs > 0 && max_glyphs <= MAX_GLYPHS,
        "invalid PDF glyph budget"
    );
    let fonts = resolved(doc, resources.get(b"Font")?)?.as_dict()?;
    let font = resolved(doc, fonts.get(font_name)?)?.as_dict()?;
    let cid = font.get(b"Subtype").and_then(Object::as_name).ok() == Some(b"Type0");
    if let Ok(map) = font.get(b"ToUnicode") {
        let _ = crate::pdf_content::decoded(resolved(doc, map)?.as_stream()?)?;
    }
    let encoding = font.get_font_encoding(doc);
    if !actual {
        ensure!(encoding.is_ok(), "font Unicode encoding unavailable");
    }
    let step = if cid { 2 } else { 1 };
    let mut out = Vec::new();
    let mut cursor = 0.;
    fn collect(
        context: (&Document, &Dictionary, bool, usize, Style, usize),
        objects: &[Object],
        decode: &dyn Fn(&[u8]) -> Result<String>,
        cursor: &mut f64,
        out: &mut Vec<DecodedGlyph>,
        decoded_bytes: &mut usize,
    ) -> Result<()> {
        let (doc, font, cid, step, style, max_glyphs) = context;
        for object in objects {
            match object {
                Object::Array(a) => collect(context, a, decode, cursor, out, decoded_bytes)?,
                Object::String(bytes, _) => {
                    ensure!(bytes.len() % step == 0, "font code width mismatch");
                    for raw in bytes.chunks_exact(step) {
                        let code = raw.iter().fold(0u32, |acc, b| acc * 256 + u32::from(*b));
                        ensure!(out.len() < max_glyphs, "PDF glyph budget exceeded");
                        let text = decode(raw)?;
                        *decoded_bytes += text.len();
                        ensure!(
                            *decoded_bytes <= 64 * 1024 * 1024,
                            "PDF Unicode text budget exceeded"
                        );
                        let advance = (width(doc, font, code, cid)? / 1000. * style.size
                            + style.character_spacing
                            + if raw == [32] { style.word_spacing } else { 0. })
                            * style.horizontal_scale;
                        ensure!(advance.is_finite(), "nonfinite glyph advance");
                        out.push(DecodedGlyph {
                            text,
                            origin: *cursor,
                            advance,
                        });
                        *cursor += advance;
                    }
                }
                Object::Integer(_) | Object::Real(_) => {
                    let shift = -num(object)? / 1000. * style.size * style.horizontal_scale;
                    if shift > style.size * 0.15 {
                        ensure!(out.len() < max_glyphs, "PDF glyph budget exceeded");
                        *decoded_bytes += 1;
                        ensure!(
                            *decoded_bytes <= 64 * 1024 * 1024,
                            "PDF Unicode text budget exceeded"
                        );
                        out.push(DecodedGlyph {
                            text: " ".to_owned(),
                            origin: *cursor,
                            advance: shift,
                        });
                    }
                    *cursor += shift;
                }
                _ => {}
            }
        }
        Ok(())
    }
    collect(
        (doc, font, cid, step, style, max_glyphs),
        objects,
        &|raw| match &encoding {
            Ok(e) => Ok(e.bytes_to_string(raw)?),
            Err(_) => Ok(String::new()),
        },
        &mut cursor,
        &mut out,
        &mut 0usize,
    )?;
    Ok((out, cursor))
}
fn representative(text: &str) -> char {
    let mut chars = text.chars();
    let first = chars.next().unwrap_or(' ');
    if chars.next().is_none() {
        return first;
    }
    for c in text.chars() {
        match bidi_class(c) {
            BidiClass::R | BidiClass::AL => return 'ا',
            BidiClass::L => return 'A',
            _ => {}
        }
    }
    first
}
fn base_level(text: &str, language: Option<&str>) -> Option<Level> {
    let (mut rtl, mut ltr) = (0, 0);
    for c in text.chars() {
        match bidi_class(c) {
            BidiClass::R | BidiClass::AL => rtl += 1,
            BidiClass::L => ltr += 1,
            _ => {}
        }
    }
    // A foreign-language line in a Persian document keeps its own base. Global
    // /Lang is evidence for mixed text, not permission to move a French period.
    if rtl == 0 && ltr > 0 {
        return Some(Level::ltr());
    }
    if ltr == 0 && rtl > 0 {
        return Some(Level::rtl());
    }
    if let Some(language) = language {
        let primary = language
            .split(['-', '_'])
            .next()
            .unwrap_or(language)
            .to_ascii_lowercase();
        if ["fa", "ar", "ur", "ps", "he", "yi"].contains(&primary.as_str()) {
            return Some(Level::rtl());
        }
    }
    if rtl > ltr { Some(Level::rtl()) } else { None }
}

fn keep_ltr_clusters(tokens: Vec<(String, bool)>) -> Vec<(String, bool)> {
    let rtl = |s: &str| {
        s.chars()
            .any(|c| matches!(bidi_class(c), BidiClass::R | BidiClass::AL))
    };
    let anchor = |s: &str| {
        s.chars()
            .any(|c| matches!(bidi_class(c), BidiClass::L | BidiClass::EN | BidiClass::AN))
    };
    let mut result = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i].1 || rtl(&tokens[i].0) {
            result.push(tokens[i].clone());
            i += 1;
            continue;
        }
        let start = i;
        while i < tokens.len() && !tokens[i].1 && !rtl(&tokens[i].0) {
            i += 1;
        }
        let run = &tokens[start..i];
        if let (Some(mut first), Some(mut last)) = (
            run.iter().position(|t| anchor(&t.0)),
            run.iter().rposition(|t| anchor(&t.0)),
        ) {
            if first > 0
                && ["−", "-", "+"].contains(&run[first - 1].0.as_str())
                && run[first]
                    .0
                    .chars()
                    .next()
                    .is_some_and(|c| matches!(bidi_class(c), BidiClass::EN | BidiClass::AN))
            {
                first -= 1;
            }
            if first > 0
                && last + 1 < run.len()
                && [("(", ")"), ("[", "]"), ("{", "}")]
                    .iter()
                    .any(|(a, b)| run[first - 1].0 == *a && run[last + 1].0 == *b)
            {
                first -= 1;
                last += 1;
            }
            result.extend_from_slice(&run[..first]);
            result.push((
                run[first..=last].iter().map(|t| t.0.as_str()).collect(),
                false,
            ));
            result.extend_from_slice(&run[last + 1..]);
        } else {
            result.extend_from_slice(run);
        }
    }
    result
}
/// Reconstruct one physical left-to-right baseline. The UAX#9 run permutation
/// depends only on Unicode classes and the PDF language, never reference text.
pub fn logical_baseline(glyphs: &[Glyph], language: Option<&str>) -> String {
    if glyphs.is_empty() {
        return String::new();
    }
    let axis = glyphs[0].axis;
    let along = |g: &Glyph| g.x * axis[0] + g.y * axis[1];
    let mut glyphs = glyphs.to_vec();
    glyphs.sort_by(|a, b| along(a).total_cmp(&along(b)));
    let mut tokens: Vec<(String, bool)> = Vec::new();
    let mut edge = None;
    for glyph in glyphs {
        let start = along(&glyph);
        if let Some(previous) = edge
            && start - previous > glyph.size.abs() * 0.18
            && !tokens
                .last()
                .is_some_and(|(s, _)| s.ends_with(char::is_whitespace))
            && !glyph.text.starts_with(char::is_whitespace)
        {
            tokens.push((" ".to_owned(), false));
        }
        tokens.push((glyph.text.clone(), glyph.actual));
        edge = Some(start + glyph.advance.max(0.));
    }
    // Scientific numeric/unit expressions are physical LTR clusters, including
    // a leading sign. Keep those interiors intact before resolving their order
    // relative to RTL text; treating "23.5 C" as separate weak runs moves C.
    let tokens = keep_ltr_clusters(tokens);
    let surrogate: String = tokens.iter().map(|(s, _)| representative(s)).collect();
    let bidi = BidiInfo::new(&surrogate, base_level(&surrogate, language));
    let Some(para) = bidi.paragraphs.first() else {
        return String::new();
    };
    let levels = bidi.reordered_levels_per_char(para, para.range.clone());
    let order = BidiInfo::reorder_visual(&levels);
    let mut result = String::new();
    for index in order {
        let (text, actual) = &tokens[index];
        if !actual && text.chars().count() == 1 && levels[index].is_rtl() {
            let c = text.chars().next().unwrap();
            if "()[]{}".contains(c) {
                result.push(unicode_bidi_mirroring::get_mirrored(c).unwrap_or(c));
            } else {
                result.push(c);
            }
        } else {
            result.push_str(text);
        }
    }
    result
}
/// Baseline grouping retains the source's first-seen block order. Superscripts
/// are kept with the baseline by a size-relative tolerance, avoiding global page
/// sorting that would intermingle unrelated columns.
pub fn logical_text(glyphs: &[Glyph], language: Option<&str>) -> String {
    struct Line {
        glyphs: Vec<Glyph>,
        baseline: f64,
        size: f64,
        axis: [f64; 2],
    }
    let mut lines: Vec<Line> = Vec::new();
    for glyph in glyphs {
        let baseline = -glyph.axis[1] * glyph.x + glyph.axis[0] * glyph.y;
        if let Some(line) = lines.iter_mut().rev().take(256).find(|line| {
            line.axis[0] * glyph.axis[0] + line.axis[1] * glyph.axis[1] > 0.98
                && (line.baseline - baseline).abs() <= line.size.max(glyph.size.abs()) * 0.65
        }) {
            line.glyphs.push(glyph.clone());
            line.size = line.size.max(glyph.size.abs());
        } else {
            lines.push(Line {
                glyphs: vec![glyph.clone()],
                baseline,
                size: glyph.size.abs(),
                axis: glyph.axis,
            });
        }
    }
    let mut out = String::new();
    for line in lines {
        out.push_str(&logical_baseline(&line.glyphs, language));
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}
