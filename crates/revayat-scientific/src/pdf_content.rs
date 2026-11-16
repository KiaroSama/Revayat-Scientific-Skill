//! Native PDF content interpretation for stored text, artwork and reviewed grids.
use crate::{pdf, pdf_forms, pdf_navigation as nav};
use anyhow::{Context, Result, bail, ensure};
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, content::Content};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
};
use serde_json::Value;
use std::{collections::HashSet, fmt};

pub struct UniqueFields(pub serde_json::Map<String, Value>);
impl<'de> Deserialize<'de> for UniqueFields {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = UniqueFields;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "unique fields object")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut m = serde_json::Map::new();
                while let Some((k, v)) = a.next_entry::<String, Value>()? {
                    if m.insert(k, v).is_some() {
                        return Err(de::Error::custom("duplicate field name in JSON"));
                    }
                }
                Ok(UniqueFields(m))
            }
        }
        d.deserialize_map(V)
    }
}
type Matrix = [f64; 6];
const IDENTITY: Matrix = [1., 0., 0., 1., 0., 0.];
fn number(o: &Object) -> Result<f64> {
    let v = match o {
        Object::Integer(n) => *n as f64,
        Object::Real(n) => f64::from(*n),
        _ => bail!("content operand must be numeric"),
    };
    ensure!(v.is_finite(), "nonfinite content coordinate");
    Ok(v)
}
fn matrix(a: &[Object]) -> Result<Matrix> {
    ensure!(a.len() == 6, "matrix needs six numbers");
    let mut m = [0.; 6];
    for (i, n) in a.iter().enumerate() {
        m[i] = number(n)?;
    }
    Ok(m)
}
fn compose(a: Matrix, b: Matrix) -> Matrix {
    [
        a[0] * b[0] + a[2] * b[1],
        a[1] * b[0] + a[3] * b[1],
        a[0] * b[2] + a[2] * b[3],
        a[1] * b[2] + a[3] * b[3],
        a[0] * b[4] + a[2] * b[5] + a[4],
        a[1] * b[4] + a[3] * b[5] + a[5],
    ]
}
fn point(m: Matrix, x: f64, y: f64) -> [f64; 2] {
    [m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]]
}
fn bounds(points: &[[f64; 2]]) -> [f64; 4] {
    let mut r = [
        f64::INFINITY,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NEG_INFINITY,
    ];
    for p in points {
        r[0] = r[0].min(p[0]);
        r[1] = r[1].min(p[1]);
        r[2] = r[2].max(p[0]);
        r[3] = r[3].max(p[1]);
    }
    r
}
fn display(m: Matrix, g: &pdf::PageGeometry) -> Matrix {
    let c = g.cropbox;
    let base = [1., 0., 0., -1., -c[0], c[3]];
    let w = c[2] - c[0];
    let h = c[3] - c[1];
    let rotation = match g.rotation {
        0 => IDENTITY,
        90 => [0., 1., -1., 0., h, 0.],
        180 => [-1., 0., 0., -1., w, h],
        270 => [0., -1., 1., 0., 0., w],
        _ => unreachable!(),
    };
    compose(compose(rotation, base), m)
}
#[derive(Clone, Debug, Serialize)]
pub struct ImagePlacement {
    pub xref: u32,
    pub width: u32,
    pub height: u32,
    pub bbox: [f64; 4],
    pub transform: Matrix,
    pub page: usize,
}
#[derive(Clone, Debug)]
pub struct TextSpan {
    pub x: f64,
    pub y: f64,
    pub text: String,
    pub axis: [f64; 2],
}
#[derive(Default)]
pub(crate) struct Parsed {
    pub(crate) images: Vec<ImagePlacement>,
    pub(crate) drawings: Vec<[f64; 4]>,
    pub(crate) lines: Vec<([f64; 2], [f64; 2])>,
    pub(crate) texts: Vec<TextSpan>,
    pub(crate) text: String,
    glyphs: Vec<crate::pdf_layout::Glyph>,
}
#[derive(Clone)]
struct State {
    ctm: Matrix,
    font: Vec<u8>,
    text_matrix: Matrix,
    line_matrix: Matrix,
    leading: f64,
    font_size: f64,
    character_spacing: f64,
    word_spacing: f64,
    horizontal_scale: f64,
    rise: f64,
}
impl Default for State {
    fn default() -> Self {
        Self {
            ctm: IDENTITY,
            font: Vec::new(),
            text_matrix: IDENTITY,
            line_matrix: IDENTITY,
            leading: 0.,
            font_size: 12.,
            character_spacing: 0.,
            word_spacing: 0.,
            horizontal_scale: 1.,
            rise: 0.,
        }
    }
}
fn resource_dict(doc: &Document, page: ObjectId) -> Result<Dictionary> {
    Ok(pdf_forms::inherited(doc, page, b"Resources")?
        .map(Object::as_dict)
        .transpose()?
        .cloned()
        .unwrap_or_default())
}
fn positioned(
    glyph: &crate::pdf_layout::DecodedGlyph,
    state: &State,
    g: &pdf::PageGeometry,
    actual: bool,
) -> Result<crate::pdf_layout::Glyph> {
    let transform = display(compose(state.ctm, state.text_matrix), g);
    let position = point(transform, glyph.origin, state.rise);
    let length = transform[0].hypot(transform[1]);
    ensure!(length > 0., "degenerate text writing axis");
    // The writing axis rotates with the page; forcing a positive screen axis
    // would reverse every glyph at /Rotate 180 or 270.
    let axis = [transform[0] / length, transform[1] / length];
    Ok(crate::pdf_layout::Glyph {
        text: glyph.text.clone(),
        x: position[0],
        y: position[1],
        advance: glyph.advance * length,
        size: state.font_size.abs() * transform[2].hypot(transform[3]),
        axis,
        actual,
    })
}
fn parse_stream(
    doc: &Document,
    data: &[u8],
    resources: &Dictionary,
    initial: State,
    g: &pdf::PageGeometry,
    stack: &mut HashSet<ObjectId>,
    out: &mut Parsed,
) -> Result<()> {
    ensure!(
        stack.len() < 32 && data.len() <= 128 * 1024 * 1024,
        "excessive page content"
    );
    let content = Content::decode(data)?;
    ensure!(
        content.operations.len() <= 2_000_000,
        "excessive content operations"
    );
    let mut state = initial;
    let mut saves = Vec::new();
    let mut marks = Vec::new();
    let mut actual_depth = 0usize;
    let mut active_actual: Option<(usize, bool)> = None;
    let mut path = Vec::new();
    let mut segments = Vec::new();
    for op in content.operations {
        let a = &op.operands;
        match op.operator.as_str() {
            "q" => {
                ensure!(saves.len() < 128, "graphics state depth exceeded");
                saves.push(state.clone());
            }
            "Q" => {
                state = saves.pop().context("unbalanced graphics state")?;
            }
            "cm" => state.ctm = compose(state.ctm, matrix(a)?),
            "BT" => {
                state.text_matrix = IDENTITY;
                state.line_matrix = IDENTITY;
            }
            "Tf" => {
                ensure!(a.len() == 2, "invalid font selection");
                state.font = a[0].as_name()?.to_vec();
                state.font_size = number(&a[1])?;
            }
            "Tm" => {
                state.text_matrix = matrix(a)?;
                state.line_matrix = state.text_matrix;
            }
            "Td" | "TD" => {
                ensure!(a.len() == 2, "invalid text offset");
                let tx = number(&a[0])?;
                let ty = number(&a[1])?;
                if op.operator == "TD" {
                    state.leading = -ty;
                }
                state.line_matrix = compose(state.line_matrix, [1., 0., 0., 1., tx, ty]);
                state.text_matrix = state.line_matrix;
            }
            "TL" => state.leading = number(a.first().context("missing leading")?)?,
            "T*" => {
                state.line_matrix =
                    compose(state.line_matrix, [1., 0., 0., 1., 0., -state.leading]);
                state.text_matrix = state.line_matrix;
            }
            "Tc" => {
                state.character_spacing = number(a.first().context("missing character spacing")?)?
            }
            "Tw" => state.word_spacing = number(a.first().context("missing word spacing")?)?,
            "Tz" => {
                state.horizontal_scale =
                    number(a.first().context("missing horizontal scale")?)? / 100.
            }
            "Ts" => state.rise = number(a.first().context("missing text rise")?)?,
            "Tj" | "TJ" | "'" | "\"" => {
                if op.operator == "'" || op.operator == "\"" {
                    state.line_matrix =
                        compose(state.line_matrix, [1., 0., 0., 1., 0., -state.leading]);
                    state.text_matrix = state.line_matrix;
                }
                let operands = if op.operator == "\"" {
                    ensure!(a.len() == 3, "invalid quoted text");
                    state.word_spacing = number(&a[0])?;
                    state.character_spacing = number(&a[1])?;
                    &a[2..]
                } else {
                    a.as_slice()
                };
                let style = crate::pdf_layout::Style {
                    size: state.font_size,
                    character_spacing: state.character_spacing,
                    word_spacing: state.word_spacing,
                    horizontal_scale: state.horizontal_scale,
                };
                let (glyphs, advance) = crate::pdf_layout::decode_glyphs(
                    doc,
                    resources,
                    &state.font,
                    operands,
                    style,
                    actual_depth > 0,
                )?;
                ensure!(
                    out.glyphs.len().saturating_add(glyphs.len()) <= crate::pdf_layout::MAX_GLYPHS,
                    "page glyph budget exceeded"
                );
                if actual_depth == 0 {
                    let text = glyphs.iter().map(|g| g.text.as_str()).collect::<String>();
                    let transform = display(compose(state.ctm, state.text_matrix), g);
                    let p = point(transform, 0., 0.);
                    ensure!(
                        out.text.len().saturating_add(text.len()) <= 64 * 1024 * 1024,
                        "page Unicode text budget exceeded"
                    );
                    out.text.push_str(&text);
                    out.texts.push(TextSpan {
                        x: p[0],
                        y: p[1],
                        text,
                        axis: [transform[0], transform[1]],
                    });
                    for glyph in &glyphs {
                        out.glyphs.push(positioned(glyph, &state, g, false)?);
                    }
                } else if let Some((index, positioned_already)) = active_actual.as_mut()
                    && let Some(first) = glyphs.first()
                {
                    let position = positioned(first, &state, g, true)?;
                    let actual = &mut out.glyphs[*index];
                    if !*positioned_already {
                        actual.x = position.x;
                        actual.y = position.y;
                        actual.axis = position.axis;
                        actual.size = position.size;
                        actual.advance = advance;
                        *positioned_already = true;
                    } else {
                        let edge =
                            position.x * actual.axis[0] + position.y * actual.axis[1] + advance;
                        let start = actual.x * actual.axis[0] + actual.y * actual.axis[1];
                        actual.advance = actual.advance.max(edge - start);
                    }
                }
                state.text_matrix = compose(state.text_matrix, [1., 0., 0., 1., advance, 0.]);
            }
            "ET" => {
                if !out.text.ends_with('\n') {
                    out.text.push('\n');
                }
            }
            "BDC" => {
                ensure!(marks.len() < 128, "marked content nesting exceeded");
                let mut actual = None;
                if let Some(o) = a.get(1) {
                    let props = match o {
                        Object::Name(name) => resources
                            .get(b"Properties")
                            .ok()
                            .map(|p| {
                                nav::resolved(doc, p).and_then(|v| Ok(v.as_dict()?.get(name)?))
                            })
                            .transpose()?,
                        _ => Some(o),
                    };
                    if let Some(props) = props
                        && let Ok(d) = nav::resolved(doc, props)?.as_dict()
                        && let Ok(text) = d.get(b"ActualText")
                    {
                        actual = Some(pdf_forms::text(nav::resolved(doc, text)?)?);
                    }
                }
                if let Some(text) = &actual {
                    if actual_depth == 0 {
                        ensure!(
                            out.text.len().saturating_add(text.len()) <= 64 * 1024 * 1024,
                            "page Unicode text budget exceeded"
                        );
                        out.text.push_str(text);
                        let marker = crate::pdf_layout::DecodedGlyph {
                            text: text.clone(),
                            origin: 0.,
                            advance: 0.,
                        };
                        active_actual = Some((out.glyphs.len(), false));
                        out.glyphs.push(positioned(&marker, &state, g, true)?);
                        let transform = display(compose(state.ctm, state.text_matrix), g);
                        let p = point(transform, 0., 0.);
                        out.texts.push(TextSpan {
                            x: p[0],
                            y: p[1],
                            text: text.clone(),
                            axis: [transform[0], transform[1]],
                        });
                    }
                    actual_depth += 1;
                }
                marks.push(actual.is_some());
            }
            "BMC" => marks.push(false),
            "EMC" => {
                let actual = marks.pop().context("unbalanced marked content")?;
                if actual {
                    actual_depth -= 1;
                    if actual_depth == 0 {
                        active_actual = None;
                    }
                }
            }
            "m" => {
                ensure!(a.len() == 2, "invalid path move");
                path.push(point(state.ctm, number(&a[0])?, number(&a[1])?));
            }
            "l" => {
                ensure!(a.len() == 2, "invalid path line");
                let p = point(state.ctm, number(&a[0])?, number(&a[1])?);
                if let Some(old) = path.last() {
                    segments.push((*old, p));
                }
                path.push(p);
            }
            "c" | "v" | "y" => {
                ensure!(a.len() % 2 == 0, "invalid curve");
                for xy in a.as_chunks::<2>().0 {
                    path.push(point(state.ctm, number(&xy[0])?, number(&xy[1])?));
                }
            }
            "re" => {
                ensure!(a.len() == 4, "invalid rectangle path");
                let x = number(&a[0])?;
                let y = number(&a[1])?;
                let w = number(&a[2])?;
                let h = number(&a[3])?;
                let p = [
                    point(state.ctm, x, y),
                    point(state.ctm, x + w, y),
                    point(state.ctm, x + w, y + h),
                    point(state.ctm, x, y + h),
                ];
                for i in 0..4 {
                    segments.push((p[i], p[(i + 1) % 4]));
                }
                path.extend(p);
            }
            "S" | "s" | "f" | "F" | "f*" | "B" | "B*" | "b" | "b*" => {
                if !path.is_empty() {
                    let r = bounds(&path);
                    let t = display(IDENTITY, g);
                    let r = bounds(&[
                        point(t, r[0], r[1]),
                        point(t, r[2], r[1]),
                        point(t, r[2], r[3]),
                        point(t, r[0], r[3]),
                    ]);
                    if (r[2] - r[0]) * (r[3] - r[1]) >= 80. {
                        out.drawings.push(r);
                    }
                    out.lines.extend(
                        segments
                            .drain(..)
                            .map(|(a, b)| (point(t, a[0], a[1]), point(t, b[0], b[1]))),
                    );
                    path.clear();
                }
            }
            "n" => {
                path.clear();
                segments.clear();
            }
            "Do" => {
                let name = a.first().context("missing XObject name")?.as_name()?;
                let xobjects = nav::resolved(doc, resources.get(b"XObject")?)?.as_dict()?;
                let reference = xobjects.get(name)?;
                let id = reference.as_reference()?;
                let stream = doc.get_object(id)?.as_stream()?;
                match stream.dict.get(b"Subtype")?.as_name()? {
                    b"Image" => {
                        let width = stream.dict.get(b"Width")?.as_i64()?;
                        let height = stream.dict.get(b"Height")?.as_i64()?;
                        ensure!(
                            width > 0
                                && height > 0
                                && width.checked_mul(height).is_some_and(|n| n <= 50_000_000),
                            "embedded image exceeds pixel limit"
                        );
                        let t = display(state.ctm, g);
                        let bbox = bounds(&[
                            point(t, 0., 0.),
                            point(t, 1., 0.),
                            point(t, 1., 1.),
                            point(t, 0., 1.),
                        ]);
                        out.images.push(ImagePlacement {
                            xref: id.0,
                            width: width as u32,
                            height: height as u32,
                            bbox,
                            transform: t,
                            page: g.page,
                        });
                    }
                    b"Form" => {
                        ensure!(stack.insert(id), "cyclic Form XObject");
                        let mut child = state.clone();
                        if let Ok(m) = stream.dict.get(b"Matrix") {
                            child.ctm =
                                compose(child.ctm, matrix(nav::resolved(doc, m)?.as_array()?)?);
                        }
                        let resources = stream
                            .dict
                            .get(b"Resources")
                            .ok()
                            .map(|r| nav::resolved(doc, r).and_then(|v| Ok(v.as_dict()?)))
                            .transpose()?
                            .unwrap_or(resources);
                        let data = decoded(stream)?;
                        parse_stream(doc, &data, resources, child, g, stack, out)?;
                        stack.remove(&id);
                    }
                    _ => bail!("unsupported XObject subtype"),
                }
            }
            "BI" => bail!("inline image requires reviewed page extraction"),
            _ => {}
        }
    }
    ensure!(
        marks.is_empty() && saves.is_empty(),
        "unbalanced page content state"
    );
    Ok(())
}
pub fn decoded(stream: &Stream) -> Result<Vec<u8>> {
    let data = if stream.dict.has(b"Filter") {
        stream.decompressed_content_with_limit(128 * 1024 * 1024)?
    } else {
        stream.content.clone()
    };
    ensure!(
        data.len() <= 128 * 1024 * 1024,
        "decoded stream exceeds limit"
    );
    Ok(data)
}
pub(crate) fn parse_page(doc: &Document, page: ObjectId) -> Result<Parsed> {
    let ids = pdf::page_ids(doc)?;
    let index = ids
        .iter()
        .position(|id| *id == page)
        .context("page not in tree")?;
    let g = pdf::geometry(doc)?;
    let mut out = Parsed::default();
    parse_stream(
        doc,
        &page_stream(doc, page)?,
        &resource_dict(doc, page)?,
        State::default(),
        &g[index],
        &mut HashSet::new(),
        &mut out,
    )?;
    Ok(out)
}
pub fn page_text(doc: &Document, page: ObjectId) -> Result<String> {
    let parsed = parse_page(doc, page)?;
    let language = doc
        .catalog()?
        .get(b"Lang")
        .ok()
        .map(crate::pdf_forms::text)
        .transpose()?;
    Ok(crate::pdf_layout::logical_text(
        &parsed.glyphs,
        language.as_deref(),
    ))
}
pub fn stored_page_text(doc: &Document, page: ObjectId) -> Result<String> {
    Ok(parse_page(doc, page)?.text)
}
pub fn artwork(doc: &Document, page: usize) -> Result<(Vec<[f64; 4]>, Vec<ImagePlacement>)> {
    let ids = pdf::page_ids(doc)?;
    ensure!(page > 0 && page <= ids.len(), "page exceeds source");
    let p = parse_page(doc, ids[page - 1])?;
    let mut rects = p.drawings;
    rects.extend(
        p.images
            .iter()
            .filter(|i| i.bbox[2] - i.bbox[0] >= 8. && i.bbox[3] - i.bbox[1] >= 4.)
            .map(|i| i.bbox),
    );
    Ok((rects, p.images))
}
pub use crate::pdf_extract::{extract_images, extract_tables};

/// A page Contents array has independent lexical streams. Always separate them
/// before parsing so an ET at one boundary never swallows a following q.
pub fn page_stream(doc: &Document, page: ObjectId) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for id in doc.get_page_contents(page) {
        out.extend(decoded(doc.get_object(id)?.as_stream()?)?);
        out.push(b'\n');
        ensure!(out.len() <= 128 * 1024 * 1024, "page content exceeds limit");
    }
    Ok(out)
}
