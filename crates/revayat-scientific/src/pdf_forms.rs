//! Typed AcroForm planning, serialized button names and reopened value checks.
use crate::pdf_navigation::resolved;
use anyhow::{Context, Result, bail, ensure};
use lopdf::{Document, Object, ObjectId, Stream, content::Content, dictionary};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

pub fn text(object: &Object) -> Result<String> {
    match object {
        Object::Name(v) => Ok(String::from_utf8(v.clone())?),
        Object::String(v, _) => {
            if v.starts_with(&[0xfe, 0xff]) {
                ensure!(v.len() % 2 == 0, "invalid UTF-16 PDF string");
                Ok(String::from_utf16(
                    &v[2..]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|p| u16::from_be_bytes([p[0], p[1]]))
                        .collect::<Vec<_>>(),
                )?)
            } else {
                Ok(String::from_utf8(v.clone())
                    .unwrap_or_else(|_| v.iter().map(|b| char::from(*b)).collect()))
            }
        }
        _ => bail!("expected PDF string or name"),
    }
}
pub fn inherited<'a>(doc: &'a Document, id: ObjectId, key: &[u8]) -> Result<Option<&'a Object>> {
    let mut current = id;
    let mut seen = HashSet::new();
    loop {
        ensure!(
            seen.len() < 64 && seen.insert(current),
            "stored value parent cycle or depth limit"
        );
        let d = doc.get_dictionary(current)?;
        if let Ok(o) = d.get(key)
            && !matches!(o, Object::Null)
        {
            return Ok(Some(resolved(doc, o)?));
        }
        if let Ok(p) = d.get(b"Parent") {
            current = p.as_reference()?;
        } else {
            return Ok(None);
        }
    }
}
#[derive(Clone, Debug)]
pub struct Widget {
    pub page: usize,
    pub id: ObjectId,
    pub name: String,
    pub kind: Vec<u8>,
    pub flags: i64,
    pub rect: [f64; 4],
}
pub fn widgets(doc: &Document) -> Result<Vec<Widget>> {
    let mut result = Vec::new();
    for (page, id) in crate::pdf::page_ids(doc)?.into_iter().enumerate() {
        if let Ok(annots) = doc.get_dictionary(id)?.get(b"Annots") {
            for reference in resolved(doc, annots)?.as_array()? {
                let id = reference.as_reference()?;
                let d = doc.get_dictionary(id)?;
                if d.get(b"Subtype").and_then(Object::as_name).ok() != Some(b"Widget") {
                    continue;
                }
                let mut names = Vec::new();
                let mut current = Some(id);
                let mut seen = HashSet::new();
                while let Some(p) = current {
                    ensure!(seen.len() < 64 && seen.insert(p), "field parent cycle");
                    let f = doc.get_dictionary(p)?;
                    if let Ok(n) = f.get(b"T") {
                        names.push(text(resolved(doc, n)?)?);
                    }
                    current = f
                        .get(b"Parent")
                        .ok()
                        .map(Object::as_reference)
                        .transpose()?;
                }
                names.reverse();
                let name = names.join(".");
                let kind = inherited(doc, id, b"FT")?
                    .context("widget has no field type")?
                    .as_name()?
                    .to_vec();
                let flags = inherited(doc, id, b"Ff")?
                    .map(Object::as_i64)
                    .transpose()?
                    .unwrap_or(0);
                let rect = crate::pdf::rectangle(resolved(doc, d.get(b"Rect")?)?)?;
                result.push(Widget {
                    page,
                    id,
                    name,
                    kind,
                    flags,
                    rect,
                });
            }
        }
    }
    Ok(result)
}
pub fn signature_present(doc: &Document) -> Result<bool> {
    if let Ok(form) = doc.catalog()?.get(b"AcroForm") {
        let form = resolved(doc, form)?.as_dict()?;
        if form.get(b"SigFlags").and_then(Object::as_i64).unwrap_or(0) > 0 {
            return Ok(true);
        }
    }
    for obj in doc.objects.values() {
        let d = match obj {
            Object::Dictionary(d) => d,
            Object::Stream(s) => &s.dict,
            _ => continue,
        };
        if d.get(b"Type").and_then(Object::as_name).ok() == Some(b"Sig")
            || d.get(b"FT").and_then(Object::as_name).ok() == Some(b"Sig")
            || d.has(b"ByteRange")
        {
            return Ok(true);
        }
    }
    Ok(false)
}
pub fn ensure_transformable(doc: &Document) -> Result<()> {
    ensure!(
        !signature_present(doc)?,
        "signed or signature-bearing PDF requires reviewed unsigned copy"
    );
    if let Ok(form) = doc.catalog()?.get(b"AcroForm") {
        ensure!(
            !resolved(doc, form)?.as_dict()?.has(b"XFA"),
            "XFA forms require reviewed AcroForm copy"
        );
    }
    Ok(())
}
pub fn button_states(
    doc: &Document,
    id: ObjectId,
    appearance: &[u8],
) -> Result<Option<Vec<String>>> {
    let d = doc.get_dictionary(id)?;
    let Some(ap) = d.get(b"AP").ok() else {
        return Ok(None);
    };
    let ap = resolved(doc, ap)?.as_dict()?;
    let Some(value) = ap.get(appearance).ok() else {
        return Ok(None);
    };
    let value = resolved(doc, value)?;
    if matches!(value, Object::Stream(_)) {
        return Ok(None);
    }
    let states = value.as_dict()?;
    ensure!(states.len() <= 1024, "excessive button appearance states");
    let mut bytes = 0;
    let mut names = HashSet::new();
    let mut result = Vec::new();
    for (name, value) in states {
        bytes += name.len() + 32;
        ensure!(bytes <= 65536, "button appearance dictionary exceeds limit");
        let name =
            String::from_utf8(name.clone()).context("button names require lossless UTF-8")?;
        ensure!(
            !name.is_empty() && !name.chars().any(|c| c.is_control()) && names.insert(name.clone()),
            "ambiguous button appearance state"
        );
        let _ = doc
            .get_object(value.as_reference()?)?
            .as_stream()
            .context("button appearance must reference individual stream")?;
        result.push(name);
    }
    Ok(Some(result))
}
pub fn on_state(states: &[String]) -> Result<&str> {
    let on: Vec<_> = states.iter().filter(|s| s.as_str() != "Off").collect();
    ensure!(
        states.iter().any(|s| s == "Off") && on.len() == 1,
        "button needs Off and one unambiguous normal on-state"
    );
    Ok(on[0])
}
pub fn stored_value(doc: &Document, id: ObjectId) -> Result<Option<String>> {
    inherited(doc, id, b"V")?.map(text).transpose()
}
pub fn inventory(doc: &Document) -> Result<Vec<Value>> {
    widgets(doc)?.into_iter().map(|w|{
        let button=w.kind==b"Btn" && w.flags&(1<<16)==0;
        let states=if button{button_states(doc,w.id,b"N")?}else{None};
        let value=inherited(doc,w.id,b"V")?.map(text).transpose()?;
        let choices=inherited(doc,w.id,b"Opt")?.map(|o|crate::pdf_navigation::object_json(doc,o,0)).transpose()?;
        Ok(json!({"page":w.page+1,"xref":w.id.0,"name":w.name,"type":String::from_utf8(w.kind)?,"value":value,"flags":w.flags,"rect":w.rect,"choices":choices,"on_state":states.as_ref().and_then(|s|on_state(s).ok()),"button_states":{"normal":states,"down":if button{button_states(doc,w.id,b"D")?}else{None}},"signed":false}))
    }).collect()
}
#[derive(Clone)]
pub struct Planned {
    pub widget: Widget,
    pub value: String,
    pub button: bool,
    pub radio: bool,
    pub group_value: String,
}
pub fn plan_fill(doc: &Document, values: &serde_json::Map<String, Value>) -> Result<Vec<Planned>> {
    ensure!(
        !values.is_empty() && values.len() <= 10000,
        "fields JSON must be a nonempty object with at most 10000 entries"
    );
    let mut groups: BTreeMap<String, Vec<Widget>> = BTreeMap::new();
    for w in widgets(doc)? {
        groups.entry(w.name.clone()).or_default().push(w);
    }
    let mut result = Vec::new();
    for (name, value) in values {
        let fields = groups
            .get(name)
            .context("fields JSON contains unknown field name")?;
        ensure!(
            fields.iter().all(|w| w.kind == fields[0].kind),
            "one field name resolves to incompatible widget types"
        );
        let radio = fields[0].kind == b"Btn" && fields[0].flags & (1 << 15) != 0;
        let radio_states = if radio {
            fields
                .iter()
                .map(|w| {
                    button_states(doc, w.id, b"N")?
                        .context("missing radio appearance")
                        .and_then(|s| Ok(on_state(&s)?.to_owned()))
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        if radio {
            let wanted = value
                .as_str()
                .context("radio value must select one exact unique on-state")?;
            ensure!(
                radio_states.iter().filter(|s| s.as_str() == wanted).count() == 1,
                "radio value must select one exact unique on-state"
            );
        }
        for (index, w) in fields.iter().enumerate() {
            ensure!(w.flags & 1 == 0, "cannot modify read-only field");
            ensure!(
                inherited(doc, w.id, b"AA")?.is_none() && inherited(doc, w.id, b"A")?.is_none(),
                "scripted field requires reviewed interactive workflow"
            );
            let mut button = false;
            let normalized = match w.kind.as_slice() {
                b"Tx" => {
                    let s = if let Some(s) = value.as_str() {
                        s.to_owned()
                    } else if value.is_number() {
                        value.to_string()
                    } else {
                        bail!("text fields accept strings or finite numbers, including zero")
                    };
                    ensure!(
                        s.chars().count() <= 100000 && !s.contains('\0'),
                        "text field value exceeds limits"
                    );
                    if let Some(max) = inherited(doc, w.id, b"MaxLen")? {
                        let max = max.as_i64()?;
                        ensure!(
                            max == 0 || s.chars().count() <= max as usize,
                            "text field exceeds document maximum length"
                        );
                    }
                    s
                }
                b"Btn" => {
                    button = true;
                    ensure!(w.flags & (1 << 16) == 0, "pushbuttons cannot be filled");
                    let states =
                        button_states(doc, w.id, b"N")?.context("missing button appearance")?;
                    let selected = on_state(&states)?;
                    if radio {
                        if radio_states[index] == value.as_str().unwrap() {
                            selected.to_owned()
                        } else {
                            "Off".to_owned()
                        }
                    } else if let Some(b) = value.as_bool() {
                        if b {
                            selected.to_owned()
                        } else {
                            "Off".to_owned()
                        }
                    } else if let Some(s) = value.as_str() {
                        ensure!(
                            states.iter().any(|v| v == s),
                            "checkbox needs exact documented state"
                        );
                        s.to_owned()
                    } else {
                        bail!("checkbox accepts boolean or exact documented state")
                    }
                }
                b"Ch" => {
                    ensure!(
                        w.flags & (1 << 21) == 0,
                        "multi-select fields require reviewed workflow"
                    );
                    let s = value.as_str().context("choice field requires string")?;
                    let choices = inherited(doc, w.id, b"Opt")?
                        .map(Object::as_array)
                        .transpose()?
                        .cloned()
                        .unwrap_or_default();
                    let allowed = choices
                        .iter()
                        .map(|o| {
                            text(if let Object::Array(a) = o {
                                a.first().unwrap_or(&Object::Null)
                            } else {
                                o
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    ensure!(
                        allowed.iter().any(|v| v == s)
                            || (w.flags & (1 << 17) != 0 && w.flags & (1 << 18) != 0),
                        "value is not allowed field choice"
                    );
                    s.to_owned()
                }
                _ => bail!("unsupported field type; signatures cannot be filled"),
            };
            result.push(Planned {
                widget: w.clone(),
                value: normalized,
                button,
                radio,
                group_value: if radio {
                    value.as_str().unwrap().to_owned()
                } else {
                    String::new()
                },
            });
        }
    }
    result.sort_by_key(|p| p.value != "Off");
    Ok(result)
}
fn text_appearance(doc: &mut Document, w: &Widget, value: &str) -> Result<ObjectId> {
    let width = (w.rect[2] - w.rect[0]) as f32;
    let height = (w.rect[3] - w.rect[1]) as f32;
    let (font, shaped) =
        crate::pdf_font::appearance(doc, value, f64::from(width), f64::from(height))?;
    let mut resources = dictionary! {"Font"=>dictionary!{"RvForm"=>font}};
    let mut operations = Vec::new();
    if let Ok(ap) = doc.get_dictionary(w.id)?.get(b"AP")
        && let Ok(n) = resolved(doc, ap)?.as_dict()?.get(b"N")
        && let Ok(stream) = resolved(doc, n)?.as_stream()
    {
        if let Ok(old) = stream.dict.get(b"Resources") {
            resources = resolved(doc, old)?.as_dict()?.clone();
            let mut fonts = resources
                .get(b"Font")
                .ok()
                .map(|f| resolved(doc, f).and_then(|v| Ok(v.as_dict()?.clone())))
                .transpose()?
                .unwrap_or_default();
            fonts.set("RvForm", font);
            resources.set("Font", fonts);
        }
        let data = stream
            .decompressed_content()
            .unwrap_or_else(|_| stream.content.clone());
        let old = Content::decode(&data)?;
        let mut in_text = false;
        for op in old.operations {
            match op.operator.as_str() {
                "BT" => in_text = true,
                "ET" => in_text = false,
                _ => {
                    if !in_text {
                        operations.push(op);
                    }
                }
            }
        }
    }
    operations.extend(shaped);
    Ok(doc.add_object(Stream::new(dictionary!{"Type"=>"XObject","Subtype"=>"Form","BBox"=>vec![0.into(),0.into(),width.into(),height.into()],"Resources"=>resources},Content{operations}.encode()?)))
}
pub fn apply_fill(doc: &mut Document, plan: &[Planned]) -> Result<()> {
    for p in plan {
        let appearance = if p.button {
            None
        } else {
            Some(text_appearance(doc, &p.widget, &p.value)?)
        };
        let d = doc.get_object_mut(p.widget.id)?.as_dict_mut()?;
        if p.button {
            d.set("AS", Object::Name(p.value.as_bytes().to_vec()));
            d.set(
                "V",
                Object::Name(
                    if p.radio {
                        p.group_value.as_bytes()
                    } else {
                        p.value.as_bytes()
                    }
                    .to_vec(),
                ),
            );
        } else {
            let mut raw = vec![0xfe, 0xff];
            for n in p.value.encode_utf16() {
                raw.extend(n.to_be_bytes());
            }
            d.set("V", Object::String(raw, lopdf::StringFormat::Hexadecimal));
            d.set("AP", dictionary! {"N"=>appearance.unwrap()});
        }
        if p.radio {
            let parent = d
                .get(b"Parent")
                .ok()
                .map(Object::as_reference)
                .transpose()?;
            if let Some(id) = parent {
                doc.get_object_mut(id)?
                    .as_dict_mut()?
                    .set("V", Object::Name(p.group_value.as_bytes().to_vec()));
            }
        }
    }
    Ok(())
}
pub fn verify_fill(doc: &Document, plan: &[Planned]) -> Result<()> {
    for p in plan {
        let d = doc.get_dictionary(p.widget.id)?;
        if p.button {
            ensure!(
                d.get(b"AS")?.as_name()? == p.value.as_bytes(),
                "saved button appearance failed verification"
            );
            let states = button_states(doc, p.widget.id, b"N")?
                .context("saved button missing appearance")?;
            ensure!(
                states.iter().any(|s| s == &p.value),
                "saved button state has no matching appearance"
            );
            let actual = stored_value(doc, p.widget.id)?.context("saved button missing value")?;
            ensure!(
                actual.as_str()
                    == if p.radio {
                        p.group_value.as_str()
                    } else {
                        p.value.as_str()
                    },
                "saved button value disagrees with appearance"
            );
            if p.radio
                && let Ok(parent) = d.get(b"Parent")
            {
                ensure!(
                    stored_value(doc, parent.as_reference()?)?.as_deref()
                        == Some(p.group_value.as_str()),
                    "radio parent value disagrees with group"
                );
            }
        } else {
            ensure!(
                stored_value(doc, p.widget.id)?.as_deref() == Some(p.value.as_str()),
                "saved form value failed verification"
            );
        }
    }
    Ok(())
}
