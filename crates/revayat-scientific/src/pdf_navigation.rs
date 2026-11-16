//! Lossless supported navigation: PDF-space arrays remain arrays and nulls.
use anyhow::{Result, bail, ensure};
use lopdf::{Dictionary, Document, Object, ObjectId};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

pub fn resolved<'a>(doc: &'a Document, object: &'a Object) -> Result<&'a Object> {
    let mut value = object;
    let mut seen = HashSet::new();
    while let Object::Reference(id) = value {
        ensure!(
            seen.len() < 64 && seen.insert(*id),
            "cyclic or excessive PDF object reference"
        );
        value = doc.get_object(*id)?;
    }
    Ok(value)
}
pub fn object_json(doc: &Document, object: &Object, depth: usize) -> Result<Value> {
    ensure!(depth < 64, "PDF data nesting exceeds limits");
    let value = resolved(doc, object)?;
    Ok(match value {
        Object::Null => Value::Null,
        Object::Boolean(b) => json!(b),
        Object::Integer(n) => json!(n),
        Object::Real(n) => {
            ensure!(n.is_finite(), "nonfinite PDF number");
            json!(n)
        }
        Object::Name(s) => json!({"name":String::from_utf8(s.clone())?}),
        Object::String(s, _) => {
            json!({"string_hex":s.iter().map(|b|format!("{b:02x}")).collect::<String>()})
        }
        Object::Array(a) => Value::Array(
            a.iter()
                .map(|v| object_json(doc, v, depth + 1))
                .collect::<Result<_>>()?,
        ),
        Object::Dictionary(d) => {
            let mut v = serde_json::Map::new();
            for (k, o) in d {
                v.insert(
                    String::from_utf8(k.clone())?,
                    object_json(doc, o, depth + 1)?,
                );
            }
            Value::Object(v)
        }
        Object::Stream(_) => bail!("stream not supported in navigation data"),
        Object::Reference(_) => unreachable!(),
    })
}
pub fn destination(
    doc: &Document,
    object: &Object,
    pages: &BTreeMap<ObjectId, usize>,
    first: usize,
    last: usize,
    offset: usize,
) -> Result<Value> {
    let values = resolved(doc, object)?
        .as_array()
        .map_err(|_| anyhow::anyhow!("named or unresolved page destinations require review"))?;
    ensure!(values.len() >= 2, "incomplete local destination");
    let id = values[0].as_reference()?;
    let index = *pages
        .get(&id)
        .ok_or_else(|| anyhow::anyhow!("destination does not resolve to a page"))?;
    ensure!(
        (first..=last).contains(&index),
        "page link target outside copied range"
    );
    let mode = values[1].as_name()?;
    let count = match mode {
        b"XYZ" => 3,
        b"Fit" | b"FitB" => 0,
        b"FitH" | b"FitV" | b"FitBH" | b"FitBV" => 1,
        b"FitR" => 4,
        _ => bail!("unsupported local destination mode"),
    };
    ensure!(
        values.len() == count + 2,
        "unsupported destination argument count"
    );
    let mut args = Vec::new();
    for v in &values[2..] {
        match v {
            Object::Null => args.push(Value::Null),
            Object::Integer(n) => args.push(json!(*n as f64)),
            Object::Real(n) if n.is_finite() => args.push(json!(*n as f64)),
            _ => bail!("unsupported destination coordinate"),
        }
    }
    Ok(json!({"page":index-first+offset,"fit":String::from_utf8(mode.to_vec())?,"args":args}))
}
fn action(
    doc: &Document,
    item: &Dictionary,
    pages: &BTreeMap<ObjectId, usize>,
    first: usize,
    last: usize,
    offset: usize,
) -> Result<Value> {
    let direct = item
        .get(b"Dest")
        .ok()
        .filter(|o| !matches!(o, Object::Null));
    let a = item.get(b"A").ok().filter(|o| !matches!(o, Object::Null));
    ensure!(
        direct.is_none() || a.is_none(),
        "ambiguous navigation contains Dest and action"
    );
    if let Some(d) = direct {
        return Ok(json!({"direct":destination(doc,d,pages,first,last,offset)?}));
    }
    if let Some(a) = a {
        let a = resolved(doc, a)?.as_dict()?;
        ensure!(
            !a.has(b"Next"),
            "chained navigation actions require reviewed copy"
        );
        match a.get(b"S")?.as_name()? {
            b"GoTo" => {
                ensure!(
                    a.iter()
                        .all(|(k, _)| [b"S".as_slice(), b"D", b"Type"].contains(&k.as_slice())),
                    "unsupported local action data"
                );
                return Ok(json!({"goto":destination(doc,a.get(b"D")?,pages,first,last,offset)?}));
            }
            b"URI" => {
                ensure!(
                    a.iter()
                        .all(|(k, _)| [b"S".as_slice(), b"URI", b"IsMap", b"Type"]
                            .contains(&k.as_slice())),
                    "unsupported URI action data"
                );
                let _ = resolved(doc, a.get(b"URI")?)?.as_str()?;
                if let Ok(v) = a.get(b"IsMap") {
                    ensure!(matches!(v, Object::Boolean(_)), "unsupported URI IsMap");
                }
                return Ok(json!({"uri":object_json(doc,&Object::Dictionary(a.clone()),0)?}));
            }
            _ => bail!("named, remote or advanced navigation requires reviewed copy"),
        }
    }
    Ok(Value::Null)
}

pub fn links(doc: &Document, first: usize, last: usize, offset: usize) -> Result<Vec<Value>> {
    let ids = crate::pdf::page_ids(doc)?;
    let pages: BTreeMap<_, _> = ids.iter().enumerate().map(|(i, id)| (*id, i)).collect();
    let mut rows = Vec::new();
    for (index, id) in ids.iter().enumerate().take(last + 1).skip(first) {
        let page = doc.get_dictionary(*id)?;
        if let Ok(annotations) = page.get(b"Annots") {
            for obj in resolved(doc, annotations)?.as_array()? {
                let annotation = resolved(doc, obj)?.as_dict()?;
                if annotation.get(b"Subtype").and_then(Object::as_name).ok() != Some(b"Link") {
                    continue;
                }
                let navigation = action(doc, annotation, &pages, first, last, offset)?;
                ensure!(
                    !navigation.is_null(),
                    "unresolved link annotation requires reviewed copy"
                );
                let mut attributes = serde_json::Map::new();
                for (k, v) in annotation {
                    if ![b"P".as_slice(), b"A", b"Dest", b"Parent"].contains(&k.as_slice()) {
                        attributes.insert(String::from_utf8(k.clone())?, object_json(doc, v, 0)?);
                    }
                }
                rows.push(json!({"page":index-first+offset,"navigation":navigation,"attributes":attributes}));
            }
        }
    }
    Ok(rows)
}

fn outline_walk(
    doc: &Document,
    start: ObjectId,
    level: usize,
    pages: &BTreeMap<ObjectId, usize>,
    offset: usize,
    seen: &mut HashSet<ObjectId>,
    rows: &mut Vec<Value>,
) -> Result<Vec<ObjectId>> {
    ensure!(level <= 64, "outline depth exceeds limit");
    let mut current = Some(start);
    let mut siblings = Vec::new();
    while let Some(id) = current {
        ensure!(
            seen.len() < 10000 && seen.insert(id),
            "cyclic or excessive outline"
        );
        siblings.push(id);
        let item = doc.get_dictionary(id)?;
        let navigation = action(doc, item, pages, 0, pages.len() - 1, offset)?;
        let mut attributes = serde_json::Map::new();
        for (k, v) in item {
            if ![
                b"Parent".as_slice(),
                b"First",
                b"Last",
                b"Prev",
                b"Next",
                b"A",
                b"Dest",
            ]
            .contains(&k.as_slice())
            {
                attributes.insert(String::from_utf8(k.clone())?, object_json(doc, v, 0)?);
            }
        }
        rows.push(json!({"level":level,"navigation":navigation,"attributes":attributes}));
        if let Ok(child) = item.get(b"First") {
            outline_walk(
                doc,
                child.as_reference()?,
                level + 1,
                pages,
                offset,
                seen,
                rows,
            )?;
        }
        current = item
            .get(b"Next")
            .ok()
            .map(Object::as_reference)
            .transpose()?;
    }
    Ok(siblings)
}
pub fn outlines(doc: &Document, offset: usize) -> Result<(Vec<Value>, Vec<ObjectId>)> {
    let pages: BTreeMap<_, _> = crate::pdf::page_ids(doc)?
        .into_iter()
        .enumerate()
        .map(|(i, id)| (id, i))
        .collect();
    if let Ok(outlines) = doc.catalog()?.get(b"Outlines") {
        let root = resolved(doc, outlines)?.as_dict()?;
        if let Ok(first) = root.get(b"First") {
            let mut rows = Vec::new();
            let top = outline_walk(
                doc,
                first.as_reference()?,
                1,
                &pages,
                offset,
                &mut HashSet::new(),
                &mut rows,
            )?;
            return Ok((rows, top));
        }
    }
    Ok((Vec::new(), Vec::new()))
}
