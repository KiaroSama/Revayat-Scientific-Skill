//! Native bounded PDF admission, object-preserving transformations and reports.
use crate::{pdf_forms, pdf_navigation as nav, publication};
#[path = "pdf_transaction.rs"]
mod transaction;
use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use lopdf::{Document, Object, ObjectId, dictionary};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
pub use transaction::{
    AdmissionLimits, PdfBoundary, open_pdf, open_pdf_with_limits, save_document,
    save_document_observed, write_report, write_report_observed,
};

pub const MAX_PDF_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_PDF_PAGES: usize = 10000;
pub const MAX_PDF_OBJECTS: usize = 200000;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PageGeometry {
    pub page: usize,
    pub mediabox: [f64; 4],
    pub cropbox: [f64; 4],
    pub rect: [f64; 4],
    pub rotation: i64,
}

pub fn rectangle(object: &Object) -> Result<[f64; 4]> {
    let a = object.as_array()?;
    ensure!(a.len() == 4, "page rectangle needs four numbers");
    let mut out = [0.; 4];
    for (i, n) in a.iter().enumerate() {
        out[i] = match n {
            Object::Integer(n) => *n as f64,
            Object::Real(n) => f64::from(*n),
            _ => bail!("page rectangle contains nonnumeric value"),
        };
        ensure!(out[i].is_finite(), "nonfinite page rectangle");
    }
    ensure!(
        out[0] < out[2] && out[1] < out[3],
        "page rectangle must be nonempty"
    );
    Ok(out)
}
fn walk_pages(
    doc: &Document,
    id: ObjectId,
    seen: &mut HashSet<ObjectId>,
    pages: &mut Vec<ObjectId>,
    depth: usize,
) -> Result<usize> {
    ensure!(
        depth < 64 && seen.insert(id) && seen.len() <= MAX_PDF_OBJECTS,
        "cyclic or excessive page tree"
    );
    let d = doc.get_dictionary(id)?;
    match d.get(b"Type")?.as_name()? {
        b"Page" => {
            pages.push(id);
            ensure!(pages.len() <= MAX_PDF_PAGES, "PDF exceeds page limit");
            Ok(1)
        }
        b"Pages" => {
            let mut count = 0;
            for child in nav::resolved(doc, d.get(b"Kids")?)?.as_array()? {
                count += walk_pages(doc, child.as_reference()?, seen, pages, depth + 1)?;
            }
            ensure!(
                d.get(b"Count")?.as_i64()? == count as i64,
                "page tree count mismatch; separately repair source first"
            );
            Ok(count)
        }
        _ => bail!("unexpected page tree object"),
    }
}
pub fn page_ids(doc: &Document) -> Result<Vec<ObjectId>> {
    let root = doc.catalog()?.get(b"Pages")?.as_reference()?;
    let mut pages = Vec::new();
    walk_pages(doc, root, &mut HashSet::new(), &mut pages, 0)?;
    ensure!(!pages.is_empty(), "PDF has no pages");
    Ok(pages)
}
pub fn geometry(doc: &Document) -> Result<Vec<PageGeometry>> {
    page_ids(doc)?
        .into_iter()
        .enumerate()
        .map(|(i, id)| {
            let media = rectangle(
                pdf_forms::inherited(doc, id, b"MediaBox")?.context("page missing MediaBox")?,
            )?;
            let crop = pdf_forms::inherited(doc, id, b"CropBox")?
                .map(rectangle)
                .transpose()?
                .unwrap_or(media);
            ensure!(
                crop[0] >= media[0]
                    && crop[1] >= media[1]
                    && crop[2] <= media[2]
                    && crop[3] <= media[3],
                "CropBox must be contained in MediaBox"
            );
            let rotate = pdf_forms::inherited(doc, id, b"Rotate")?
                .map(Object::as_i64)
                .transpose()?
                .unwrap_or(0)
                .rem_euclid(360);
            ensure!(rotate % 90 == 0, "page rotation must be a quarter turn");
            let (w, h) = if rotate % 180 == 0 {
                (crop[2] - crop[0], crop[3] - crop[1])
            } else {
                (crop[3] - crop[1], crop[2] - crop[0])
            };
            Ok(PageGeometry {
                page: i + 1,
                mediabox: media,
                cropbox: crop,
                rect: [0., 0., w, h],
                rotation: rotate,
            })
        })
        .collect()
}
pub fn validate_pdf(path: &Path) -> Result<()> {
    let _ = open_pdf(path, false)?;
    Ok(())
}
pub fn inspect_pdf(source: &Path) -> Result<Value> {
    let d = open_pdf(source, false)?;
    let xfa = d
        .catalog()?
        .get(b"AcroForm")
        .ok()
        .map(|o| nav::resolved(&d, o).and_then(|v| Ok(v.as_dict()?.has(b"XFA"))))
        .transpose()?
        .unwrap_or(false);
    Ok(
        json!({"format":"pdf","pages":geometry(&d)?,"fields":pdf_forms::inventory(&d)?,"signature_bearing":pdf_forms::signature_present(&d)?,"xfa":xfa,"embedded_file_count":embedded_count(&d)?,"validation":"parsed-structure","visual_review":"not-performed"}),
    )
}
fn embedded_count(doc: &Document) -> Result<usize> {
    let mut count = 0;
    for o in doc.objects.values() {
        if let Ok(d) = o.as_dict()
            && d.get(b"Type").and_then(Object::as_name).ok() == Some(b"Filespec")
            && d.has(b"EF")
        {
            count += 1;
        }
    }
    Ok(count)
}
fn materialize_page_inheritance(doc: &mut Document, ids: &[ObjectId]) -> Result<()> {
    for id in ids {
        for key in [b"MediaBox".as_slice(), b"CropBox", b"Rotate", b"Resources"] {
            if let Some(value) = pdf_forms::inherited(doc, *id, key)?.cloned() {
                doc.get_object_mut(*id)?
                    .as_dict_mut()?
                    .set(key.to_vec(), value);
            }
        }
    }
    Ok(())
}
/// Copy every source once, preserving the identities of shared fonts and images.
pub fn merge_pdfs(sources: &[PathBuf], destination: &Path) -> Result<()> {
    merge_pdfs_observed(sources, destination, |_, _| Ok(()))
}
pub fn merge_pdfs_observed(
    sources: &[PathBuf],
    destination: &Path,
    observer: impl FnMut(PdfBoundary, &Path) -> Result<()>,
) -> Result<()> {
    ensure!(
        (1..=1000).contains(&sources.len()),
        "merge needs 1..1000 input PDFs"
    );
    publication::validate_destination(destination, sources)?;
    let mut docs = Vec::new();
    let mut expected = Vec::new();
    let mut links = Vec::new();
    let mut outlines = Vec::new();
    for source in sources {
        let doc = open_pdf(source, true)?;
        ensure!(
            pdf_forms::widgets(&doc)?.is_empty()
                && !doc.catalog()?.has(b"AcroForm")
                && embedded_count(&doc)? == 0,
            "merge does not support forms or attachments"
        );
        let ids = page_ids(&doc)?;
        let offset = expected.len();
        links.extend(nav::links(&doc, 0, ids.len() - 1, offset)?);
        outlines.extend(nav::outlines(&doc, offset)?.0);
        expected.extend(geometry(&doc)?);
        docs.push(doc);
    }
    ensure!(
        expected.len() <= MAX_PDF_PAGES,
        "merged PDF exceeds page limit"
    );
    for (i, p) in expected.iter_mut().enumerate() {
        p.page = i + 1;
    }
    let mut result = Document::with_version("1.7");
    let pages_root = result.new_object_id();
    let catalog = result.new_object_id();
    let mut kids = Vec::new();
    let mut top_outlines = Vec::new();
    for mut doc in docs {
        let ids = page_ids(&doc)?;
        materialize_page_inheritance(&mut doc, &ids)?;
        doc.renumber_objects_with(result.max_id + 1);
        result.max_id = doc.max_id;
        let ids = page_ids(&doc)?;
        top_outlines.extend(nav::outlines(&doc, 0)?.1);
        for id in ids {
            doc.get_object_mut(id)?
                .as_dict_mut()?
                .set("Parent", pages_root);
            kids.push(Object::Reference(id));
        }
        result.objects.extend(doc.objects);
    }
    result.objects.insert(
        pages_root,
        Object::Dictionary(
            dictionary! {"Type"=>"Pages","Kids"=>kids,"Count"=>expected.len() as i64},
        ),
    );
    let mut root = dictionary! {"Type"=>"Catalog","Pages"=>pages_root};
    if !top_outlines.is_empty() {
        let outline_root = result.new_object_id();
        for (i, id) in top_outlines.iter().enumerate() {
            let d = result.get_object_mut(*id)?.as_dict_mut()?;
            d.set("Parent", outline_root);
            d.remove(b"Prev");
            d.remove(b"Next");
            if i > 0 {
                d.set("Prev", top_outlines[i - 1]);
            }
            if i + 1 < top_outlines.len() {
                d.set("Next", top_outlines[i + 1]);
            }
        }
        result.objects.insert(outline_root,Object::Dictionary(dictionary!{"Type"=>"Outlines","First"=>top_outlines[0],"Last"=>*top_outlines.last().unwrap(),"Count"=>outlines.len() as i64}));
        root.set("Outlines", outline_root);
    }
    result.objects.insert(catalog, Object::Dictionary(root));
    result.trailer.set("Root", catalog);
    result.trailer.remove(b"Info");
    save_document_observed(
        &mut result,
        destination,
        sources,
        &expected,
        |doc| {
            ensure!(
                nav::links(doc, 0, expected.len() - 1, 0)? == links,
                "staged PDF changed page links"
            );
            ensure!(
                nav::outlines(doc, 0)?.0 == outlines,
                "staged PDF changed outlines"
            );
            Ok(())
        },
        observer,
    )
}
pub fn extract_pages(source: &Path, destination: &Path, first: usize, last: usize) -> Result<()> {
    extract_pages_observed(
        source,
        destination,
        first,
        last,
        AdmissionLimits::default(),
        |_, _| Ok(()),
    )
}
pub fn extract_pages_observed(
    source: &Path,
    destination: &Path,
    first: usize,
    last: usize,
    limits: AdmissionLimits,
    observer: impl FnMut(PdfBoundary, &Path) -> Result<()>,
) -> Result<()> {
    ensure!(
        first > 0 && last >= first,
        "page range must be positive and ordered"
    );
    let protected = [source.to_owned()];
    publication::validate_destination(destination, &protected)?;
    let mut doc = open_pdf_with_limits(source, true, limits)?;
    let all = page_ids(&doc)?;
    ensure!(last <= all.len(), "requested range exceeds source pages");
    let expected_links = nav::links(&doc, first - 1, last - 1, 0)?;
    let mut expected = geometry(&doc)?[first - 1..last].to_vec();
    for (i, p) in expected.iter_mut().enumerate() {
        p.page = i + 1;
    }
    let selected = all[first - 1..last].to_vec();
    materialize_page_inheritance(&mut doc, &selected)?;
    let root = doc.new_object_id();
    for id in &selected {
        doc.get_object_mut(*id)?.as_dict_mut()?.set("Parent", root);
    }
    doc.objects.insert(root,Object::Dictionary(dictionary!{"Type"=>"Pages","Kids"=>selected.iter().copied().map(Object::Reference).collect::<Vec<_>>(),"Count"=>selected.len() as i64}));
    let catalog = doc.catalog_mut()?;
    catalog.set("Pages", root);
    catalog.remove(b"Outlines");
    catalog.remove(b"PageLabels");
    catalog.remove(b"OpenAction");
    catalog.remove(b"AA");
    doc.prune_objects();
    save_document_observed(
        &mut doc,
        destination,
        &protected,
        &expected,
        |d| {
            ensure!(
                nav::links(d, 0, selected.len() - 1, 0)? == expected_links,
                "staged extraction changed page links"
            );
            Ok(())
        },
        observer,
    )
}
pub fn fill_pdf(
    source: &Path,
    destination: &Path,
    values: &serde_json::Map<String, Value>,
    additional_sources: &[PathBuf],
) -> Result<()> {
    fill_pdf_observed(source, destination, values, additional_sources, |_, _| {
        Ok(())
    })
}
pub fn fill_pdf_observed(
    source: &Path,
    destination: &Path,
    values: &serde_json::Map<String, Value>,
    additional_sources: &[PathBuf],
    observer: impl FnMut(PdfBoundary, &Path) -> Result<()>,
) -> Result<()> {
    let mut protected = vec![source.to_owned()];
    protected.extend_from_slice(additional_sources);
    publication::validate_destination(destination, &protected)?;
    let mut doc = open_pdf(source, true)?;
    let expected = geometry(&doc)?;
    let plan = pdf_forms::plan_fill(&doc, values)?;
    pdf_forms::apply_fill(&mut doc, &plan)?;
    save_document_observed(
        &mut doc,
        destination,
        &protected,
        &expected,
        |d| pdf_forms::verify_fill(d, &plan),
        observer,
    )
}
pub fn page_text(doc: &Document, page: usize) -> Result<String> {
    let ids = page_ids(doc)?;
    ensure!(page > 0 && page <= ids.len(), "page exceeds document range");
    crate::pdf_content::page_text(doc, ids[page - 1])
}
pub fn pdf_text(source: &Path) -> Result<String> {
    let doc = open_pdf(source, false)?;
    let mut result = String::new();
    for n in 1..=page_ids(&doc)?.len() {
        result.push_str(&page_text(&doc, n)?);
        result.push('\n');
        ensure!(result.len() <= 64 * 1024 * 1024, "PDF text exceeds 64 MiB");
    }
    Ok(result)
}
/// Decoded Unicode in content-stream order, without geometric/bidi recovery.
pub fn stored_pdf_text(source: &Path) -> Result<String> {
    let doc = open_pdf(source, false)?;
    let mut result = String::new();
    for id in page_ids(&doc)? {
        result.push_str(&crate::pdf_content::stored_page_text(&doc, id)?);
        result.push('\n');
        ensure!(result.len() <= 64 * 1024 * 1024, "PDF text exceeds 64 MiB");
    }
    Ok(result)
}
pub fn extract_text(source: &Path, destination: &Path) -> Result<()> {
    let d = open_pdf(source, false)?;
    let mut pages = Vec::new();
    let mut text_bytes = 0usize;
    for g in geometry(&d)? {
        let text = page_text(&d, g.page)?;
        let source_stream_text =
            crate::pdf_content::stored_page_text(&d, page_ids(&d)?[g.page - 1])?;
        text_bytes = text_bytes
            .saturating_add(text.len())
            .saturating_add(source_stream_text.len());
        ensure!(
            text_bytes <= 128 * 1024 * 1024,
            "PDF text report exceeds 128 MiB"
        );
        pages.push(json!({"page":g.page,"rect":g.rect,"text":text,"source_stream_text":source_stream_text}));
    }
    write_report(
        &json!({"format":"pdf-text","order":"geometry-unicode-bidi","actual_text":"authoritative","pages":pages,"semantic_completeness":"not-verified"}),
        destination,
        &[source.to_owned()],
    )
}

pub fn render_page(source: &Path, page: usize, dpi: u32, destination: &Path) -> Result<()> {
    let d = open_pdf(source, false)?;
    let g = geometry(&d)?;
    ensure!(page > 0 && page <= g.len(), "render page exceeds document");
    render_region(source, page, dpi, g[page - 1].rect, destination)
}
pub fn render_region(
    source: &Path,
    page: usize,
    dpi: u32,
    clip: [f64; 4],
    destination: &Path,
) -> Result<()> {
    ensure!(dpi > 0, "render density must be positive");
    let d = open_pdf(source, false)?;
    let g = geometry(&d)?;
    ensure!(page > 0 && page <= g.len(), "render page exceeds document");
    let r = g[page - 1].rect;
    ensure!(
        clip.iter().all(|n| n.is_finite())
            && clip[0] >= r[0]
            && clip[1] >= r[1]
            && clip[2] <= r[2]
            && clip[3] <= r[3]
            && clip[0] < clip[2]
            && clip[1] < clip[3],
        "crop rectangle must be finite, nonempty and inside page"
    );
    let scale = f64::from(dpi) / 72.;
    let x = (clip[0] * scale).floor() as u64;
    let y = (clip[1] * scale).floor() as u64;
    let w = (clip[2] * scale).ceil() as u64 - x;
    let h = (clip[3] * scale).ceil() as u64 - y;
    ensure!(
        w.checked_mul(h).is_some_and(|n| n <= 50_000_000),
        "crop exceeds 50 million pixels; no downsampling performed"
    );
    let destination = publication::validate_destination(destination, &[source.to_owned()])?;
    let parent = destination
        .parent()
        .context("render destination parent missing")?;
    fs::create_dir_all(parent)?;
    let work = tempfile::Builder::new()
        .prefix(".revayat-raster-")
        .tempdir_in(parent)?;
    let prefix = work.path().join("page");
    let mut spec = crate::runtime::CommandSpec::new("pdftoppm");
    spec.timeout = Duration::from_secs(120);
    spec.args = vec![
        "-f".into(),
        page.to_string().into(),
        "-l".into(),
        page.to_string().into(),
        "-singlefile".into(),
        "-png".into(),
        "-cropbox".into(),
        "-r".into(),
        dpi.to_string().into(),
        "-x".into(),
        x.to_string().into(),
        "-y".into(),
        y.to_string().into(),
        "-W".into(),
        w.to_string().into(),
        "-H".into(),
        h.to_string().into(),
        source.as_os_str().to_owned(),
        prefix.as_os_str().to_owned(),
    ];
    let output = crate::runtime::run(&spec)?;
    ensure!(
        output.success(),
        "Poppler raster backend failed: {}",
        output.stderr_text()
    );
    let stage = prefix.with_extension("png");
    let image = image::open(&stage)?;
    ensure!(
        u64::from(image.width()) == w && u64::from(image.height()) == h,
        "raster backend changed requested crop dimensions"
    );
    publication::publish_files(
        &[(stage, destination)],
        &[source.to_owned()],
        Some(MAX_PDF_BYTES),
    )
}
pub fn render_sample_set(source: &Path, output_prefix: &Path) -> Result<Vec<PathBuf>> {
    let d = open_pdf(source, false)?;
    let n = page_ids(&d)?.len();
    let mut pages = vec![1, n.div_ceil(2), n];
    pages.sort_unstable();
    pages.dedup();
    let parent = output_prefix
        .parent()
        .context("sample output parent missing")?;
    let protected = [source.to_owned()];
    let mut outputs = Vec::new();
    for page in pages {
        let output = output_prefix.with_file_name(format!(
            "{}-{page}.png",
            output_prefix
                .file_name()
                .context("output prefix missing")?
                .to_string_lossy()
        ));
        publication::validate_destination(&output, &protected)?;
        outputs.push((page, output));
    }
    fs::create_dir_all(parent)?;
    let work = tempfile::Builder::new()
        .prefix(".revayat-samples-")
        .tempdir_in(parent)?;
    let mut entries = Vec::new();
    let mut result = Vec::new();
    for (page, destination) in outputs {
        let stage = work.path().join(format!("page-{page}.png"));
        render_page(source, page, 100, &stage)?;
        entries.push((stage, destination.clone()));
        result.push(destination);
    }
    publication::publish_files(&entries, &protected, Some(MAX_PDF_BYTES))?;
    Ok(result)
}

#[derive(Parser)]
#[command(name = "document-pdf")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Inspect {
        source: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Text {
        source: PathBuf,
        output: PathBuf,
    },
    Tables {
        source: PathBuf,
        output: PathBuf,
    },
    Images {
        source: PathBuf,
        output: PathBuf,
    },
    Merge {
        output: PathBuf,
        #[arg(required = true)]
        sources: Vec<PathBuf>,
    },
    Fill {
        source: PathBuf,
        output: PathBuf,
        #[arg(long)]
        fields: PathBuf,
    },
    Ocr {
        source: PathBuf,
        output: PathBuf,
        #[arg(long, default_value = "eng")]
        language: String,
        #[arg(long, default_value_t = 300)]
        dpi: u32,
        #[arg(long = "page-timeout", alias = "timeout", default_value_t = 120)]
        timeout: u64,
    },
}
pub fn cli(args: &[String]) -> Result<i32> {
    let a = Args::try_parse_from(
        std::iter::once("document-pdf".to_owned()).chain(args.iter().cloned()),
    )?;
    match a.command {
        Commands::Inspect { source, output } => {
            let v = inspect_pdf(&source)?;
            if let Some(p) = output {
                write_report(&v, &p, &[source])?;
            } else {
                println!("{}", serde_json::to_string_pretty(&v)?);
            }
        }
        Commands::Text { source, output } => extract_text(&source, &output)?,
        Commands::Tables { source, output } => {
            crate::pdf_content::extract_tables(&source, &output)?
        }
        Commands::Images { source, output } => {
            crate::pdf_content::extract_images(&source, &output)?
        }
        Commands::Merge { sources, output } => merge_pdfs(&sources, &output)?,
        Commands::Fill {
            source,
            output,
            fields,
        } => {
            ensure!(
                fs::metadata(&fields)?.len() <= 8 * 1024 * 1024,
                "fields JSON exceeds size limit"
            );
            let values: crate::pdf_content::UniqueFields =
                serde_json::from_slice(&fs::read(&fields)?)?;
            fill_pdf(&source, &output, &values.0, &[fields])?;
        }
        Commands::Ocr {
            source,
            output,
            language,
            dpi,
            timeout,
        } => crate::pdf_ocr::ocr_pdf(&source, &output, &language, dpi, timeout)?,
    }
    Ok(0)
}
#[derive(Parser)]
#[command(name = "extract-pdf-pages")]
struct PagesArgs {
    source: PathBuf,
    destination: PathBuf,
    range: Option<String>,
    #[arg(long = "from")]
    first: Option<usize>,
    #[arg(long = "to")]
    last: Option<usize>,
}
pub fn pages_cli(args: &[String]) -> Result<i32> {
    let a = PagesArgs::try_parse_from(
        std::iter::once("extract-pdf-pages".to_owned()).chain(args.iter().cloned()),
    )?;
    let (first, last) = if let Some(range) = a.range {
        ensure!(
            a.first.is_none() && a.last.is_none(),
            "choose range or --from/--to"
        );
        let r = regex::Regex::new(r"^([1-9][0-9]*)(?:-([1-9][0-9]*))?$")?;
        let c = r
            .captures(&range)
            .context("range must contain positive integers")?;
        let first = c[1].parse()?;
        let last = c
            .get(2)
            .map(|m| m.as_str().parse())
            .transpose()?
            .unwrap_or(first);
        (first, last)
    } else {
        (
            a.first.context("need --from")?,
            a.last.context("need --to")?,
        )
    };
    extract_pages(&a.source, &a.destination, first, last)?;
    Ok(0)
}
