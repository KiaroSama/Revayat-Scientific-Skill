//! Strict reviewed crop maps, pairwise components and native-density extraction.
use crate::{
    pdf,
    pdf_content::{self, ImagePlacement},
    publication,
};
use anyhow::{Context, Result, ensure};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::{Path, PathBuf},
};
pub type Rect = [f64; 4];
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Figure {
    pub id: String,
    pub rectangle: Option<Rect>,
}
pub fn load_map(path: &Path) -> Result<BTreeMap<usize, Vec<Figure>>> {
    crate::images::plain_path(path)?;
    let raw = fs::read_to_string(path)?;
    let text = raw.trim_start_matches('\u{feff}');
    ensure!(!text.trim().is_empty(), "crop map empty");
    ensure!(
        text.lines().all(|l| !l.trim().is_empty()),
        "crop map empty row"
    );
    let delimiter = if text.lines().next().unwrap().contains('\t') {
        b'\t'
    } else {
        b','
    };
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(delimiter)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut by_page = BTreeMap::<usize, Vec<Figure>>::new();
    let mut seen = HashSet::new();
    let mut width = None;
    let mut explicit_header = false;
    let page_pattern = regex::Regex::new(r"^[1-9][0-9]*$")?;
    for (index, row) in reader.records().enumerate() {
        let row = row?;
        let cells: Vec<_> = row.iter().map(str::trim).collect();
        ensure!(!cells.is_empty(), "empty crop map row");
        if index == 0 && cells[0] == "figure_id" {
            ensure!(
                cells == ["figure_id", "pdf_page"]
                    || cells == ["figure_id", "printed", "pdf_page"]
                    || cells == ["figure_id", "pdf_page", "x0", "y0", "x1", "y1"],
                "unsupported crop map header"
            );
            width = Some(cells.len());
            explicit_header = cells.len() == 6;
            continue;
        }
        let width = *width.get_or_insert(cells.len());
        ensure!(
            cells.len() == width && [2, 3, 6].contains(&width) && (width != 6 || explicit_header),
            "crop map invalid column count"
        );
        let id = cells[0];
        ensure!(
            !id.is_empty()
                && !id.ends_with(['.', ' '])
                && id != "."
                && id != ".."
                && !id
                    .chars()
                    .any(|c| c.is_control() || "/\\:*?\"<>|".contains(c)),
            "unsafe figure_id"
        );
        ensure!(seen.insert(id.to_lowercase()), "duplicate figure_id");
        let page = if width == 6 {
            cells[1]
        } else {
            cells[width - 1]
        };
        ensure!(
            page_pattern.is_match(page),
            "pdf_page must be positive integer"
        );
        let page = page.parse()?;
        let rectangle = if width == 6 {
            let mut rect = [0.; 4];
            for (i, value) in cells[2..].iter().enumerate() {
                rect[i] = value.parse::<f64>()?;
            }
            ensure!(valid(rect), "invalid crop rectangle");
            Some(rect)
        } else {
            None
        };
        by_page.entry(page).or_default().push(Figure {
            id: id.to_owned(),
            rectangle,
        });
    }
    ensure!(!by_page.is_empty(), "crop map contains no figures");
    Ok(by_page)
}
pub fn valid(r: Rect) -> bool {
    r.iter().all(|n| n.is_finite()) && r[0] < r[2] && r[1] < r[3]
}
fn adjacent(a: Rect, b: Rect, gap: f64) -> bool {
    a[0] <= b[2] + gap && b[0] <= a[2] + gap && a[1] <= b[3] + gap && b[1] <= a[3] + gap
}
pub fn cluster(rects: &[Rect], gap: f64) -> Result<Vec<Rect>> {
    ensure!(
        gap.is_finite() && gap >= 0. && rects.iter().all(|r| valid(*r)),
        "invalid artwork rectangle or cluster gap"
    );
    let mut items = rects.to_vec();
    let mut out = Vec::new();
    while let Some(start) = items.pop() {
        let mut group = vec![start];
        let mut cursor = 0;
        while cursor < group.len() {
            let current = group[cursor];
            for i in (0..items.len()).rev() {
                if adjacent(current, items[i], gap) {
                    group.push(items.swap_remove(i));
                }
            }
            cursor += 1;
        }
        let mut r = group[0];
        for p in group {
            r = [
                r[0].min(p[0]),
                r[1].min(p[1]),
                r[2].max(p[2]),
                r[3].max(p[3]),
            ];
        }
        if r[2] - r[0] >= 40. || r[3] - r[1] >= 24. {
            out.push(r);
        }
    }
    out.sort_by(|a, b| a[1].total_cmp(&b[1]).then(a[0].total_cmp(&b[0])));
    Ok(out)
}
pub fn pick_clusters(clusters: &[Rect], n: usize) -> Result<Vec<Rect>> {
    ensure!(
        n > 0 && clusters.len() == n,
        "ambiguous figure boundaries; supply reviewed x0,y0,x1,y1 map columns"
    );
    let mut v = clusters.to_vec();
    v.sort_by(|a, b| a[1].total_cmp(&b[1]));
    Ok(v)
}
pub fn pad_clip(page: Rect, r: Rect, pad: f64, slack: f64) -> Rect {
    [
        (r[0] - pad).max(page[0]),
        (r[1] - pad).max(page[1]),
        (r[2] + pad + slack).min(page[2]),
        (r[3] + pad).min(page[3]),
    ]
}
pub fn crop_dpi(images: &[ImagePlacement], clip: Rect, minimum: u32) -> Result<u32> {
    let mut density = f64::from(minimum);
    for image in images {
        if image.bbox[0] >= clip[2]
            || image.bbox[2] <= clip[0]
            || image.bbox[1] >= clip[3]
            || image.bbox[3] <= clip[1]
        {
            continue;
        }
        let t = image.transform;
        let w = t[0].hypot(t[1]);
        let h = t[2].hypot(t[3]);
        ensure!(w > 0. && h > 0., "image invalid placement dimensions");
        density = density
            .max(72. * f64::from(image.width) / w)
            .max(72. * f64::from(image.height) / h);
    }
    ensure!(
        density.is_finite() && density > 0. && density <= f64::from(u32::MAX),
        "image invalid sampling density"
    );
    let dpi = density.ceil() as u32;
    let w = ((clip[2] - clip[0]) * f64::from(dpi) / 72.).ceil() + 2.;
    let h = ((clip[3] - clip[1]) * f64::from(dpi) / 72.).ceil() + 2.;
    ensure!(
        w * h <= 50_000_000.,
        "crop exceeds 50 million pixels; preserve original asset instead of downsampling"
    );
    Ok(dpi)
}
#[derive(Parser)]
#[command(name = "crop-source-figures")]
pub struct Args {
    pub pdf: PathBuf,
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long)]
    pub map: Option<PathBuf>,
    #[arg(long)]
    pub cover: bool,
    #[arg(long, default_value_t = 1)]
    pub cover_page: usize,
    #[arg(long, default_value_t = 0)]
    pub author_page: usize,
    #[arg(long, default_value_t = 300)]
    pub dpi: u32,
}
pub fn crop_document(args: &Args) -> Result<usize> {
    ensure!(
        (72..=2400).contains(&args.dpi),
        "--dpi must be between 72 and 2400"
    );
    ensure!(
        args.map.is_some() || args.cover || args.author_page > 0,
        "need --map, --cover or --author-page"
    );
    let doc = pdf::open_pdf(&args.pdf, false)?;
    let geometry = pdf::geometry(&doc)?;
    let by_page = args
        .map
        .as_ref()
        .map(|p| load_map(p))
        .transpose()?
        .unwrap_or_default();
    let mut protected = vec![args.pdf.clone()];
    protected.extend(args.map.clone());
    let mut planned = Vec::new();
    for (number, figures) in by_page {
        ensure!(
            number > 0 && number <= geometry.len(),
            "requested PDF page out of range"
        );
        let page = geometry[number - 1].rect;
        let (rects, images) = pdf_content::artwork(&doc, number)?;
        let explicit = figures.iter().filter(|f| f.rectangle.is_some()).count();
        ensure!(
            explicit == 0 || explicit == figures.len(),
            "one page cannot mix automatic and explicit crop rectangles"
        );
        let rectangles = if explicit > 0 {
            figures.iter().map(|f| f.rectangle.unwrap()).collect()
        } else {
            pick_clusters(&cluster(&rects, 28.)?, figures.len())?
                .into_iter()
                .map(|r| pad_clip(page, r, 12., 72.))
                .collect::<Vec<_>>()
        };
        for (figure, clip) in figures.into_iter().zip(rectangles) {
            ensure!(
                valid(clip)
                    && clip[0] >= page[0]
                    && clip[1] >= page[1]
                    && clip[2] <= page[2]
                    && clip[3] <= page[3],
                "reviewed rectangle must be entirely inside page"
            );
            let dpi = crop_dpi(&images, clip, args.dpi)?;
            planned.push((
                number,
                clip,
                dpi,
                args.out.join(format!("fig-{}.png", figure.id)),
            ));
        }
    }
    for (number, name, is_cover) in [
        (
            args.cover.then_some(args.cover_page),
            "cover-illustration.png",
            true,
        ),
        (
            (args.author_page > 0).then_some(args.author_page),
            "author.png",
            false,
        ),
    ] {
        if let Some(number) = number {
            ensure!(
                number > 0 && number <= geometry.len(),
                "requested PDF page out of range"
            );
            let page = geometry[number - 1].rect;
            let (_, images) = pdf_content::artwork(&doc, number)?;
            let area = (page[2] - page[0]) * (page[3] - page[1]);
            let candidates: Vec<_> = images
                .iter()
                .filter(|i| {
                    let w = i.bbox[2] - i.bbox[0];
                    let h = i.bbox[3] - i.bbox[1];
                    if is_cover {
                        w * h >= 80. && w * h <= 0.55 * area
                    } else {
                        w >= 24. && h >= 24. && w * h <= 0.5 * area
                    }
                })
                .collect();
            ensure!(
                candidates.len() == 1,
                "ambiguous special artwork; use reviewed crop-map rectangle"
            );
            let r = candidates[0].bbox;
            let mut clip = pad_clip(page, r, if is_cover { 4. } else { 2. }, 72.);
            if !is_cover {
                clip[2] = (r[2] + 4.).min(page[2]);
            }
            let dpi = crop_dpi(&images, clip, args.dpi)?;
            planned.push((number, clip, dpi, args.out.join(name)));
        }
    }
    let mut names = HashSet::new();
    for (_, _, _, destination) in &planned {
        publication::validate_destination(destination, &protected)?;
        ensure!(
            names.insert(destination.to_string_lossy().to_lowercase()),
            "crop destination collision"
        );
        if args.out.exists() {
            for entry in fs::read_dir(&args.out)? {
                let p = entry?.path();
                ensure!(
                    p == *destination
                        || p.file_name().unwrap().to_string_lossy().to_lowercase()
                            != destination
                                .file_name()
                                .unwrap()
                                .to_string_lossy()
                                .to_lowercase(),
                    "case-insensitive crop destination collision"
                );
            }
        }
    }
    fs::create_dir_all(&args.out)?;
    let work = tempfile::Builder::new()
        .prefix(".revayat-crops-")
        .tempdir_in(&args.out)?;
    let mut entries = Vec::new();
    for (number, clip, dpi, destination) in &planned {
        let stage = work
            .path()
            .join(destination.file_name().context("crop filename missing")?);
        pdf::render_region(&args.pdf, *number, *dpi, *clip, &stage)?;
        entries.push((stage, destination.clone()));
    }
    publication::publish_files(&entries, &protected, Some(pdf::MAX_PDF_BYTES))?;
    Ok(entries.len())
}
pub fn cli(args: &[String]) -> Result<i32> {
    let a = Args::try_parse_from(
        std::iter::once("crop-source-figures".to_owned()).chain(args.iter().cloned()),
    )?;
    let n = crop_document(&a)?;
    println!("crop-source-figures: published={n}");
    Ok(0)
}
