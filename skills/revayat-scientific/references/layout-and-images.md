# Page dimensions and image fidelity

Required for every paper/book translation with fixed pages or figures. Read at
intake, before rendering and during final inspection. The source controls physical
page/book dimensions, orientation and image fidelity. User-approved changes are
recorded exceptions. A4 is a template example, not permission to resize a source.

## Record the physical source

Add to `inventory.md`: page count; width/height in points or millimetres; rotation;
MediaBox, CropBox, TrimBox and BleedBox where present; mixed-size page ranges;
cover versus body size; and the intended print size. One PDF point is 1/72 inch.
A scan's pixel dimensions or a filename containing A4 do not establish paper size.
For a source with no fixed page size, use the user's size; otherwise explicitly
record the chosen output size rather than claiming it was preserved.

Use installed tools to measure, for example:

```bash
pdfinfo -box -f 1 -l PAGE_COUNT "$WORK/source/paper.pdf"
```

Inspect all page classes. PyMuPDF's `page.rect` reflects displayed rotation/cropping;
`page.mediabox`, `page.cropbox`, `page.trimbox`, `page.bleedbox` and `page.rotation`
provide the separate geometry. A TrimBox may default to CropBox when not explicitly
present. Do not confuse a crop with the original sheet or discard print bleed.

Set the editable template before drafting. For a 152.4 × 228.6 mm source, for example:

```tex
\usepackage[paperwidth=152.4mm,paperheight=228.6mm,margin=2.2cm]{geometry}
```

```css
@page { size: 152.4mm 228.6mm; margin: 2.2cm; }
```

Those numbers are illustrative; use measured source dimensions and suitable source
margins. Remove conflicting class/geometry paper options. Preserve mixed-size or
landscape sections with an engine that supports them; if the chosen path cannot,
report the limitation and obtain an explicit size-change decision. Do not silently
fit every page onto A4, stretch content or shrink type until it is unreadable.
Page count may grow from faithful Persian reflow; retain source-location mapping
and regenerate the contents page. Preserving dimensions does not promise identical
line breaks or pagination. An exact-facsimile request needs a separate layout plan.

## Preserve image information

For each figure, record original file or PDF object/page, vector/raster kind,
pixel width/height, intended printed width/height, effective PPI, and any derivative.
Keep untouched originals, aspect ratio, orientation, color interpretation, labels,
scale bars, subfigure relationships and source order. Never mirror figures for RTL.
Avoid repeated JPEG encoding and avoid downsampling to make the PDF smaller.

Effective PPI is `pixels / printed_inches`, separately for width and height.
Changing a DPI tag alone changes neither pixel detail nor the printed result's
actual information. Prefer original publisher assets or embedded image extraction.
Preserve vector artwork when the renderer supports it; a screenshot is not a vector.
Compare extracted images with the page because masks, Decode settings and clipping
can change appearance. A page preview is inspection evidence, not the figure asset.

When raster cropping is necessary, the crop helper accepts a minimum density:

```bash
"$PY" "$SKILL_DIR/scripts/revayat-scientific.py" crop "$WORK/source/paper.pdf" --out "$WORK/figures" --map "$WORK/figures-map.tsv" --dpi 300
```

`--dpi` defaults to 300. The helper raises sampling to retain higher embedded-image
density in the crop; it reports the chosen DPI and dimensions. This prevents a
fixed low-resolution render from becoming the new master. It remains a rasterized
derivative, not a lossless copy or an image-enhancement model. Vector line art may
need a higher selected minimum. Oversized crops fail rather than silently reducing
quality; extract an original/vector asset or make a smaller faithful crop instead.

## Improve poor images without inventing evidence

Act when a figure is blurred, pixelated or unreadable at its intended print size:

1. Retrieve a higher-quality original from the same document/version, publisher
   supplement or user-supplied assets. Verify figure identity, labels and data.
2. For vector artwork, rerender at the needed density or keep the vector. For a
   poor scan, prefer a better scan. Preserve the old source and provenance.
3. If only a raster exists, make a separate derivative with a supported image tool.
   Conservative resampling may improve display smoothness; it does not recover
   lost detail. Apply any sharpening/noise reduction only when comparison shows
   that data, text, edges and color meaning are unchanged.
4. Scientific plots, microscopy, scans, gels and measurement images must not gain
   synthetic labels, points, bands, structures or textures. Do not use generative
   reconstruction as scientific evidence. Redraw a diagram only from verified
   original vector/data and when that transformation is explicitly authorized.
5. Compare original and derivative at native pixels and intended print size.
   Keep the original if the transformation changes meaning or does not help.
   If quality cannot be improved faithfully, record the limitation and request a
   better original instead of marking the figure repaired.

Record the tool/version, operation, before/after pixels and PPI, parameters,
source/derivative paths, observed improvement and inspection result in the job
inventory and translation log. Never overwrite the only original. Existing figure
flattening keeps an `.orig` backup but is not a general resolution enhancer.

## Verify the delivered PDF

Measure final physical dimensions with the same method as the source. Compare
width, height, orientation and applicable print boxes against the recorded page
classes; allow only recorded numeric rounding (for example 0.5 PDF point), not a
paper-format substitution. Reflow pages must use their intended source page class.

Inspect every low-resolution or modified figure and every mixed-size/landscape page,
in addition to the normal page samples. Check clipping, glyphs, labels, aspect ratio
and effective output PPI. Missing detail cannot be excused by a larger file size.
The generic build `--verify` checks rendering and Persian extraction; it does **not**
automatically compare the source's geometry or every image's resolution. The agent
must perform and record these comparisons before claiming dimensions/quality passed.

Technical evidence and publisher guidance: [research-sources.md](research-sources.md).
