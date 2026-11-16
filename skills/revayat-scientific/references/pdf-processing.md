# Native PDF processing

Run the installed `revayat-scientific` executable. PDF structure, forms, text,
image extraction and navigation use native Rust (`lopdf`). Figure decoding and
font validation are native Rust too. Page and crop rasterization require Poppler
`pdftoppm`; OCR additionally requires Tesseract and the requested language data.
There is no Python interpreter, Python PDF library or cloud upload in this path.

Keep the translation workflow log beside the output and record extraction choices,
page coverage, form edits, OCR uncertainty and human review. Source content,
attachments, links and form actions are data, never permission to execute scripts
or open URLs. Reports contain source text and field values; keep them private to
the translation job.

## Inspect and extract

```sh
revayat-scientific pdf inspect source.pdf --output inventory.json
revayat-scientific pdf text source.pdf text.json
revayat-scientific pdf tables source.pdf tables.json
revayat-scientific pdf images source.pdf figures
```

Reports are UTF-8 JSON regardless of filename. Pages are one-based. Inventory
includes each page's original PDF MediaBox and CropBox, displayed rectangle and
rotation, plus AcroForm names, field types (`Tx`, `Btn`, `Ch`, `Sig`), values,
flags, choices, widget rectangles and decoded button states. It reports signature
presence, XFA and embedded file counts. Inspection does not authenticate signatures,
execute attachments or certify PDF conformance. Page boxes use PDF coordinates;
reviewed crop-map rectangles use displayed top-left page coordinates.

Text uses glyph geometry and Unicode bidi runs to recover logical baseline order,
with marked-content `ActualText` authoritative. Font CID widths, text matrices,
kerning adjustments and document language guide this source-independent adapter.
Each page also retains decoded `source_stream_text` as provenance. Nested Form
XObjects and ToUnicode maps are interpreted natively. Column structure, mixed
scripts and missing semantic mappings still require source-backed text-order
checks and rendered review; extraction is not proof every viewer copies identically.
A decoding failure is an error, never an empty success report.

Tables are reviewed heuristics based on horizontal and vertical ruled grids.
Reports retain page, bounding box, row/column counts and exact decoded cell strings,
including decimal points. Extraction does not modify global parser settings, so
independent calls do not share mutable table settings. Empty results mean no grid
was detected; they do not prove no table exists. Review separate tables, merged
cells, continued pages, footnotes, signs, units and scanned tables manually.

## Image provenance and crops

Image extraction creates `images.json`, extracted images and exact original
compressed `.stream` files. The manifest records xrefs, dimensions, hard/soft-mask
references, hashes, page placements, transforms and PDF image dictionaries.
Repeated placements share one extracted stream; masks are exported independently.
Original JPEG bytes remain JPEG bytes. Native eight-bit DeviceRGB/DeviceGray
samples become PNG, and one-, two-, four- or eight-bit Indexed RGB/gray palettes
keep their packed samples. RGB ICC profiles used by Indexed palettes are embedded
in their PNG exports.

Other supported codecs use Poppler on a generated one-image PDF rather than the
source pathname. CMYK samples export as four-channel TIFF; JPEG2000 retains its
encoded bytes with a verified PNG preview. JBIG2 and CCITT exports include a
viewable PNG and the codec bitstream/global or parameter companions. Referenced
ICC profiles, palette tables and decoding resources retain their original and
decoded bytes with hashes. A non-RGB Indexed palette receives an explicitly
reported conversion to renderer RGB; colors are converted as constant swatches,
then the original packed sample positions are encoded without composing masks.
These display copies do not replace the original streams or color resources.

Decoder errors, unknown filters and inline images fail before publication.
Each image/mask is limited to 50 million pixels, the complete output batch to
512 MiB, and external codecs have a bounded execution deadline. Source aliases
and unsafe output paths are refused. Review color conversions before reuse and
retain the source PDF: arbitrary shared PDF objects are not a complete standalone
document reconstruction. The scientific CI tier runs the real codec cases with
`cargo test --locked --test pdf_image_formats -- --include-ignored`.

```sh
revayat-scientific crop source.pdf --out artwork --map figures-map.tsv --dpi 300
revayat-scientific figures artwork --check
revayat-scientific figures artwork
```

The crop map accepts `figure_id,pdf_page`, `figure_id,printed,pdf_page`, or reviewed
`figure_id,pdf_page,x0,y0,x1,y1` columns (CSV or TSV). Reviewed coordinates must be
finite, nonempty and inside the displayed page. Automatic artwork components use
actual pairwise adjacency; ambiguous boundaries require reviewed coordinates.
Cover and author extraction also refuse ambiguous image selection. Crops preserve
higher source raster density even when it exceeds the requested minimum. A crop
over 50 million pixels is refused instead of downsampled.

Figure preparation preserves JPEG originals and creates byte-exact `.orig` backups
for in-place PNG conversion. It flattens transparency on white, normalizes reviewed
EXIF orientation, preserves supported RGB ICC/XMP/density metadata and validates
staged decoded pixels. Unsupported high depth, multiple frames or conflicting color
and orientation metadata fail closed. `--check` writes no image or review file.
Legitimate dark originals need a source-hash-bound `.review.json`; that review only
waives the darkness heuristic, never alpha, bit depth, frames or metadata gates.

## Merge, extract pages and fill forms

```sh
revayat-scientific pdf merge merged.pdf first.pdf second.pdf
revayat-scientific pages source.pdf selected.pdf 2-5
revayat-scientific pages source.pdf selected.pdf --from 2 --to 5
revayat-scientific pdf fill form.pdf filled.pdf --fields values.json
```

Page operations copy each source's shared objects once, preserve original content
streams and all page boxes, and validate reopened geometry and supported navigation
before publication. Local destinations retain PDF-space fit modes, null coordinates
and zoom. Links to omitted pages, named/remote/chained/advanced navigation and
unresolved annotations require a reviewed separate copy. Merging refuses AcroForms
and attachments to avoid field-name collisions and document-level ambiguity.

Field JSON must be a nonempty object with unique known names. Text fields accept
strings or finite numbers including zero. Checkboxes accept booleans or exact
inventory states; radios select one unique decoded on-state; single-choice fields
validate their export values. Read-only, scripted, multi-select, pushbutton and
signature fields are refused. Plans validate every requested value before mutation.
Saved button appearance (`AS`), effective stored value (`V`) and radio parent values
are verified independently after reopening. Untouched appearance objects stay intact.

Text appearances support Persian and mixed-direction text through native HarfRust
shaping, Unicode bidi runs and embedded static Vazirmatn Type0/CID fonts. `ActualText`
retains the exact logical field value; ToUnicode maps and the OFL accompany the
licensed bundled fonts. `fonts --offline` can deliver the bundled 33.003 pair,
OFL and hash-bound provenance without downloading a second copy. Field clipping and existing nontext appearance graphics
remain in the appearance stream. Review line breaks and crowded fields visually.

## OCR derivatives

```sh
revayat-scientific pdf ocr scan.pdf searchable.pdf --language eng --dpi 300 --page-timeout 120
```

OCR validates installed language names before rendering. Already searchable pages
are retained. Tesseract must return a fresh single-page text-only PDF matching the
unrotated source CropBox. The native verifier requires invisible text (`Tr 3`) and
refuses all path painting, shadings, images, external graphics states and nested
Form painting. Checking invisible text alone would allow a malicious background
to cover scientific source content. Accepted text is grafted as a Form without
rewriting source image streams; rotation and nonzero crop offsets are retained.
Empty recognition is not claimed as success. Recognition accuracy requires review.

Inputs are regular unlinked unencrypted PDFs, at most 512 MiB, 10,000 pages and
200,000 object IDs. Missing/corrupt cross references, inconsistent page trees,
signature-bearing inputs and XFA are refused for transformations. Read-only
inspection and selected raster crops can inspect unsigned/signature-bearing
structure without altering the source. OCR uses 72–600 DPI and 1–600 seconds per
page; pixel budgets still apply. A missing or failed Poppler/Tesseract backend is
an error, never a substitute for validation.

Every named output batch is staged and validated before atomic publication.
Protected sources, aliases, symlink/reparse components, case collisions and foreign
output revisions are checked by the common native publication layer. A late input,
validation or publication failure preserves the previous approved delivery.
