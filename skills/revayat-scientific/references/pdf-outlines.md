# Outline preservation during PDF merge

The built-in `pdf merge` operation preserves supported outline hierarchy, titles,
local destinations, URI actions, emphasis, colors and expansion state. It remaps
local page references to the corresponding copied pages. Original PDF-space
coordinates, zoom values and standard XYZ/Fit destination arguments are retained,
including null coordinates and rotated or cropped target pages. URLs are retained
as data; they are never fetched or executed.

The implementation deliberately does not use a simple three-column TOC as a
lossless outline representation. That representation omits destinations, actions
and presentation attributes. Reconstructing coordinates from page numbers also
loses precise targets. `scripts/pdf_outlines.py` plans the supported objects,
rewrites only local page references and verifies outline semantics after the
staged output is reopened, before replacing an existing delivery.

Supported local destinations are XYZ, Fit, FitH, FitV, FitR, FitB, FitBH and FitBV.
Grouping entries without actions are retained. URI actions retain their URI and
IsMap flag. Named destinations, remote/launch or other advanced actions, chained
actions, conflicting Dest/action entries and unsupported destination encodings
are refused before publication rather than silently stripped. Make an explicitly
reviewed derivative when those advanced features require reconciliation.

Merge remains a page-oriented transformation, not a lossless archive of all
source-document metadata or identities. Keep the originals. Source signature,
form, attachment, encryption and publication safeguards remain in effect.

Technical references:
- [PyMuPDF detailed table of contents](https://pymupdf.readthedocs.io/en/latest/document.html#Document.get_toc)
- [PyMuPDF low-level PDF object APIs](https://pymupdf.readthedocs.io/en/latest/document.html#Document.xref_get_key)
- [PyMuPDF page insertion](https://pymupdf.readthedocs.io/en/latest/document.html#Document.insert_pdf)

Regression coverage: `tests/test_pdf_outline_preservation.py` uses real PDFs,
all quarter-turn rotations, offset CropBoxes, destination variants, repeated
inputs, unchanged page rasters and failure-preservation controls.
