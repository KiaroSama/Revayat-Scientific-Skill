# PDF outline and page-link preservation

The Rust PDF implementation preserves raw supported destination arrays through
`lopdf` object copying. It does not round-trip destinations through viewer-space
coordinates. Merge and page extraction validate navigation again after writing.

```sh
revayat-scientific pdf merge merged.pdf first.pdf second.pdf
revayat-scientific pages source.pdf selected.pdf 2-5
```

Supported local fits are `XYZ`, `Fit`, `FitH`, `FitV`, `FitR`, `FitB`, `FitBH` and
`FitBV`, with their exact numeric/null argument counts. Destination page references
are remapped for each input copy, including repeated occurrences of one source.
Page rotation and CropBox offsets do not change destination coordinates. A link to
a page outside an extracted range is refused before publishing the derivative.

Outline hierarchy, titles, colors, style flags, collapsed counts and supported
URI actions are copied as data. URI `IsMap` is retained; no URL is opened. Documents
without outlines do not acquire fabricated bookmarks. Top-level outline lists are
joined while their children retain source relationships. Shared page resources and
original content stream bytes retain one object identity within each copied source.

The verifier reads raw link annotations as well as outline dictionaries. Ambiguous
`Dest` plus `A`, unresolved annotations, named/remote destinations, unsupported fit
arguments, advanced actions, `Next` chains and cycles require a reviewed separate
copy. An unsupported action is an error rather than silently dropped navigation.

After staging, the helper checks page count, MediaBox, CropBox, rotation, outline order,
styles, local targets, destination tails and link rectangles/actions. A failed
reopened check preserves both source bytes and any previous destination. These are
structural and authored pixel-regression guarantees; they do not certify arbitrary
PDF conformance, external URLs, signatures or semantic correctness of the document.

Native regression targets are `pdf_outlines`, `pdf_links`, `pdf_admission` and
`pdf_page_integrity`. Real Poppler tests compare source and derivative pixels for
rotated/cropped pages. Scientific CI executes them with `--include-ignored`; an
unexecuted optional integration test is reported as ignored, not passed.
