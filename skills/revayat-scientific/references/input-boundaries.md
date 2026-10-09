# Input, publication and history contracts

## PDF admission

The `scripts/pdf_input.py` context manager supplies shared admission for contiguous
page extraction, existing PDF operations and raster cropping. Parity tests bind
these public entry points. Read-only inspection and raster cropping can admit
signature-bearing inputs; PDF transformations refuse signatures and XFA. All paths retain the existing
512 MiB, 10000-page and 200000-object bounds, reject encrypted inputs (including
an empty user password), and refuse parser-repaired documents. Use a separately
authorized, reviewed derivative when a source needs decryption or repair. A
signature-bearing fixture or successful structural check does not authenticate a
cryptographic signature or certify scientific meaning.

Page extraction still uses one contiguous `insert_pdf` call, preserving shared
resources rather than copying every page separately. The staged output is
reopened before recoverable publication. Named/remote page links, chained actions,
unresolved annotations and local targets outside the copied range are refused
before publication. Supported
numeric destinations are remapped with their exact PDF-space coordinates/zoom;
staged page-link rectangles and URI/file data are checked separately from outlines.
Sources and previous approved outputs remain unchanged on admission or staged
validation failure; publication uses the shared accountable recovery contract.
Raster crop admission does not authenticate signatures or rewrite source bytes.
Its separate 50-million-pixel allocation ceiling is unchanged.

## Safe package destinations

`tools/package.py --output PATH` captures the allowlisted payload, protects its
sources and known build inputs, and in a Git checkout also protects every tracked
path. Outputs cannot overwrite source documentation outside the payload, follow
links/junctions, alias a protected input through a hardlink, collide by case, or
use a directory as a file. Outputs beneath the skill, `tools/` or `install/` are
refused. Use `dist/` or a separate explicit destination.

A same-filesystem staged ZIP must pass CRC and required-entry checks before the
shared publication helper can replace a legitimate prior output. This is
recoverable publication, not a global atomic filesystem transaction. Exported
source trees without `.git` protect known build inputs and payload, but cannot
enumerate an unavailable index. Package validity does not prove host discovery;
retain install-and-run tests for the actual generated artifact.

## Literal TeX includes

For the supported normal-category-code subset, a TeX control word ends before a
nonletter, not at a Unicode regular-expression word boundary. Thus `\input2` and
`\input2.tex` are literal source dependencies; `\inputenc` is another macro.
Comments, literal examples and paired backslashes stay inert. The same closure
limits, missing-file checks, cycle checks and source-location mapping apply.
Arbitrary macro expansion and changed category codes remain unsupported, not
silently interpreted as fully validated TeX. Recognizing a nonletter filename
boundary does not certify every spelling on every engine: unbraced underscore
filenames depend on filename/category-code handling; native numeric input has
an explicit compiler control.

## Stored Git identity

The identity checker reads actual author and committer metadata with replacement
objects disabled. It refuses shallow repositories and nonempty legacy graft
files, including the Git-selected alternate graft path, because those views can
hide ancestors. It does not delete those files or replacement refs. Use a complete,
ungrafted checkout. A `--base` range still says nothing about excluded history.
The required exact address is `Kiaro.Sama.Dev@gmail.com` in both roles. A mailmap
or replacement object is not a stored-history correction; any authorized rewrite
needs a private backup, tree/topology verification and per-reference safety checks.

## Primary research and adopted boundaries (2026-10-03)

- [LaTeX documentation](https://www.latex-project.org/help/documentation/) and
  [LaTeX source](https://github.com/latex3/latex2e): use real compiler evidence for
  control-word boundaries, while keeping the scanner's supported subset explicit.
- [PyMuPDF API](https://pymupdf.readthedocs.io/en/latest/document.html) and
  [qpdf](https://github.com/qpdf/qpdf): distinguish opening, permissions, parser
  repair, transformation and signature authentication. No qpdf dependency added.
- [Python ZIP API](https://docs.python.org/3/library/zipfile.html) and
  [pikepdf saving contracts](https://pikepdf.readthedocs.io/en/latest/api/main.html):
  validate a staged artifact before replacing a destination; protect source identity.
- [Git replacements](https://git-scm.com/docs/git-replace) and
  [shallow history](https://git-scm.com/docs/shallow): a displayed history is not
  necessarily the original complete graph. Tests use disposable unpublished repos.
- [Spec Kit workflows](https://github.github.com/spec-kit/reference/workflows.html):
  carry research, requirement IDs, regressions and acceptance through the owner's
  selected feature and configured chain. Do not replace private Rules or bypass
  human gates. No external code, model weights or test corpora are bundled here.
