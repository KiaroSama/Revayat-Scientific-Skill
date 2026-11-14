# Native PDF output

Use the native Rust executable for readiness, source lint, rendering and verification. An installed skill has `bin/revayat-scientific` (`.exe` on Windows). A source checkout builds with `cargo build --locked --release --workspace --bins`; use the resulting executable or `cargo run --locked --release --bin revayat-scientific --`.

```console
revayat-scientific doctor
revayat-scientific fonts job/fonts
```

`doctor` emits JSON with native runtime/version, discovered Chromium, container runtime and native verification tool availability. Discovery is not proof of effective sandboxing or a successful render. Missing tools cannot support a verified-delivery claim.

## Engines and native prerequisites

| Source | Engine | Prerequisites |
| --- | --- | --- |
| `.tex` | `tex` | Linux Docker/Podman image and effective production containment; host XeLaTeX is not a fallback |
| `.html` / `.htm` | `chromium` | Sandboxed Chrome, Chromium or Edge; native Rust DevTools client |

Poppler provides `pdfinfo`, `pdffonts`, `pdftoppm` and `pdftotext` verification. Optional OCR uses Tesseract and explicit language data. DOCX scientific rendering uses independent LibreOffice Writer. The executable does not install these system tools automatically.

An explicit `--browser PATH` or `REVAYAT_CHROMIUM` selects the controlled browser. Source rendering does not execute document scripts, permit unrestricted network access or silently disable the browser sandbox. Resource resolution is bound to the job and its admitted assets. Native preflight checks resource attributes, srcset, CSS URL/import/image functions and recursive local CSS/SVG before Chromium starts. Image data URLs have explicit MIME, decoded-byte, count (2048) and aggregate (256 MiB) bounds. Plain strings, namespace identifiers, comments and RCDATA are not resources. Malformed/dynamic resource tokens, XML base, SVG DTD/scripts/events/animation and closure depth above 32 are refused; prepare a separately reviewed static input. A broken sandbox prerequisite is an error.

## Isolated TeX

Build the toolchain image from a complete source checkout's repository root. The installed skill/archive alone does not contain the Rust crate source used by the image build:

```console
docker build -f skills/revayat-scientific/assets/Dockerfile.tex -t revayat-scientific-tex:1 .
```

The image compiles a Rust `revayat-tex-entry` executable and contains the fixed TeX toolchain. Production compilation uses explicit XeLaTeX arguments, no shell escape, bounded passes/output and the configured native process owner. Container settings and native observations must establish the required memory, process, network and filesystem boundary. Rootless engines with ineffective resource limits must fail readiness/security checks. An unavailable container does not authorize host compilation.

## Build and verify

Keep original sources and job sidecars together, outside the installed skill. Builds require `terms.tsv` and `manifest.txt`, either in the job directory or passed explicitly. The same terminology level must be used for lint and build.

```console
revayat-scientific lint job/doc.tex --level journal --terms job/terms.tsv --manifest job/manifest.txt --strict
revayat-scientific build job/doc.tex --out delivery/article.pdf --engine tex --level journal --verify
revayat-scientific build job/doc.html --out delivery/article.pdf --engine chromium --level journal --verify
revayat-scientific text-order delivery/article.pdf --source job/doc.tex --json
```

The optional positional slug and `--output-dir` remain available; `--out` gives the exact PDF destination. `--verify` requests actual PDF checks and sample rasters. A plain render without verification must not be described as verified output.

Source snapshots, sidecars, asset admission and expected output destinations are checked across the build. A guard rejects stale input revisions, output aliases and changed intermediate artifacts. Verification failure preserves the previous approved delivery; unresolved cleanup retains local recovery evidence and blocks publication.

Inspect page count and physical page boxes, embedded fonts, representative first/middle/last rasters and text extraction. Compare scientific symbols, equations, tables, captions and all page classes visually against the source. Generic render checks do not automatically certify original page size or image fidelity; inventory and compare those deliberately.

## Fonts and logical order

The font command validates a complete regular/bold pair, OFL license and provenance, then publishes them together. It accepts a validated local/cache pair in offline mode and never treats a half-installed pair as complete. Keep the license and provenance beside delivered font files.

Persian stays in logical Unicode order. Use the template's RTL paragraphs and complete LTR isolates around formulas, identifiers and numeric units. Do not reverse strings or insert pre-shaped text to imitate a renderer. The text-order checker compares NFKC-normalized Persian source phrases with actual Poppler extraction; report failed/inconclusive results and sampled coverage. Viewer clipboard behavior and semantic accuracy remain separate observations.

```console
revayat-scientific pages delivery/full.pdf delivery/excerpt.pdf 1-20
```

Page extraction uses the same native PDF admission policy as other transformations. It is not a workaround for signatures, unsupported structures or failed source checks. See [PDF processing](pdf-processing.md), [RTL and bidi](rtl-bidi.md), [build integrity](build-integrity.md) and [review](review.md).
