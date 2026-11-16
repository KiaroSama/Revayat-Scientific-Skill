# Troubleshooting native tools

Record the command, native prerequisite, bounded failure and what remains unverified in the translation log. Do not publish document contents or credentials to diagnose a tool failure.

| Symptom | Check | Resolution |
| --- | --- | --- |
| Executable missing | Installed skill `bin/` or source `target/release/` | Build the pinned Rust workspace or obtain the matching operating-system CI artifact |
| Wrong executable format | Operating system and architecture | Use the native artifact for this machine |
| Missing document command | Command `--help` and executable version | Use the complete 2.0 executable and its documented schema |
| TeX unavailable | Docker/Podman image and effective limits | Build the image from the repository root; do not substitute host TeX |
| Sandbox enforcement failure | Actual memory, process, network and filesystem evidence | Fix the native host/engine prerequisite; do not bypass a failed security check |
| Chromium cannot start | Browser path, normal sandbox helper ownership and user namespace support | Install/configure a supported sandboxed browser; do not disable its sandbox |
| Resource denied | Job-local path, link/traversal and URI policy | Preserve source boundaries and explicitly supply the intended admitted asset |
| Verification tool missing | `doctor` JSON and native Poppler executables | Install the required native tools before claiming verified PDF delivery |
| OCR unavailable | Tesseract and selected language data | Install that language data or report OCR unperformed |
| Inconclusive text order | Actual source phrases and extracted PDF text | Inspect the extraction and rendered document; do not reverse source strings |
| Font bundle incomplete | Regular/bold files, OFL and provenance | Run `fonts` for a complete validated bundle |
| Existing skill refused | Exact frontmatter identity and destination | Keep foreign contents intact; select the correct destination |
| Recovery required | Named complete local journal, stages, backups and locks | Stop competing writers and resolve every target deliberately before removing evidence |

Use [PDF output](pdf-output.md), [DOCX](docx.md), [PDF processing](pdf-processing.md), [build integrity](build-integrity.md) and [input boundaries](input-boundaries.md) for the relevant contract. A mechanical check does not replace source-language, scientific or visual review.
