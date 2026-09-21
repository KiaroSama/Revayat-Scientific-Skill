# Native DOCX fixtures

`docx-content.json` is an original, redistributable scientific-document scenario:
Persian and English runs, bold/italic typography, explicit RTL/language metadata,
non-A4 portrait and landscape sections, a table, headers/footers and an image.
`test_docx.py` generates its small PNG and DOCX in a temporary directory with a
Persian/space-containing path. It compares source hashes, untouched archive-member
bytes, image bytes and section geometry after an actual targeted text edit.

The compact ZIP fixture in the same test isolates malicious archive names, DTDs,
macros, stale patches, empty text nodes, field markup and publication failure.
These are authored structural regressions, not a substitute for opening a real
user document in an office renderer. Font fallback, pagination and scientific
translation quality require a separate rendered-document review.
