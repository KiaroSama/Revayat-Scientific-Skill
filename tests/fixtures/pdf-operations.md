# Native PDF operation fixtures

`test_pdf_operations.py` creates small, original PDFs in project-local temporary
directories: a scientific form with zero/false values, a ruled temperature table,
an embedded JPEG, mixed page sizes/rotation, an encrypted document and a signature
field. Tests assert source bytes, stored values, geometry, original image streams
and page-provenanced extraction, including late input/publication failures.

The simulated OCR test controls the backend and verifies that adding hidden text
does not change rendered pixels or geometry. It is not OCR-engine evidence.
The separate real-Tesseract test rasterizes an authored English specimen and
requires an installed Tesseract with `eng` data. A missing runtime skips that test
explicitly; CI must install it to verify the actual OCR path. Neither authored
fixture demonstrates scientific translation quality on a real user paper.
