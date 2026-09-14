# Troubleshooting and recovery

Use the reported failure to choose a recovery step. Keep the original source and
previous delivered PDF intact. Correct a failed stage before continuing.

## Tools and installation

| Symptom | Check | Action |
| --- | --- | --- |
| Python command not found | Interpreter chosen for this job | Resolve Python 3.10+; use the same interpreter for dependencies and helpers |
| Skill does not appear | Host's documented discovery path | Install the payload, refresh discovery, and confirm its `name` field |
| Existing install refused | Current destination | Use `--force` only for an intended replacement; the old copy is retained |
| Installed files unreadable | Destination access and inheritance | Use the current installer; it stages with inherited parent permissions |
| Log initialization failed | Writable log directory | Read the stderr fallback; do not claim a log file was written |

## Source, terminology and figures

| Symptom | Action |
| --- | --- |
| Missing source page or incomplete download | Recover the actual source using [extraction.md](extraction.md); do not translate from memory |
| Two-column text interleaves | Compare with the page image and repair reading order before drafting |
| Missing `terms.tsv` or `manifest.txt` | Create the job records; a figure-free manifest contains a comment |
| `terms-calque` | Complete keep-English rows using [terminology.md](terminology.md) |
| Figure missing, mirrored or cropped incorrectly | Compare the referenced image with the source page and correct its path or crop |
| Dark image flagged | Inspect the source before using inversion; a dark photograph may be correct |

## Build and verification

| Symptom | Action |
| --- | --- |
| Renderer unavailable | Use an available documented engine or obtain prerequisites with approval |
| Renderer fails after starting | Read the TeX/browser error; a silent fallback would hide the failure |
| Missing Poppler/PyMuPDF | Install the requirements needed by verification before claiming a verified PDF |
| PDF empty or truncated | Rebuild after fixing the renderer/driver failure; retain the previous delivered edition |
| Fonts not embedded or text extraction fails | Follow [pdf-output.md](pdf-output.md); prefer the tested Vazirmatn mapping |
| Extraction is inconclusive | Inspect the source and rendered artifact; zero from the standalone checker is not proof of readable extraction |
| Output collides with working PDF | Choose a distinct output directory so a failed build cannot overwrite the delivered edition |
| Timeout or cancellation | Treat the stage as incomplete; fix its cause before retrying with a justified limit |
| Crop exceeds 50 million pixels | Extract the original/vector asset or choose a smaller faithful crop; do not silently downsample |
| Output page size differs from source | Set measured geometry in the editable template and verify again; see [layout-and-images.md](layout-and-images.md) |
| Correct source quote triggers Persian lint | Verify the original and use only its documented rule-specific exception; see [source-languages.md](source-languages.md) |

## Resumption

Read `progress.md` and the source inventory first. Preserve approved terminology
and unchanged reviewed parts. Changed source or terms invalidate only affected
parts. Missing review records mean unreviewed, not approved. Re-run the final
assembled-document gate after revisions; see [long-documents.md](long-documents.md).
