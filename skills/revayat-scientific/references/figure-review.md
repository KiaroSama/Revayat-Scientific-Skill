# Reviewing legitimate dark figures

The darkness detector is a heuristic, not proof of a corrupt or inverted image.
An originally dark micrograph, astronomical image or plot must not be inverted
merely to clear the build gate. Image-depth, frame, transparency, color-profile
and file-safety checks remain mandatory.

After actually comparing the current asset with its source page, the coordinating
agent or reviewer may record that the darkness is original in a UTF-8 JSON sidecar
named `<complete-image-filename>.review.json`, for example
`figures/artwork/fig-2.png.review.json`:

```json
{
  "version": 1,
  "sha256": "<lowercase SHA-256 of the exact current image bytes>",
  "decision": "preserve-dark-original",
  "note": "Identify the source page/figure and record the actual comparison."
}
```

This example is a schema illustration, not an approval. Replace both placeholders
only after the comparison. On PowerShell 7, obtain the digest with
`(Get-FileHash -LiteralPath 'figures/artwork/fig-2.png' -Algorithm SHA256).Hash.ToLowerInvariant()`.
Record the review and its source evidence in the translation log as well.

The helper never generates or signs an approval. Do not trust a sidecar bundled
with unreviewed input as evidence that someone performed the required review.
The sidecar is a local workflow assertion, not authentication or a security boundary.

A valid matching sidecar discharges only the darkness warning for that exact file.
Changing the image invalidates its digest; compare the changed asset again instead
of automatically refreshing the hash. Each image needs its own sidecar. Unknown
fields, invalid/duplicate JSON keys, stale digests, linked paths and oversized
reviews fail. Review files are limited to 16 KiB and notes to 4096 characters;
notes are not copied to diagnostic logs.

`prepare-figures.py --check` keeps the image and sidecar bytes unchanged.
Unreviewed dark images still fail; transparency and unsupported depth/frames
continue to fail even with a valid darkness review. Both native build adapters
use the same referenced-asset checker through `build-support.py`, including
nested artwork directories. No blanket skip flag or automatic inversion is added.

When no source comparison is possible, report the figure as unresolved.
Do not invent a review or alter scientific intensities to force success.

References:
- [PLOS figure guidance](https://journals.plos.org/plosone/s/figures)
- [Pillow image representations and operations](https://pillow.readthedocs.io/en/stable/reference/Image.html)
