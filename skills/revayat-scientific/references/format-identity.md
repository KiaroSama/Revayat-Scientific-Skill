# Format identity and preservation boundaries

## PDF button values

`pdf inspect` reports decoded ASCII/UTF-8 normal and pressed-down button-state
names. Use those names directly in the fields JSON; do not apply PDF `#xx`
escaping to user values. For example, `On State` is a label, while `On#20State`
can be a different literal label. The parser decodes serialized dictionary keys
exactly once. Checkbox booleans remain supported. Radio choices must identify
one unique normal on-state in their group.

`pdf_button_states.py` reads the bounded name-to-stream-reference appearance
subset through public PyMuPDF object APIs, independently of the widget helper's
serialized spelling. Direct and indirect appearance dictionaries are supported.
An appearance dictionary is limited to 65536 serialized characters and 1024
states. Non-UTF-8 names, control characters, unsupported values and ambiguous
normal on-states require a separately reviewed workflow rather than lossy
normalization. Inspection can report a well-formed ambiguous state set with a
null `on_state`; filling it is refused.

Before publication, verification checks the selected appearance, its actual
normal-state entry and the stored field value. The stored `/V` may be inherited
through `/Parent`; do not substitute an appearance-derived `Widget.field_value`
for that check. Parent traversal is bounded to 64 objects and rejects cycles.
Unselected radio children may inherit the selected group's value. These checks
validate the implemented form subset, not all interactive calculations or all
PDF viewers. Existing scripted-field, signature, XFA and publication safeguards
remain mandatory. No form JavaScript is executed.

## DOCX restricted-feature identity

An OPC part does not lose its signature or VBA identity when its filename changes.
`docx_package.py` checks effective declared content types and exact known
relationship identifiers, in addition to the existing conservative filename
and macro-enabled-main guards. Content-type comparison for this restriction is
ASCII case-insensitive; overrides still take precedence over defaults.

The known set covers package signature origin, XML signature and certificate
parts, and VBA project, legacy, agile and V3 project signature
metadata, including their version-specific relationship identifiers. It is not an exhaustive malware detector. Unknown custom XML is not
classified as a restricted feature merely because it contains similar words.
Restricted external relationships are never permission to fetch their targets.

Inspection reports the existing `unsupported` categories; editing/validation
continue to refuse those packages. Keep the original and obtain an explicitly
reviewed permitted derivative rather than deleting signature or macro metadata
to make editing pass. Presence of metadata is **not** proof of signature validity,
certificate trust, executable macro contents or maliciousness. Synthetic regression
packages exercise classification/refusal, not cryptographic authentication.

## Git metadata is not a package destination

The packaging output is forbidden from the checkout's `.git` control path, the
actual Git directory, a worktree's shared directory, and Git-resolved index,
object-store and split-index paths. This includes relocated metadata outside the
checkout and an explicitly selected `GIT_DIR` even without a local gitfile. Missing or ambiguous Git path resolution is a failed preflight, not an
empty protection list. Exported source trees also reserve their `.git` path.
No history or repository metadata is rewritten by the package command. Existing
source-alias checks, staged ZIP validation and recoverable publication remain in
place. Ordinary `dist/` and independent output paths remain supported.

## Research decisions (2026-10-04)

- [PyMuPDF widgets](https://pymupdf.readthedocs.io/en/latest/widget.html) and
  [low-level object APIs](https://pymupdf.readthedocs.io/en/latest/document.html#Document.xref_get_key):
  separate serialized names, appearance selection and stored/inherited values.
  [pikepdf's object model](https://pikepdf.readthedocs.io/en/latest/topics/objects.html)
  is a useful independent comparison; no second PDF runtime is added here.
- [Open XML SDK part identities](https://github.com/dotnet/Open-XML-SDK/blob/main/data/parts/DigitalSignatureOriginPart.json),
  [VBA project identity](https://github.com/dotnet/Open-XML-SDK/blob/main/data/parts/VbaProjectPart.json),
  and [Microsoft's agile VBA signature definition](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-xlsb/301bfe6b-5acc-4223-81e6-4ee2cc3fc09b):
  treat declared package types/relationships as identities, not default filenames.
- [OfficeIMO signature profile identities](https://github.com/EvotecIT/OfficeIMO/blob/master/OfficeIMO.Word/Internal/MacroSignatures/WordMacroProjectSignatureInspector.cs):
  include the documented canonical Agile/V3 relationship identifiers rather than
  assuming every VBA relation uses the legacy 2006 namespace. No signature
  verification implementation is copied or claimed here.
- [Git path resolution](https://git-scm.com/docs/git-rev-parse): query active
  private/common and relocated metadata paths instead of assuming `.git/` is a
  directory beside the source. Tests use disposable local repositories only.
- [Spec Kit workflows](https://github.github.com/spec-kit/reference/workflows.html):
  carry these requirements, research and acceptance evidence through the owner's
  actual configured chain and selected local feature. Do not publish private Rules
  or replace their checkpoints with an assumed default workflow.

Regression modules: `test_pdf_button_names.py`, `test_docx_feature_identity.py`,
and `test_package_git_metadata.py`. They use the existing test discovery and
operation logging. No additional runtime dependencies, certificates, macro
payloads, model weights or third-party source code are distributed.
