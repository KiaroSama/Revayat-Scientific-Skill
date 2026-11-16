# License notices

Revayat Scientific is GPL-3.0-or-later; see [LICENSE](LICENSE). The native executable is built from the exact Cargo.lock dependency set. Complete third-party license and copyright notices are retained in [third-party-licenses.txt](references/third-party-licenses.txt), including platform-specific dependency sources.

The linked Rust 1.100.0 standard library retains its complete official [copyright and license notices](references/rust-standard-library-notices.html), copied unchanged from the verified toolchain with [provenance and checksum](references/rust-standard-library-notices.json).

The MIT notice for adapted upstream skill material remains in [upstream-license.txt](references/upstream-license.txt). The inert OOXML defaults embedded by the native DOCX writer retain their [separate MIT notice](assets/LICENSE.docx-defaults). The bundled Western-digit static Vazirmatn font pair retains its SIL OFL 1.1 license and copyright; font delivery also writes the corresponding complete OFL and provenance beside the fonts.

Vendored voice guidance retains its upstream MIT notices: blader/humanizer at `b48c832f0f809c1b5658edbb838c2521b72f2413` (Copyright (c) 2025 Siqi Chen), [LICENSE](references/voice/humanizer/LICENSE); frolin/great-russian-skill at `c9ba8661768927c21b7ba5608e63dce832c568b5` (Copyright (c) 2026 Andrew), [LICENSE](references/voice/great-russian/LICENSE); and Mojtaba-Alehosseini/persian-skill at `4264f6ef03f7568bc15b14287a3db09bc815fc31` (Copyright (c) 2026 Mojtaba Alehosseini), [LICENSE](references/voice/persian/LICENSE) and [NOTICE](references/voice/persian/NOTICE). The [voice provenance](references/voice/README.md) lists retained files and integration boundaries.

Optional external Chrome/Chromium/Edge, Poppler, Tesseract, LibreOffice, Docker/Podman and the TeX toolchain retain their own licenses. They are not bundled as skill executables. Source papers and original artwork retain their authorship and reuse terms. Research references describe lessons and provenance; links to external implementations do not make those runtimes part of this Rust distribution.

The corresponding source for native CI artifacts is the same reviewed repository revision that produced the artifact. Keep its GPL license, notices and source revision with redistributed builds.
