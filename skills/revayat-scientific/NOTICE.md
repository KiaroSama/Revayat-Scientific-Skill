# License notices

Revayat Scientific is GPL-3.0-or-later; see [LICENSE](LICENSE). The native executable is built from the exact Cargo.lock dependency set. Complete third-party license and copyright notices are retained in [third-party-licenses.txt](references/third-party-licenses.txt), including platform-specific dependency sources.

The linked Rust 1.99.1 standard library retains its complete official [copyright and license notices](references/rust-standard-library-notices.html), copied unchanged from the verified toolchain with [provenance and checksum](references/rust-standard-library-notices.json).

The MIT notice for adapted upstream skill material remains in [upstream-license.txt](references/upstream-license.txt). The inert OOXML defaults embedded by the native DOCX writer retain their [separate MIT notice](assets/LICENSE.docx-defaults). The bundled Western-digit static Vazirmatn font pair retains its SIL OFL 1.1 license and copyright; font delivery also writes the corresponding complete OFL and provenance beside the fonts.

Optional external Chrome/Chromium/Edge, Poppler, Tesseract, LibreOffice, Docker/Podman and the TeX toolchain retain their own licenses. They are not bundled as skill executables. Source papers and original artwork retain their authorship and reuse terms. Research references describe lessons and provenance; links to external implementations do not make those runtimes part of this Rust distribution.

The corresponding source for native CI artifacts is the same reviewed repository revision that produced the artifact. Keep its GPL license, notices and source revision with redistributed builds.
