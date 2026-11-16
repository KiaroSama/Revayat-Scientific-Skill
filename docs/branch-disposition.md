# Branch consolidation

All migration work is proposed in PR #33, targeting `main`. No PR is merged into
`main` by this work. The following histories are retained in the migration branch:

| Branch / PR | Decision |
| --- | --- |
| `rewrite/rust-native` at `8801758` | Starting point and ancestor of `rewrite/rust-complete`; its existing Rust modules and migration inventories are preserved and repaired. |
| `dependabot/github_actions/actions-1a2b6da459`, PR #32, `749c976` | Consolidated into this branch. CodeQL init/analyze already use the proposed 4.39.3 commit `33d7b85` in the Rust workflow. |
| `dependabot/pip/zizmor-1.32.0`, PR #31, `ab0cac4` | Consolidated into this branch. The Rust CLI installs the exact native zizmor 1.32.0 release with Cargo; the removed Python development-requirements file is not reintroduced. |
| `dependabot/pip/skills/revayat-scientific/pymupdf-2.1`, PR #30, `2475694` | Consolidated as superseded. Native lopdf/Poppler document operations replace PyMuPDF in the Rust product; adding its Python requirement again would restore a removed runtime. |

The dependency branch histories are joined with Git's `ours` merge strategy:
their relevant updates already exist or are superseded by the language migration.
The merge adds ancestry only and does not silently reintroduce legacy code. The
source refs can remain as historical pointers; they no longer represent separate
unresolved migration proposals. The superseded PR descriptions link to PR #33.

This disposition does not waive the unfinished native execution and parity gates
documented in [development](development.md). The consolidated PR remains a draft
until those gates actually pass.
