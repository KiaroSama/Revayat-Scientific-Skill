//! All 36 authored checks formerly outside the 583-method and 37-shell censuses.
use anyhow::Result;
use revayat_scientific::security_cases::Cases;
#[cfg(windows)]
#[path = "support/windows_junction.rs"]
mod windows_junction;
fn case(id: &str) -> Result<()> {
    let root = tempfile::tempdir()?;
    #[cfg(windows)]
    if id == "publication/portable-reparse-metadata" {
        let target = root.path().join("reparse-target");
        std::fs::create_dir(&target)?;
        windows_junction::create(&root.path().join("reparse-link"), &target)?;
    }
    Cases::new(
        root.path(),
        std::path::Path::new(env!("CARGO_BIN_EXE_revayat-scientific")),
        false,
    )?
    .run(id)
}
#[test]
fn docx_restricted_relationship_lowercase() -> Result<()> {
    case("docx/restricted-rels-_rels")
}

#[test]
fn docx_restricted_relationship_uppercase_suffix() -> Result<()> {
    case("docx/restricted-RELS-_rels")
}

#[test]
fn docx_restricted_relationship_uppercase_directory() -> Result<()> {
    case("docx/restricted-rels-_RELS")
}

#[test]
fn docx_restricted_relationship_mixed_case() -> Result<()> {
    case("docx/restricted-ReLs-_ReLs")
}

#[test]
fn docx_ordinary_internal_relationship() -> Result<()> {
    case("docx/ordinary-external-False")
}

#[test]
fn docx_ordinary_external_relationship() -> Result<()> {
    case("docx/ordinary-external-True")
}

#[test]
fn html_ordinary_nesting() -> Result<()> {
    case("html/ordinary-nesting")
}

#[test]
fn html_ordinary_lint() -> Result<()> {
    case("html/ordinary-lint")
}

#[test]
fn html_ordinary_guard() -> Result<()> {
    case("html/ordinary-guard")
}

#[test]
fn html_ordinary_assets() -> Result<()> {
    case("html/ordinary-assets")
}

#[test]
fn html_ordinary_render_entry_ordering() -> Result<()> {
    case("html/ordinary-render-entry-ordering")
}

#[test]
fn html_depth_parser() -> Result<()> {
    case("html/depth/parser")
}

#[test]
fn html_depth_source() -> Result<()> {
    case("html/depth/source")
}

#[test]
fn html_depth_guard() -> Result<()> {
    case("html/depth/guard")
}

#[test]
fn html_depth_assets() -> Result<()> {
    case("html/depth/assets")
}

#[test]
fn html_depth_text_order() -> Result<()> {
    case("html/depth/text-order")
}

#[test]
fn html_depth_resource_policy() -> Result<()> {
    case("html/depth/resource-policy")
}

#[test]
fn html_depth_render_entry() -> Result<()> {
    case("html/depth/render-entry")
}

#[test]
fn html_depth_lint() -> Result<()> {
    case("html/depth/lint")
}

#[test]
fn html_nodes_parser() -> Result<()> {
    case("html/nodes/parser")
}

#[test]
fn html_nodes_source() -> Result<()> {
    case("html/nodes/source")
}

#[test]
fn html_nodes_guard() -> Result<()> {
    case("html/nodes/guard")
}

#[test]
fn html_nodes_assets() -> Result<()> {
    case("html/nodes/assets")
}

#[test]
fn html_nodes_text_order() -> Result<()> {
    case("html/nodes/text-order")
}

#[test]
fn html_nodes_resource_policy() -> Result<()> {
    case("html/nodes/resource-policy")
}

#[test]
fn html_nodes_render_entry() -> Result<()> {
    case("html/nodes/render-entry")
}

#[test]
fn html_nodes_lint() -> Result<()> {
    case("html/nodes/lint")
}

#[test]
fn publication_portable_reparse_metadata() -> Result<()> {
    case("publication/portable-reparse-metadata")
}

#[test]
fn publication_ordinary_publication() -> Result<()> {
    case("publication/ordinary-publication")
}

#[test]
fn publication_protected_hardlink() -> Result<()> {
    case("publication/protected-hardlink")
}

#[test]
fn tex_output_production_run_arguments_evaluated() -> Result<()> {
    case("tex-output/production-run-arguments-evaluated")
}

#[test]
fn tex_output_production_rw_output_bind() -> Result<()> {
    case("tex-output/production-rw-output-bind")
}

#[test]
fn tex_output_production_per_file_not_aggregate() -> Result<()> {
    case("tex-output/production-per-file-not-aggregate")
}

#[test]
#[ignore = "requires XeLaTeX; the required isolated security worker and equipped scientific CI execute this exact case"]
fn tex_output_real_xelatex_no_shell() -> Result<()> {
    case("tex-output/real-xelatex-no-shell")
}

#[test]
#[ignore = "requires XeLaTeX; the required isolated security worker and equipped scientific CI execute this exact case"]
fn tex_output_two_permitted_output_files() -> Result<()> {
    case("tex-output/two-permitted-output-files")
}

#[test]
#[ignore = "requires XeLaTeX; the required isolated security worker and equipped scientific CI execute this exact case"]
fn tex_output_ordinary_pdf() -> Result<()> {
    case("tex-output/ordinary-pdf")
}
