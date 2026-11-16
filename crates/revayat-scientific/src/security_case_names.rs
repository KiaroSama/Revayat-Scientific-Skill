//! Exact native worker IDs and their independently registered test counterparts.
pub const CASE_NAMES: &[(&str, &str)] = &[
    (
        "docx/restricted-rels-_rels",
        "docx_restricted_relationship_lowercase",
    ),
    (
        "docx/restricted-RELS-_rels",
        "docx_restricted_relationship_uppercase_suffix",
    ),
    (
        "docx/restricted-rels-_RELS",
        "docx_restricted_relationship_uppercase_directory",
    ),
    (
        "docx/restricted-ReLs-_ReLs",
        "docx_restricted_relationship_mixed_case",
    ),
    (
        "docx/ordinary-external-False",
        "docx_ordinary_internal_relationship",
    ),
    (
        "docx/ordinary-external-True",
        "docx_ordinary_external_relationship",
    ),
    ("html/ordinary-nesting", "html_ordinary_nesting"),
    ("html/ordinary-lint", "html_ordinary_lint"),
    ("html/ordinary-guard", "html_ordinary_guard"),
    ("html/ordinary-assets", "html_ordinary_assets"),
    (
        "html/ordinary-render-entry-ordering",
        "html_ordinary_render_entry_ordering",
    ),
    ("html/depth/parser", "html_depth_parser"),
    ("html/depth/source", "html_depth_source"),
    ("html/depth/guard", "html_depth_guard"),
    ("html/depth/assets", "html_depth_assets"),
    ("html/depth/text-order", "html_depth_text_order"),
    ("html/depth/resource-policy", "html_depth_resource_policy"),
    ("html/depth/render-entry", "html_depth_render_entry"),
    ("html/depth/lint", "html_depth_lint"),
    ("html/nodes/parser", "html_nodes_parser"),
    ("html/nodes/source", "html_nodes_source"),
    ("html/nodes/guard", "html_nodes_guard"),
    ("html/nodes/assets", "html_nodes_assets"),
    ("html/nodes/text-order", "html_nodes_text_order"),
    ("html/nodes/resource-policy", "html_nodes_resource_policy"),
    ("html/nodes/render-entry", "html_nodes_render_entry"),
    ("html/nodes/lint", "html_nodes_lint"),
    (
        "publication/portable-reparse-metadata",
        "publication_portable_reparse_metadata",
    ),
    (
        "publication/ordinary-publication",
        "publication_ordinary_publication",
    ),
    (
        "publication/protected-hardlink",
        "publication_protected_hardlink",
    ),
    (
        "tex-output/production-run-arguments-evaluated",
        "tex_output_production_run_arguments_evaluated",
    ),
    (
        "tex-output/production-rw-output-bind",
        "tex_output_production_rw_output_bind",
    ),
    (
        "tex-output/production-per-file-not-aggregate",
        "tex_output_production_per_file_not_aggregate",
    ),
    (
        "tex-output/real-xelatex-no-shell",
        "tex_output_real_xelatex_no_shell",
    ),
    (
        "tex-output/two-permitted-output-files",
        "tex_output_two_permitted_output_files",
    ),
    ("tex-output/ordinary-pdf", "tex_output_ordinary_pdf"),
];
