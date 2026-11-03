//! Native implementation of the scientific translation helper contracts.
//!
//! Source offsets are UTF-8 byte offsets. File contents and byte provenance are
//! retained without normalizing line endings, including mixed LF/CRLF sources.
pub mod build;
pub mod docx;
pub mod identity;
pub mod ledger;
pub mod publication;
pub mod render;
pub mod runtime;
pub mod sandbox;
pub mod source;
pub mod tex;
pub mod tex_container;
pub mod tex_supervisor;

pub mod ci;
pub mod ci_tools;
pub mod crop;
pub mod distribution;
pub mod distribution_paths;
pub mod fonts;
pub mod html;
pub mod html_scopes;
pub mod images;
pub mod lint;
pub mod migration;
pub mod pdf;
pub mod pdf_content;
pub mod pdf_font;
pub mod pdf_forms;
pub mod pdf_navigation;
pub mod pdf_ocr;
pub mod resource;
pub mod terms;
pub mod text_order;
pub mod validation;
pub mod windows_security;

pub mod distribution_package;
pub mod pdf_extract;
pub mod pdf_images_advanced;
pub mod pdf_layout;

pub mod resource_preflight;
pub mod security_cases;
