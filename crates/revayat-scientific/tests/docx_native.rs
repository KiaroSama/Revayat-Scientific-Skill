//! Native equivalents of all 54 legacy DOCX behaviors, including the optional
//! real LibreOffice render tier. Synthetic signature fixtures are not signatures.
use revayat_scientific::{docx as d, publication::Boundary};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

type Members = BTreeMap<String, Vec<u8>>;
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    source: PathBuf,
    output: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        Self {
            source: root.join("source.docx"),
            output: root.join("output.docx"),
            root,
            _temp: temp,
        }
    }
    fn write(&self, members: &Members) {
        write_zip(&self.source, members, b"untouched package comment");
    }
    fn base(&self) -> Members {
        let members = base();
        self.write(&members);
        members
    }
    fn patch(&self, part: &str, expected: &str, new: &str) {
        d::edit_package(
            &self.source,
            &self.output,
            &json!([{"part":part,"index":0,"expected":expected,"text":new}]),
            &[],
        )
        .unwrap();
    }
    fn blocked(&self, category: &str) {
        let before = fs::read(&self.source).unwrap();
        fs::write(&self.output, b"previous approved delivery").unwrap();
        let report = d::inspect_package(&self.source).unwrap();
        assert!(
            report["unsupported"]
                .as_array()
                .unwrap()
                .contains(&json!(category))
        );
        let mut published = false;
        let e = d::edit_package_observed(
            &self.source,
            &self.output,
            &patch("Original text", "Reviewed replacement"),
            &[],
            |event| {
                if matches!(event, d::EditEvent::Publication { .. }) {
                    published = true;
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(!published, "restricted package reached publication");
        assert!(e.to_string().contains(category));
        assert_eq!(fs::read(&self.source).unwrap(), before);
        assert_eq!(
            fs::read(&self.output).unwrap(),
            b"previous approved delivery"
        );
        self.clean();
    }
    fn clean(&self) {
        assert!(!fs::read_dir(&self.root).unwrap().any(|p| {
            p.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".revayat-")
        }));
    }
    fn story(
        &self,
        kind: &str,
        part: &str,
        generic: bool,
        default: bool,
        root: Option<&str>,
        extra: &str,
    ) -> Members {
        let mut m = base();
        m.remove("word/media/unchanged.bin");
        m.insert(
            "word/document.xml".into(),
            document("<w:p><w:r><w:t>Body</w:t></w:r></w:p>"),
        );
        let mime = if generic {
            "application/xml".into()
        } else {
            format!("application/vnd.openxmlformats-officedocument.wordprocessingml.{kind}+xml")
        };
        let declaration = if default {
            format!(
                "<Default Extension=\"{}\" ContentType=\"{mime}\"/>",
                part.rsplit('.').next().unwrap()
            )
        } else {
            format!("<Override PartName=\"/{part}\" ContentType=\"{mime}\"/>")
        };
        append(
            &mut m,
            "[Content_Types].xml",
            "</Types>",
            &(declaration + extra),
        );
        let tag = root.unwrap_or(match kind {
            "header" => "hdr",
            "footer" => "ftr",
            _ => kind,
        });
        m.insert(
            part.into(),
            format!(
                "<w:{tag} xmlns:w=\"{}\"><w:p><w:r><w:t>Original</w:t></w:r></w:p></w:{tag}>",
                d::W
            )
            .into_bytes(),
        );
        m.insert("word/_rels/document.xml.rels".into(),format!("<Relationships xmlns=\"{}\"><Relationship Id=\"s1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/{kind}\" Target=\"/{part}\"/></Relationships>",d::R).into_bytes());
        self.write(&m);
        m
    }
    fn feature(
        &self,
        f: &Feature,
        typed: bool,
        related: bool,
        external: bool,
        default: bool,
    ) -> Members {
        let mut m = base();
        m.insert("opaque/object.dat".into(), f.payload.to_vec());
        let mime = if typed {
            f.mime.as_str()
        } else {
            "application/octet-stream"
        };
        let declaration = if default {
            format!("<Default Extension=\"dat\" ContentType=\"{mime}\"/>")
        } else {
            format!("<Override PartName=\"/opaque/object.dat\" ContentType=\"{mime}\"/>")
        };
        append(&mut m, "[Content_Types].xml", "</Types>", &declaration);
        if related {
            append(
                &mut m,
                "_rels/.rels",
                "</Relationships>",
                &format!(
                    "<Relationship Id=\"restricted\" Type=\"{}\" Target=\"{}\" TargetMode=\"{}\"/>",
                    f.relation,
                    if external {
                        "https://example.invalid/do-not-fetch"
                    } else {
                        "opaque/object.dat"
                    },
                    if external { "External" } else { "Internal" }
                ),
            );
        }
        self.write(&m);
        m
    }
    fn signatures(&self, typed: bool, related: bool, folder: &str, uppercase: bool) -> Members {
        let mut m = real();
        for (part, kind, bytes) in [
            (format!("{folder}/origin.sigs"), "origin", b"".as_slice()),
            (
                format!("{folder}/signature.data"),
                "xmlsignature+xml",
                b"<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"/>".as_slice(),
            ),
        ] {
            m.insert(part.clone(), bytes.to_vec());
            let mut mime = if typed {
                format!("application/vnd.openxmlformats-package.digital-signature-{kind}")
            } else {
                "application/octet-stream".into()
            };
            if uppercase {
                mime = mime.to_uppercase();
            }
            append(
                &mut m,
                "[Content_Types].xml",
                "</Types>",
                &format!("<Override PartName=\"/{part}\" ContentType=\"{mime}\"/>"),
            );
        }
        if related {
            append(
                &mut m,
                "_rels/.rels",
                "</Relationships>",
                &format!(
                    "<Relationship Id=\"signature-origin\" Type=\"{SIG}origin\" Target=\"/{folder}/origin.sigs\"/>"
                ),
            );
            m.insert(format!("{folder}/_rels/origin.sigs.rels"),format!("<Relationships xmlns=\"{}\"><Relationship Id=\"signature\" Type=\"{SIG}signature\" Target=\"signature.data\"/></Relationships>",d::R).into_bytes());
        }
        self.write(&m);
        m
    }
}
fn write_zip(path: &Path, members: &Members, comment: &[u8]) {
    let mut z = ZipWriter::new(File::create(path).unwrap());
    z.set_raw_comment(comment.into()).unwrap();
    for (name, bytes) in members.iter().rev() {
        z.start_file(name, SimpleFileOptions::default()).unwrap();
        z.write_all(bytes).unwrap();
    }
    z.finish().unwrap();
}
fn read_zip(path: &Path) -> Members {
    let mut z = ZipArchive::new(File::open(path).unwrap()).unwrap();
    (0..z.len())
        .map(|i| {
            let mut f = z.by_index(i).unwrap();
            let n = f.name().unwrap().into_owned();
            let mut b = Vec::new();
            f.read_to_end(&mut b).unwrap();
            (n, b)
        })
        .collect()
}
fn document(body: &str) -> Vec<u8> {
    format!(
        "<w:document xmlns:w=\"{}\"><w:body>{body}</w:body></w:document>",
        d::W
    )
    .into_bytes()
}
fn base() -> Members {
    BTreeMap::from([
 ("[Content_Types].xml".into(),format!("<Types xmlns=\"{}\"><Default Extension=\"xml\" ContentType=\"application/xml\"/><Default Extension=\"bin\" ContentType=\"application/octet-stream\"/><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"{}\"/></Types>",d::C,d::MAIN_TYPE).into_bytes()),
 ("_rels/.rels".into(),format!("<Relationships xmlns=\"{}\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>",d::R).into_bytes()),
 ("word/document.xml".into(),document("<w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Original text</w:t></w:r></w:p><w:sectPr><w:pgSz w:w=\"9071\" w:h=\"13606\"/></w:sectPr>")),
 ("word/media/unchanged.bin".into(),b"\0\x01scientific samples\xff".to_vec())])
}
fn real() -> Members {
    let bytes = include_bytes!("../../../tests/fixtures/docx-native-original.docx");
    let mut z = ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    (0..z.len())
        .map(|i| {
            let mut f = z.by_index(i).unwrap();
            let n = f.name().unwrap().into_owned();
            let mut b = Vec::new();
            f.read_to_end(&mut b).unwrap();
            (n, b)
        })
        .collect()
}
fn append(m: &mut Members, name: &str, end: &str, extra: &str) {
    let s = String::from_utf8(m[name].clone()).unwrap();
    m.insert(
        name.into(),
        s.replace(end, &format!("{extra}{end}")).into_bytes(),
    );
}
fn replace(m: &mut Members, name: &str, old: &str, new: &str) {
    let s = String::from_utf8(m[name].clone()).unwrap();
    assert!(s.contains(old), "fixture replacement missing {old}");
    m.insert(name.into(), s.replace(old, new).into_bytes());
}
fn patch(expected: &str, text: &str) -> Value {
    json!([{"part":"word/document.xml","index":0,"expected":expected,"text":text}])
}
fn has_node(report: &Value, part: &str, text: &str) -> bool {
    report["text_nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["part"] == part && n["index"] == 0 && n["text"] == text)
}
fn exact_except(before: &Members, after: &Members, part: &str, expected: &[u8]) {
    assert_eq!(before.len(), after.len());
    for (name, data) in before {
        assert_eq!(
            after[name],
            if name == part {
                expected
            } else {
                data.as_slice()
            },
            "changed member {name}"
        );
    }
}
fn fail_commit(f: &Fixture, patches: &Value) {
    let before = fs::read(&f.source).unwrap();
    let mut reached = false;
    let e = d::edit_package_observed(&f.source, &f.output, patches, &[], |event| {
        if matches!(
            event,
            d::EditEvent::Publication {
                boundary: Boundary::BeforeCommit,
                ..
            }
        ) {
            reached = true;
            anyhow::bail!("injected publication failure");
        }
        Ok(())
    });
    assert!(e.is_err());
    assert!(
        reached,
        "publication failure must reach the real commit boundary"
    );
    assert_eq!(fs::read(&f.source).unwrap(), before);
    f.clean();
}
fn batch(f: &Fixture, count: usize) -> Members {
    let mut m = base();
    let body = format!(
        "<!-- untouched -->{}",
        (0..count)
            .map(|i| format!("<w:p><w:r><w:t>Original {i}</w:t></w:r></w:p>"))
            .collect::<String>()
    );
    m.insert("word/document.xml".into(), document(&body));
    m.insert(
        "word/header1.xml".into(),
        format!(
            "<w:hdr xmlns:w=\"{}\"><w:p><w:r><w:t>Header</w:t><w:t/></w:r></w:p></w:hdr>",
            d::W
        )
        .into_bytes(),
    );
    f.write(&m);
    m
}
fn edits(count: usize) -> Value {
    Value::Array((0..count).rev().map(|i|json!({"part":"word/document.xml","index":i,"expected":format!("Original {i}"),"text":format!("ترجمه {i}")})).collect())
}
fn content(run: Value) -> Value {
    json!({"sections":[{"width_mm":210,"height_mm":297,"margins_mm":{"top":20,"bottom":20,"left":20,"right":20},"header":{"runs":[run]},"footer":{"runs":[run]},"blocks":[{"type":"paragraph","runs":[run]},{"type":"table","rows":[[{"runs":[run]},{"text":"علم"}]]}]}]})
}
fn create(f: &Fixture, content: &Value) -> PathBuf {
    let source = f.root.join("content.json");
    fs::write(&source, serde_json::to_vec(content).unwrap()).unwrap();
    d::create_document(&source, &f.source).unwrap();
    source
}
const SIG: &str = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/";
struct Feature {
    mime: String,
    relation: String,
    payload: &'static [u8],
}
fn features() -> Vec<Feature> {
    let mut features = vec![
        Feature {
            mime: "application/vnd.openxmlformats-package.digital-signature-origin".into(),
            relation: format!("{SIG}origin"),
            payload: b"",
        },
        Feature {
            mime: "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml"
                .into(),
            relation: format!("{SIG}signature"),
            payload: b"<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"/>",
        },
        Feature {
            mime: "application/vnd.openxmlformats-package.digital-signature-certificate".into(),
            relation: format!("{SIG}certificate"),
            payload: b"opaque synthetic certificate, not authenticated",
        },
    ];
    for (name, uri) in [
        (
            "vbaProject",
            "http://schemas.microsoft.com/office/2006/relationships/vbaProject",
        ),
        (
            "vbaProjectSignature",
            "http://schemas.microsoft.com/office/2006/relationships/vbaProjectSignature",
        ),
        (
            "vbaProjectSignatureAgile",
            "http://schemas.microsoft.com/office/2006/relationships/vbaProjectSignatureAgile",
        ),
        (
            "vbaProjectSignatureAgile",
            "http://schemas.microsoft.com/office/2014/relationships/vbaProjectSignatureAgile",
        ),
        (
            "vbaProjectSignatureV3",
            "http://schemas.microsoft.com/office/2020/07/relationships/vbaProjectSignatureV3",
        ),
    ] {
        features.push(Feature {
            mime: format!("application/vnd.ms-office.{name}"),
            relation: uri.into(),
            payload: b"opaque synthetic VBA metadata",
        });
    }
    features
}

#[path = "docx_native/docx.rs"]
mod docx;
#[path = "docx_native/docx_batch_scaling.rs"]
mod docx_batch_scaling;
#[path = "docx_native/docx_feature_identity.rs"]
mod docx_feature_identity;
#[path = "docx_native/docx_script_formatting.rs"]
mod docx_script_formatting;
#[path = "docx_native/docx_signature_identity.rs"]
mod docx_signature_identity;
#[path = "docx_native/docx_story_parts.rs"]
mod docx_story_parts;
#[path = "docx_native/docx_story_render.rs"]
mod docx_story_render;
#[path = "docx_native/native_docx_boundaries.rs"]
mod native_docx_boundaries;
#[path = "docx_native/native_docx_creation.rs"]
mod native_docx_creation;
