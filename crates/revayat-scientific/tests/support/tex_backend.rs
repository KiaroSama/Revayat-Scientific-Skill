//! Reusable detached TeX protocol model; its rendered PDF is self-contained.
use anyhow::{Result, bail};
use revayat_scientific::tex_container as tex;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};
pub(crate) fn pdf(path: &Path) -> Result<()> {
    use lopdf::{Document, Object, Stream, dictionary};
    let mut d = Document::with_version("1.7");
    let pages = d.new_object_id();
    let font =
        d.add_object(dictionary! {"Type"=>"Font","Subtype"=>"Type1","BaseFont"=>"Helvetica"});
    let stream = d.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 20 250 Td (Staged revision) Tj ET".to_vec(),
    ));
    let page=d.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"MediaBox"=>vec![Object::from(0),Object::from(0),Object::from(250),Object::from(360)],"Contents"=>stream,"Resources"=>dictionary!{"Font"=>dictionary!{"F1"=>font}}});
    d.objects.insert(
        pages,
        dictionary! {"Type"=>"Pages","Kids"=>vec![Object::Reference(page)],"Count"=>1}.into(),
    );
    let catalog = d.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
    d.trailer.set("Root", catalog);
    d.save(path)?;
    Ok(())
}
pub(crate) struct Backend {
    pub(crate) alive: bool,
    pub(crate) run: String,
    pub(crate) calls: usize,
    pub(crate) cleanup_calls: usize,
    pub(crate) code: i32,
    pub(crate) invalid: bool,
    pub(crate) cleanup_fail: bool,
    pub(crate) timeout: bool,
    pub(crate) corrupt_chunk: bool,
    pub(crate) corrupt_hash: bool,
    pub(crate) directory: PathBuf,
}
impl Backend {
    pub(crate) fn new() -> Self {
        Self {
            alive: false,
            run: String::new(),
            calls: 0,
            cleanup_calls: 0,
            code: 0,
            invalid: false,
            cleanup_fail: false,
            timeout: false,
            corrupt_chunk: false,
            corrupt_hash: false,
            directory: PathBuf::new(),
        }
    }
    pub(crate) fn execute(&mut self, args: &[String], _: u64) -> Result<(i32, String)> {
        if args.iter().any(|s| s == "run") {
            self.calls += 1;
            self.alive = true;
            self.run = args[args.iter().position(|s| s == "--name").unwrap() + 1]
                .trim_start_matches("revayat-tex-")
                .into();
            let directory =
                Path::new(&args[args.iter().position(|s| s == "--cidfile").unwrap() + 1])
                    .parent()
                    .unwrap();
            self.directory = directory.to_owned();
            fs::write(directory.join("container.cid"), "a".repeat(64))?;
            fs::create_dir(directory.join("container-output"))?;
            return Ok((0, "a".repeat(64)));
        }
        if args.iter().any(|s| s == "exec") {
            if let Some(index) = args.iter().position(|s| s == "--output-manifest") {
                let files = args[index + 1..]
                    .iter()
                    .filter_map(|name| {
                        let path = self.directory.join("container-output").join(name);
                        path.metadata()
                            .ok()
                            .map(|metadata| json!({"name":name,"size":metadata.len(),"sha256":if self.corrupt_hash { "0".repeat(64) } else { revayat_scientific::build::file_hash(&path).unwrap() }}))
                    })
                    .collect::<Vec<_>>();
                return Ok((0, serde_json::to_string(&files)?));
            }
            if let Some(index) = args.iter().position(|s| s == "--read-output") {
                use base64::Engine;
                if self.corrupt_chunk {
                    return Ok((0, "!!!!".into()));
                }
                let bytes = fs::read(
                    self.directory
                        .join("container-output")
                        .join(&args[index + 1]),
                )?;
                let offset: usize = args[index + 2].parse()?;
                let count: usize = args[index + 3].parse()?;
                return Ok((
                    0,
                    base64::engine::general_purpose::STANDARD
                        .encode(&bytes[offset..offset + count]),
                ));
            }
            if self.timeout {
                return Err(revayat_scientific::runtime::DeadlineExceeded {
                    idle: false,
                    limit: std::time::Duration::from_secs(150),
                }
                .into());
            }
            let output = self.directory.join("container-output/document.pdf");
            if self.invalid {
                fs::write(output, b"%PDF-1.7\ntruncated")?;
            } else {
                pdf(&output)?;
            }
            if self.code != 0 {
                fs::write(
                    self.directory.join("container-output/console-pass-1.log"),
                    b"Undefined control sequence\nl.9 PRIVATE_MANUSCRIPT_LINE",
                )?;
            }
            return Ok((self.code, String::new()));
        }
        if args.iter().any(|s| s == "ps") {
            if self.cleanup_fail {
                bail!("daemon unavailable");
            }
            return Ok((
                0,
                if self.alive {
                    "a".repeat(64)
                } else {
                    String::new()
                },
            ));
        }
        if args.iter().any(|s| s == "inspect") {
            return Ok((0,json!([{"Id":"a".repeat(64),"Name":format!("/revayat-tex-{}",self.run),"Config":{"Labels":{tex::RUN_LABEL:self.run}}}]).to_string()));
        }
        if args.iter().any(|s| s == "rm") {
            self.cleanup_calls += 1;
            self.alive = false;
            return Ok((0, String::new()));
        }
        bail!("unexpected fake runtime query")
    }
}
