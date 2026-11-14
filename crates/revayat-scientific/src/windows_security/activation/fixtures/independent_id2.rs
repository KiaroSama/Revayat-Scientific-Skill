//! Actual supplementary NoCRT compilation with uninterrupted held source/tool/image inputs.
//! Compilation/PE qualification alone never proves that an entry or CSR event executed.
use super::*;
use crate::windows_security::activation::fixtures::source;

const SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/security/windows/native-fixtures/independent_id2.rs"
));
pub const SOURCE_SHA256: &str = "20548ee4a4ef07501906b7e6438b4c3de426d25f9534ed6eb6e2c52736569353";

/// Only this actual compiler path constructs the token. The owner retains every
/// descriptor until explicit close, including while the native observer borrows it.
pub struct CompiledIndependentId2 {
    image: PathBuf,
    inputs: Option<Inputs>,
}
pub struct HeldIndependentId2<'a> {
    owner: &'a mut CompiledIndependentId2,
}
impl CompiledIndependentId2 {
    pub fn build(tools: &mut DiscoveredRustTools, work: &Path) -> Result<Self> {
        io::plain(work, false)?;
        ensure!(work.is_dir(), "independent ID2 work directory is absent");
        tools.verify()?;
        let folder = work.join("independent-id2-build");
        owned::directory(&folder)?;
        let image = folder.join("startup-independent-id2.exe");
        let mut inputs = Inputs::new();
        let result = (|| {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/security/windows/native-fixtures/independent_id2.rs");
            copy_pinned(
                &mut inputs,
                &folder,
                &path,
                "main.rs",
                SOURCE,
                SOURCE_SHA256,
            )?;
            for name in ["abi.rs", "builtins.rs", "emit.rs"] {
                let (text, digest) = source::pinned(name)?;
                copy_pinned(
                    &mut inputs,
                    &folder,
                    &source::owned_directory().join(name),
                    name,
                    text,
                    digest,
                )?;
            }
            let resource = folder.join("independent-id2.res");
            let bytes = Bytes(source::resource_bytes(
                1033,
                2,
                image::INDEPENDENT_ID2_MANIFEST,
            )?);
            inputs.create(&resource, &bytes.0, 131072)?;
            compile(
                tools,
                &mut inputs,
                &folder,
                &image,
                LinkRole::IndependentId2(&resource),
            )?;
            let bytes = Bytes(inputs.bytes(&image)?);
            PeImage::parse(&bytes.0, 1)?.qualify_independent_id2()?;
            inputs.verify()?;
            tools.verify()
        })();
        if let Err(primary) = result {
            inputs.finish::<()>(Err(primary))?;
            unreachable!("primary compiler failure retained")
        }
        Ok(Self {
            image,
            inputs: Some(inputs),
        })
    }
    pub fn hold(&mut self) -> Result<HeldIndependentId2<'_>> {
        self.verify()?;
        Ok(HeldIndependentId2 { owner: self })
    }
    fn verify(&mut self) -> Result<()> {
        io::no_overrides(&self.image)?;
        let inputs = self
            .inputs
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("independent ID2 owner is closed"))?;
        inputs.verify()?;
        let bytes = Bytes(inputs.bytes(&self.image)?);
        PeImage::parse(&bytes.0, 1)?.qualify_independent_id2()
    }
    pub fn close(mut self) -> Result<()> {
        self.finish()
    }
    fn finish(&mut self) -> Result<()> {
        self.inputs
            .take()
            .map_or(Ok(()), |mut inputs| inputs.finish(Ok(())))
    }
}
impl Drop for CompiledIndependentId2 {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}
impl HeldIndependentId2<'_> {
    pub(crate) fn image(&self) -> &Path {
        &self.owner.image
    }
    pub(crate) fn verify(&mut self) -> Result<()> {
        self.owner.verify()
    }
}
fn copy_pinned(
    inputs: &mut Inputs,
    folder: &Path,
    path: &Path,
    destination: &str,
    expected: &str,
    digest: &str,
) -> Result<()> {
    inputs.open(path, 65536)?;
    let bytes = Bytes(inputs.bytes(path)?);
    let text = std::str::from_utf8(&bytes.0)?.replace("\r\n", "\n");
    ensure!(
        text == expected && !text.contains('\r') && io::digest(text.as_bytes()) == digest,
        "independent ID2 source differs from reviewed Rust pin"
    );
    inputs.create(&folder.join(destination), text.as_bytes(), 65536)
}
