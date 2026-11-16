//! Subject-bound facade over the shared byte parser. A subject is metadata,
//! never evidence that the file was loaded or that a native stage executed.
use super::*;
pub struct KernelImage<'a> {
    pub(super) pe: PeImage<'a>,
    pub(super) subject: &'static str,
}
impl<'a> KernelImage<'a> {
    pub fn from_static(bytes: &'a [u8]) -> Result<Self> {
        Self::with_subject(bytes, 1, "kernelbase.dll")
    }
    pub fn from_activation_worker(bytes: &'a [u8]) -> Result<Self> {
        Self::with_subject(bytes, 1, "kernel32.dll")
    }
    pub fn with_subject(bytes: &'a [u8], base: u64, subject: &str) -> Result<Self> {
        let subject = match subject {
            "kernelbase.dll" => "kernelbase.dll",
            "kernel32.dll" => "kernel32.dll",
            "ntdll.dll" => "ntdll.dll",
            _ => anyhow::bail!("unsupported fixed image subject"),
        };
        Ok(Self {
            pe: PeImage::parse(bytes, base)?,
            subject,
        })
    }
    pub fn kernelbase_identity(&self) -> Result<String> {
        ensure!(
            self.subject == "kernelbase.dll",
            "wrong KernelBase identity subject"
        );
        self.pe.kernelbase_identity()
    }
    pub fn kernel32_identity(&self) -> Result<String> {
        ensure!(
            self.subject == "kernel32.dll",
            "wrong activation-worker identity subject"
        );
        self.pe.kernel32_identity()
    }
    pub fn entry_slice(&self) -> Result<StaticSlice> {
        ensure!(
            self.subject == "kernelbase.dll" && self.pe.entry != 0,
            "wrong static entry subject"
        );
        self.pe.static_slice(self.pe.entry)
    }
    pub fn contains_executable(&self, address: u64) -> bool {
        address >= self.pe.base
            && address - self.pe.base < u64::from(self.pe.image_size)
            && self.pe.executable((address - self.pe.base) as u32, 1)
    }
    pub fn activation_worker_slice(&self) -> Result<StaticSlice> {
        ensure!(
            self.subject == "kernel32.dll",
            "wrong activation-worker subject"
        );
        self.pe.activation_worker_slice()
    }
    pub fn qualify_static(&self, text: &str) -> Result<StaticView> {
        self.pe.qualify_static(text, self.entry_slice()?)
    }
    pub fn qualify_static_slice(&self, text: &str, slice: StaticSlice) -> Result<StaticView> {
        self.pe.qualify_static(text, slice)
    }
}
