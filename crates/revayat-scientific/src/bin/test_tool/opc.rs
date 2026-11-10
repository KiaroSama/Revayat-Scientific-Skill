//! Independent native OPC consumer, always invoked under the test runtime owner.
use anyhow::{Result, ensure};
use std::{os::windows::ffi::OsStrExt, path::Path};
use windows::{
    Win32::{
        Storage::{
            FileSystem::FILE_ATTRIBUTE_NORMAL,
            Packaging::Opc::{
                IOpcFactory, OPC_READ_DEFAULT, OPC_STREAM_IO_READ, OPC_URI_TARGET_MODE_INTERNAL,
                OpcFactory,
            },
        },
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoTaskMemFree, CoUninitialize,
        },
    },
    core::{PCWSTR, PWSTR, w},
};

const CHUNK: &[u8] = b"<html><body>bounded independent OPC control</body></html>";

struct Apartment;
impl Apartment {
    fn initialize() -> Result<Self> {
        // SAFETY: this child thread owns the matching uninitialization below.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok()?;
        Ok(Self)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}
struct TaskString(PWSTR);
impl Drop for TaskString {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(Some(self.0.0.cast())) };
    }
}
fn allocated_text(value: PWSTR) -> Result<String> {
    let owned = TaskString(value);
    ensure!(!owned.0.is_null(), "OPC returned a null string");
    // SAFETY: OPC returns a terminated CoTaskMem string; ownership stays live.
    Ok(unsafe { owned.0.to_string() }?)
}

pub(super) fn consume(path: &Path) -> Result<()> {
    let _apartment = Apartment::initialize()?;
    let name = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: official typed, in-process Windows OPC APIs; live UTF-16 filename
    // and an authored bounded package. No Revayat ZIP/XML reader is used here.
    unsafe {
        let factory: IOpcFactory = CoCreateInstance(&OpcFactory, None, CLSCTX_INPROC_SERVER)?;
        let stream = factory.CreateStreamOnFile(
            PCWSTR(name.as_ptr()),
            OPC_STREAM_IO_READ,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL.0,
        )?;
        let package = factory.ReadPackageFromStream(&stream, OPC_READ_DEFAULT)?;
        let parts = package.GetPartSet()?;
        let document_uri = factory.CreatePartUri(w!("/word/document.xml"))?;
        let document = parts.GetPart(&document_uri)?;
        let relationships = document.GetRelationshipSet()?.GetEnumerator()?;
        ensure!(
            relationships.MoveNext()?.as_bool(),
            "case-variant OPC relationship was not recognized"
        );
        let relationship = relationships.GetCurrent()?;
        ensure!(
            !relationships.MoveNext()?.as_bool(),
            "case-variant OPC relationship was not recognized exactly once"
        );
        ensure!(
            allocated_text(relationship.GetId()?)? == "rIdControlled",
            "OPC relationship id differs"
        );
        ensure!(
            allocated_text(relationship.GetRelationshipType()?)?
                == "http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk",
            "OPC relationship type differs"
        );
        ensure!(
            relationship.GetTargetMode()? == OPC_URI_TARGET_MODE_INTERNAL,
            "OPC target is external"
        );
        let resolved = relationship
            .GetSourceUri()?
            .CombinePartUri(&relationship.GetTargetUri()?)?;
        ensure!(
            resolved.GetPath()? == "/word/chunk.html",
            "OPC resolved another target"
        );
        let chunk = parts.GetPart(&resolved)?.GetContentStream()?;
        let mut data = [0u8; 256];
        let mut count = 0;
        chunk
            .Read(
                data.as_mut_ptr().cast(),
                data.len() as u32,
                Some(&mut count),
            )
            .ok()?;
        ensure!(
            (count as usize) <= data.len(),
            "OPC content read exceeded supplied buffer"
        );
        ensure!(
            data[..count as usize] == *CHUNK,
            "independent OPC chunk bytes differ"
        );
        let mut eof = 1;
        chunk
            .Read(data.as_mut_ptr().cast(), 1, Some(&mut eof))
            .ok()?;
        ensure!(eof == 0, "OPC chunk had an unqualified tail");
    }
    println!("OPC_CASE_RELATIONSHIP_RECOGNIZED");
    Ok(())
}
