//! Supplementary NoCRT own-module ID2 qualifier, independent of original Python roles.
use super::*;

pub const INDEPENDENT_ID2_MANIFEST: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity type=\"win32\" version=\"1.0.0.0\" processorArchitecture=\"amd64\" name=\"Scientific.Security.ExplicitId2\"/></assembly>\n";
const IMPORTS: &[&str] = &[
    "CreateActCtxW",
    "ExitProcess",
    "GetCommandLineW",
    "GetLastError",
    "GetModuleHandleW",
    "GetStdHandle",
    "ReleaseActCtx",
    "WriteFile",
];

impl PeImage<'_> {
    pub fn qualify_independent_id2(&self) -> Result<()> {
        // Reuse the strict original descriptor/thunk/parser gates; this is a
        // separate eight-import subject, never the seven-import Python role.
        self.child_activation_imports(IMPORTS, true)?;
        self.qualify_explicit_id2()
    }
}

fn fixture() -> Vec<u8> {
    use crate::windows_security::activation::self_result::SelfRole;
    let mut bytes = self_activation_validation_fixture(SelfRole::ExplicitId2);
    long(&mut bytes, 0x2b8, 0x1700);
    long(&mut bytes, 0x338, 0x1700);
    text(&mut bytes, 0x902, "GetCommandLineW\0");
    put(&mut bytes, 0x11c, 0x180);
    put(&mut bytes, 0xb64, INDEPENDENT_ID2_MANIFEST.len() as u32);
    bytes[0xb80..0xb80 + INDEPENDENT_ID2_MANIFEST.len()].copy_from_slice(INDEPENDENT_ID2_MANIFEST);
    bytes
}

/// Synthetic PE checks only; no result here attests compilation or native CSR.
pub fn check_independent_id2_validation() -> Result<()> {
    ensure!(
        INDEPENDENT_ID2_MANIFEST.len() == 243
            && sha256(INDEPENDENT_ID2_MANIFEST)
                == "34a80b2520ff37279dd9ebf0d8227f22691b7c7b80ce3d28b1e1200a3fefca27",
        "independent ID2 payload differs"
    );
    let bytes = fixture();
    let check = |bytes: &[u8]| PeImage::parse(bytes, 1)?.qualify_independent_id2();
    check(&bytes)?;
    ensure!(
        PeImage::parse(
            &self_activation_validation_fixture(
                crate::windows_security::activation::self_result::SelfRole::ExplicitId2
            ),
            1
        )?
        .qualify_independent_id2()
        .is_err(),
        "original seven-import role accepted as independent NoCRT control"
    );
    refuse(
        &bytes,
        &[
            Short(0x96, 0x2002),
            Short(0xdc, 2),
            Short(0xde, 0),
            Word(0xa8, 0),
            Word(0x108, 0x1000),
            Word(0x150, 0x1000),
            Word(0x170, 0x1000),
            Word(0x178, 0x1000),
            Word(0x114, 39),
            Word(0x214, 1),
            Xor(0x500),
            Xor(0x902),
            Xor(0x338),
            Group(vec![Zero(0x2b8, 8), Zero(0x338, 8)]),
            Group(vec![Copy(0x280, 0x2b8, 8), Copy(0x300, 0x338, 8)]),
            Word(0xb10, 23),
            Word(0xb30, 1),
            Word(0xb50, 1034),
            Short(0xb4e, 2),
            Word(0xb64, 242),
            Xor(0xb80),
        ],
        check,
    )
}
