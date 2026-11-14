//! Original ntdll CSR export and wrong-subject mutation matrix.
use super::*;

pub(in crate::windows_security::image) fn check_csr_export_validation() -> Result<()> {
    let mut bytes = worker();
    bytes[0x480..0x501].fill(0);
    text(&mut bytes, 0x480, "CsrClientCallServer\0");
    ensure!(
        KernelImage::with_subject(&bytes, 0x10000000, "ntdll.dll")?.csr_dispatch_export()?
            == 0x10001020,
        "CSR ntdll export product differs"
    );
    refuse(
        &bytes,
        &[
            Word(0x108, 0),
            Word(0x10c, 39),
            Word(0x414, 4097),
            Word(0x418, 4097),
            Short(0x458, 2),
            Word(0x440, 0x1200),
            Word(0x440, 0x2000),
            Xor(0x480),
            Word(0x450, u32::MAX),
            Word(0x41c, u32::MAX),
            Word(0x1ac, 0x40000040),
            Group(vec![Word(0x418, 2), Word(0x454, 0x1280), Short(0x45a, 1)]),
            Group(vec![
                Word(0x418, 2),
                Word(0x454, 0x12b0),
                Short(0x45a, 0),
                Text(0x4b0, "OtherExport\0"),
            ]),
        ],
        |bad| {
            KernelImage::with_subject(bad, 0x10000000, "ntdll.dll")?
                .csr_dispatch_export()
                .map(|_| ())
        },
    )?;
    ensure!(
        KernelImage::from_activation_worker(&bytes)?
            .csr_dispatch_export()
            .is_err(),
        "CSR target admitted kernel32 subject"
    );
    Ok(())
}
