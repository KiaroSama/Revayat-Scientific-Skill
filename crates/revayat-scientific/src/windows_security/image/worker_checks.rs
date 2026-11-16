//! Full original activation-worker parser/static assertion root. The synthetic
//! PE is inspected only; hash/subject qualification is never inferred from it.
use super::*;

pub fn check_activation_worker_validation() -> Result<()> {
    let bytes = worker();
    let image = KernelImage::from_activation_worker(&bytes)?;
    let slice = image.activation_worker_slice()?;
    ensure!(
        slice.rva == 0x1020
            && slice.start == 0x180001020
            && slice.raw == 0x220
            && slice.length == 1504,
        "activation-worker positive slice differs"
    );
    let view = image.qualify_static_slice(
        concat!(
            "Dump of file C:\\private\\kernel32.dll\n",
            "  0000000180001020: B8 01 00 00 00     mov eax,1\n",
            "  0000000180001025: E9 D6 FF FF FF     jmp 0000000180001000\n"
        ),
        slice,
    )?;
    ensure!(
        view.records == 2
            && view.unsupported == 0
            && view.text
                == concat!(
                    "rva=0x00001020 bytes=B801000000 mnemonic=mov operands=eax,1\n",
                    "rva=0x00001025 bytes=E9D6FFFFFF mnemonic=jmp operands=rva:0x00001000\n"
                )
            && !view.text.contains("private")
            && !view.text.contains("18000")
            && !view.text.contains('\\'),
        "activation-worker static positive or redaction differs"
    );
    let identity = image.kernel32_identity()?;
    ensure!(
        identity.starts_with("phase=image-identity module=kernel32.dll sha256=")
            && identity.ends_with(" pe_timestamp=305419896 image_size=8192 file_size=2048")
            && identity.len() < 256
            && !identity.contains("pdb")
            && !identity.contains('\\'),
        "activation-worker identity differs"
    );
    let mut drift = bytes.clone();
    drift[0x700] ^= 1;
    ensure!(
        KernelImage::from_activation_worker(&drift)?.kernel32_identity()? != identity,
        "activation-worker identity missed unrelated drift"
    );
    let partial = image.qualify_static_slice(
        concat!(
            "  0000000180001020: B8 01     mov eax,1\n       00 00 00\n",
            "  0000000180001025: E9 D6 FF FF FF     jmp 0000000180001000\n"
        ),
        slice,
    )?;
    ensure!(
        partial.records == 1
            && partial.unsupported == 1
            && partial.text
                == "rva=0x00001025 bytes=E9D6FFFFFF mnemonic=jmp operands=rva:0x00001000\n",
        "ambiguous activation-worker prefix was retained"
    );
    refuse(
        &bytes,
        &[
            Word(0x108, 0),
            Word(0x108, u32::MAX),
            Word(0x10c, 39),
            Word(0x10c, 1048577),
            Word(0x400, 1),
            Word(0x414, 0),
            Word(0x414, 4097),
            Word(0x418, 0),
            Word(0x418, 4097),
            Word(0x410, u32::MAX),
            Word(0x41c, u32::MAX),
            Word(0x420, u32::MAX),
            Word(0x424, u32::MAX),
            Short(0x458, 2),
            Word(0x450, 0),
            Word(0x450, u32::MAX),
            Byte(0x480, b'X'),
            Byte(0x480, 0),
            Byte(0x480, 0x80),
            Group((0..129).map(|index| Byte(0x480 + index, b'A')).collect()),
            Group(vec![Word(0x418, 2), Word(0x454, 0x1280), Short(0x45a, 0)]),
            Word(0x440, 0),
            Word(0x440, 0x1300),
            Word(0x440, 0x1600),
            Word(0x440, 0x2000),
            Word(0x440, u32::MAX),
            Word(0x1ac, 0x40000040),
            Word(0x190, 0x20),
            Word(0x19c, 0x100),
            Zero(0xb0, 8),
            Long(0xb0, u64::MAX),
            Word(0x178, 1),
            Short(0x96, 2),
        ],
        |bad| {
            KernelImage::from_activation_worker(bad)?
                .activation_worker_slice()
                .map(|_| ())
        },
    )?;
    let mut forward_start = bytes.clone();
    put(&mut forward_start, 0x440, 0x1200);
    ensure!(
        KernelImage::from_activation_worker(&forward_start)?
            .activation_worker_slice()
            .is_err(),
        "export directory start was accepted as a code target"
    );
    let mut ordinal = bytes.clone();
    short(&mut ordinal, 0x458, 1);
    put(&mut ordinal, 0x444, 0x1020);
    put(&mut ordinal, 0x440, 0);
    ensure!(
        KernelImage::from_activation_worker(&ordinal)?
            .activation_worker_slice()?
            .rva
            == 0x1020,
        "name ordinal was biased by public export base7"
    );
    let mut second = bytes.clone();
    for (at, n) in [(0x418, 2), (0x450, 0x12b0), (0x454, 0x1280)] {
        put(&mut second, at, n);
    }
    short(&mut second, 0x458, 1);
    short(&mut second, 0x45a, 0);
    text(&mut second, 0x4b0, "OtherExport\0");
    ensure!(
        KernelImage::from_activation_worker(&second)?
            .activation_worker_slice()?
            .rva
            == 0x1020,
        "unselected export altered selected ordinal"
    );
    let mut clipped = bytes.clone();
    put(&mut clipped, 0x190, 0x30);
    ensure!(
        KernelImage::from_activation_worker(&clipped)?
            .activation_worker_slice()?
            .length
            == 16,
        "activation-worker virtual clipping differs"
    );
    let mut large = bytes.clone();
    large.resize(8192, 0);
    for (at, n) in [(0x190, 6144), (0x198, 6144), (0xd0, 12288)] {
        put(&mut large, at, n);
    }
    ensure!(
        KernelImage::from_activation_worker(&large)?
            .activation_worker_slice()?
            .length
            == 4096,
        "activation-worker slice exceeded fixed4096 cap"
    );
    for invalid in [
        "",
        "  0000000180001020: C3     ret\n",
        "  0000000180001000: B8     mov eax,1\n",
    ] {
        ensure!(
            image.qualify_static_slice(invalid, slice).is_err(),
            "invalid activation-worker static text accepted"
        );
    }
    let mut tampered = slice;
    tampered.raw += 1;
    ensure!(
        image
            .qualify_static_slice(
                "  0000000180001020: B8 01 00 00 00     mov eax,1\n",
                tampered
            )
            .is_err(),
        "tampered activation-worker slice accepted"
    );
    ensure!(
        KernelImage::from_static(&bytes)?
            .activation_worker_slice()
            .is_err(),
        "KernelBase static subject accepted a Kernel32 worker role"
    );
    Ok(())
}
