//! Original KernelImage identity/static assertion roots, callable by bootstrap.
use super::*;
pub fn check_identity_validation() -> Result<()> {
    ensure!(
        sha256(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "independent SHA literal differs"
    );
    let b = identity();
    let line =
        KernelImage::with_subject(&b, 0x10000000, "kernelbase.dll")?.kernelbase_identity()?;
    ensure!(
        line.contains(
            "pdb_guid=00112233-4455-6677-8899-aabbccddeeff pdb_age=7 pdb_name=kernelbase.pdb"
        ) && line.ends_with("pe_timestamp=305419896 image_size=8192 file_size=2048")
            && line.len() < 512
            && !line.contains(['\\', '/'])
            && !line.contains("0x10000000"),
        "original cached identity differs"
    );
    let check = |bytes: &[u8]| {
        KernelImage::with_subject(bytes, 0x10000000, "kernelbase.dll")?
            .kernelbase_identity()
            .map(|_| ())
    };
    let mut changed = b.clone();
    changed[0x700] = 1;
    ensure!(
        KernelImage::from_static(&changed)?.kernelbase_identity()? != line,
        "cached identity missed unrelated byte drift"
    );
    refuse(
        &b,
        &[
            Word(0x138, 0),
            Word(0x13c, 27),
            Word(0x400, 1),
            Word(0x13c, 65 * 28),
            Word(0x13c, u32::MAX),
            Word(0x40c, 1),
            Word(0x410, 24),
            Word(0x410, 513),
            Word(0x414, 0x1281),
            Word(0x418, 0x481),
            Word(0x418, u32::MAX),
            Word(0x480, 0x3031424e),
            Zero(0x484, 16),
            Word(0x494, 0),
            Byte(0x498, b'X'),
            Byte(0x498, b'/'),
            Byte(0x499, 0),
            Byte(0x4a6, b'X'),
            Word(0x410, 40),
            Group(vec![Word(0x13c, 56), Copy(0x400, 0x41c, 28)]),
            Group(vec![
                Word(0x13c, 56),
                Copy(0x400, 0x41c, 28),
                Word(0x430, 0x1300),
                Word(0x434, 0x500),
                Copy(0x480, 0x500, 39),
            ]),
            Group(vec![Word(0x414, 0), Word(0x418, 0)]),
            Group(vec![Word(0x410, 0), Word(0x414, 0), Word(0x418, 0)]),
            Group(vec![Word(0x414, 0x1200), Word(0x418, 0x400)]),
        ],
        check,
    )?;
    let mut empty = b.clone();
    put(&mut empty, 0x13c, 56);
    put(&mut empty, 0x428, 16);
    ensure!(
        KernelImage::from_static(&empty)?
            .kernelbase_identity()?
            .contains("pdb_age=7"),
        "empty REPRO record refused"
    );
    let mut file = b.clone();
    for (at, n) in [(0x13c, 56), (0x428, 1), (0x42c, 4), (0x434, 0x600)] {
        put(&mut file, at, n);
    }
    ensure!(
        KernelImage::from_static(&file)?
            .kernelbase_identity()?
            .contains("pdb_age=7"),
        "bounded file-only debug record refused"
    );
    refuse(
        &file,
        &[
            Word(0x434, 0),
            Word(0x434, u32::MAX),
            Word(0x434, 0x480),
            Word(0x430, 0x1401),
            Word(0x414, 0),
        ],
        check,
    )?;
    let mut next = b.clone();
    put(&mut next, 0x494, 8);
    let next = KernelImage::from_static(&next)?.kernelbase_identity()?;
    ensure!(
        next.contains("pdb_age=8")
            && !next.contains("pdb_age=7")
            && KernelImage::from_static(&b)?.kernelbase_identity()? == line,
        "cached identity reused another image"
    );
    ensure!(
        KernelImage::with_subject(&b, 0x10000000, "ntdll.dll")?
            .kernelbase_identity()
            .is_err(),
        "wrong cached-image subject accepted"
    );
    Ok(())
}
pub fn check_static_validation() -> Result<()> {
    let b = static_image();
    let image = KernelImage::from_static(&b)?;
    let slice = image.entry_slice()?;
    ensure!(
        slice.start == 0x180001000 && slice.length == 1536 && slice.raw == 512,
        "original static slice differs"
    );
    let view=image.qualify_static("Dump of file C:\\private\\KernelBase.dll\r\nFile Type: DLL\r\n\r\n  0000000180001000: B8 00 00 00 00     mov eax,0\r\n  0000000180001005: C3                 ret\r\n")?;
    ensure!(
        view.records == 2
            && view.unsupported == 0
            && view.text
                == "rva=0x00001000 bytes=B800000000 mnemonic=mov operands=eax,0\nrva=0x00001005 bytes=C3 mnemonic=ret operands=none\n"
            && !view.text.contains("private")
            && !view.text.contains("18000")
            && !view.text.contains('\\'),
        "static positive or redaction differs"
    );
    const RET: &str = "rva=0x00001005 bytes=C3 mnemonic=ret operands=none\n";
    for (input, unsupported) in [
        (
            "  0000000180001000: B8 00 00 00 00     mov eax,0\nunknown label:\n  0000000180001005: C3     ret\n",
            1,
        ),
        (
            "  0000000180001000: B8 00     mov eax,0\n       00 00\n       00\n  0000000180001005: C3     ret\n",
            2,
        ),
        (
            "  0000000180001000: B8 00     mov eax,0\n\n       00 00 00\n  0000000180001005: C3     ret\n",
            1,
        ),
        ("  0000000180001005: C3     ret\n\n", 0),
        ("       FF\n  0000000180001005: C3     ret\n", 1),
        (
            "  0000000180001000: B8 00     mov eax,0\n       00\n  0000000180001005: C3     ret\n\n  0000000180001006: E8 F5     call 0000000180001000\n       FF FF FF\n",
            2,
        ),
        (
            "  0000000180001005: C3     ret\n  00000001800015FF: 00 00     mov al,al\n",
            1,
        ),
        (
            "  0000000180001005: C3     ret\n  0000000180001006: E8 F5 FF FF FF     bogus\n\u{202e}private\n",
            2,
        ),
    ] {
        let v = image.qualify_static(input)?;
        ensure!(
            v.records == 1 && v.unsupported == unsupported && v.text == RET,
            "original static framing case differs"
        );
    }
    let branch =
        image.qualify_static("  0000000180001006: E8 F5 FF FF FF     call 0000000180001000\n")?;
    ensure!(
        branch.unsupported == 0
            && branch.text
                == "rva=0x00001006 bytes=E8F5FFFFFF mnemonic=call operands=rva:0x00001000\n",
        "static branch operand differs"
    );
    let private =
        image.qualify_static("  0000000180001005: C3     ret C:\\private\\secret.dll\n")?;
    ensure!(
        private.unsupported == 1
            && private.text == "rva=0x00001005 bytes=C3 mnemonic=ret operands=withheld\n",
        "private operand escaped"
    );
    for (input, expected) in [
        (
            "",
            "static qualifier refused stage=no-qualified-record lines=0 records=0 unsupported=0 output_chars=0 text_chars=0",
        ),
        (
            "Dump of file C:\\private\\KernelBase.dll\n",
            "static qualifier refused stage=no-qualified-record lines=1 records=0 unsupported=0 output_chars=0 text_chars=39",
        ),
        (
            "  0000000180001000: B8 00 00 00 00     mov eax,0\n                    00\n",
            "static qualifier refused stage=no-qualified-record lines=2 records=0 unsupported=1 output_chars=0 text_chars=72",
        ),
        (
            "  0000000180001000: C3     ret\n",
            "static qualifier refused stage=byte-equality lines=1 records=0 unsupported=0 output_chars=0 text_chars=31",
        ),
    ] {
        ensure!(
            image
                .qualify_static(input)
                .err()
                .is_some_and(|error| error.to_string() == expected),
            "original static diagnostic differs"
        );
    }
    for input in [
        "",
        "Dump of file C:\\private\\KernelBase.dll\n",
        "  0000000180001000: C3     ret\n",
        "  0000000180001000: B8 00 00 00 00     mov\n  0000000180001000: B8     mov\n",
        "  0000000180001005: C3     ret\n  0000000180001000: B8 00 00 00 00     mov\n",
        "  0000000180001600: 00     nop\n",
        "  00000001800015FF: 00 00     nop\n",
        "  0000000180001000: B8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     mov\n",
        "  0000000180001000:     ret\n",
        "  0000000180001000: B8     ???\n",
        "  0000000180001000: B8 00 00 00 00     mov eax,0\n                    00\n",
        "  0000000180001000: B8 00     mov eax,0\n       00\n  0000000180001001: 00     nop\n",
        "  0000000180001005: C3     ret\n       00\n  0000000180001000: B8 00 00 00 00     mov eax,0\n",
        "  0000000180001000: B8 00     mov eax,0\nprivate path\n       00\n",
    ] {
        ensure!(
            image.qualify_static(input).is_err(),
            "original invalid static framing accepted"
        );
    }
    for input in ["x".repeat(1048577), "\n".repeat(4097)] {
        ensure!(
            image.qualify_static(&input).is_err(),
            "static text budget accepted"
        );
    }
    refuse(
        &b,
        &[
            Zero(0xb0, 8),
            Long(0xb0, u64::MAX),
            Word(0xa8, 0),
            Word(0x190, 0),
            Group(vec![Word(0x190, 1), Word(0xa8, 0x1001)]),
            Word(0x19c, 0x100),
            Word(0x1ac, 0x40000040),
        ],
        |bad| KernelImage::from_static(bad)?.entry_slice().map(|_| ()),
    )?;
    let mut short_virtual = b.clone();
    put(&mut short_virtual, 0x190, 7);
    ensure!(
        KernelImage::from_static(&short_virtual)?
            .entry_slice()?
            .length
            == 7,
        "short virtual span differs"
    );
    let mut large = b.clone();
    large.resize(8192, 0);
    for (at, n) in [(0x190, 6144), (0x198, 6144), (0xd0, 12288)] {
        put(&mut large, at, n);
    }
    ensure!(
        KernelImage::from_static(&large)?.entry_slice()?.length == 4096,
        "static slice cap differs"
    );
    large[0x200..0x1200].fill(0);
    let input = (0..1300)
        .map(|i| {
            format!(
                "  {:016X}: 00     mov C:\\private\\secret.dll\n",
                0x180001000u64 + i
            )
        })
        .collect::<String>();
    ensure!(
        KernelImage::from_static(&large)?
            .qualify_static(&input)
            .is_err(),
        "static aggregate output budget accepted"
    );
    Ok(())
}
