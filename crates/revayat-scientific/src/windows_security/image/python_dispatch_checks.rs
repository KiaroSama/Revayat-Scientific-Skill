//! Original Python-dispatch identity/parser fixture matrix. Synthetic bytes
//! never replace the three genuinely held runtime images used by native owners.
use super::*;

pub fn qualify_python_dispatch_image(
    bytes: &[u8],
    digest: &str,
    length: usize,
    language: u16,
    payload_hash: &str,
    payload_length: usize,
) -> Result<()> {
    ensure!(
        bytes.len() == length && sha256(bytes) == digest,
        "Python dispatch image identity differs"
    );
    let image = PeImage::parse(bytes, 1)?;
    ensure!(
        image.entry != 0 && image.full_executable(image.entry, 1),
        "Python dispatch entry span differs"
    );
    image.qualify_python_imports("python-exe")?;
    let manifest = image.manifest(1, false)?;
    ensure!(
        manifest.language == language
            && manifest.bytes.len() == payload_length
            && sha256(manifest.bytes) == payload_hash,
        "Python dispatch default manifest identity differs"
    );
    Ok(())
}

pub fn python_dispatch_validation_fixtures() -> [Vec<u8>; 3] {
    let mut images = [
        imports(&["KERNEL32.dll", "python311.dll", "VCRUNTIME140.dll"]),
        imports(&[
            "ADVAPI32.dll",
            "bcrypt.dll",
            "KERNEL32.dll",
            "VCRUNTIME140.dll",
            "VERSION.dll",
            "WS2_32.dll",
        ]),
        imports(&["KERNEL32.dll"]),
    ];
    for (index, image) in images[..2].iter_mut().enumerate() {
        image.resize(2048, 0);
        put(image, 0x190, 0x600);
        put(image, 0x198, 0x600);
        resource(image, 0x500, 0x1300, if index == 0 { 1 } else { 2 });
        put(image, 0x564, 3);
        image[0x580..0x583].copy_from_slice(b"abc");
    }
    images
}

pub fn check_python_dispatch_identity() -> Result<()> {
    let [bytes, dll, runtime] = python_dispatch_validation_fixtures();
    const PAYLOAD_HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    qualify_python_dispatch_image(&bytes, &sha256(&bytes), 2048, 1033, PAYLOAD_HASH, 3)?;
    refuse(
        &bytes,
        &[
            Word(0xa8, 0),
            Xor(0x300),
            Word(0x530, 2),
            Word(0x550, 1034),
            Xor(0x580),
            Word(0x564, 4),
        ],
        |bad| qualify_python_dispatch_image(bad, &sha256(bad), 2048, 1033, PAYLOAD_HASH, 3),
    )?;
    ensure!(
        qualify_python_dispatch_image(&bytes, &sha256(&bytes), 2049, 1033, PAYLOAD_HASH, 3)
            .is_err(),
        "Python dispatch length drift accepted"
    );
    ensure!(
        qualify_python_dispatch_image(&bytes, PAYLOAD_HASH, 2048, 1033, PAYLOAD_HASH, 3).is_err(),
        "Python dispatch digest drift accepted"
    );
    let dll = PeImage::parse(&dll, 1)?;
    ensure!(
        dll.qualify_python_imports("python311")? == 0,
        "Python dispatch DLL import fixture differs"
    );
    let manifest = dll.module_manifest(false)?;
    ensure!(
        manifest.language == 1033 && manifest.bytes == b"abc",
        "Python dispatch module manifest fixture differs"
    );
    ensure!(
        PeImage::parse(&runtime, 1)?.qualify_python_imports("vcruntime140")? == 0,
        "Python dispatch runtime import fixture differs"
    );
    Ok(())
}
