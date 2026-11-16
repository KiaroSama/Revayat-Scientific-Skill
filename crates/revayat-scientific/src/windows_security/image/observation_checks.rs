//! Original observation/checkpoint products. Literal bytes and listings are
//! authored independently of the production formatter; no image is executed.
use super::super::observation::{qualify_observation, require_records, select_optional};
use super::*;
use std::cell::RefCell;

const HASHES: [&str; 2] = [
    "f4acdac5f1dc54b20c84a51ad0f507f421f5d1170e276a5a75d4e7dcf88750e2",
    "96c0459f0d73d728e5c13a10d83d840f56913ef7281d17370a5e1eb197faa450",
];
struct ObservationFixture {
    bytes: Vec<u8>,
    entry: u32,
    site: u32,
    rvas: [u32; 11],
    listing: &'static str,
}
const ORIGINAL_LISTING: &str = concat!(
    "  00000001800BD1FA: 0F B6 C0     movzx eax,al\n",
    "  00000001800BD1FD: 48 83 C4 40     add rsp,40h\n",
    "  00000001800BD201: 5B     pop rbx\n",
    "  00000001800BD202: C3     ret\n",
    "  00000001800BD243: 3C 01     cmp al,1\n",
    "  00000001800BD245: 75 B3     jne 00000001800BD1FA\n",
    "  00000001800BD273: E8 F8 11 00 00     call 00000001800BE470\n",
    "  00000001800BD278: 85 C0     test eax,eax\n",
    "  00000001800BD27A: 0F 88 80 00 00 00     js 00000001800BD300\n",
    "  00000001800BD300: 32 C0     xor al,al\n",
    "  00000001800BD302: E9 F3 FE FF FF     jmp 00000001800BD1FA\n",
);
const SERVICED_LISTING: &str = concat!(
    "  00000001800BD09A: 0F B6 C0     movzx eax,al\n",
    "  00000001800BD09D: 48 83 C4 40     add rsp,40h\n",
    "  00000001800BD0A1: 5B     pop rbx\n",
    "  00000001800BD0A2: C3     ret\n",
    "  00000001800BD0E3: 3C 01     cmp al,1\n",
    "  00000001800BD0E5: 75 B3     jne 00000001800BD09A\n",
    "  00000001800BD113: E8 F8 11 00 00     call 00000001800BE310\n",
    "  00000001800BD118: 85 C0     test eax,eax\n",
    "  00000001800BD11A: 0F 88 80 00 00 00     js 00000001800BD1A0\n",
    "  00000001800BD1A0: 32 C0     xor al,al\n",
    "  00000001800BD1A2: E9 F3 FE FF FF     jmp 00000001800BD09A\n",
);
fn observation_fixture(index: usize) -> ObservationFixture {
    let (entry, site, section, rvas, listing) = if index == 0 {
        (
            0xbd1a0,
            0xbd243,
            0xbd100,
            [
                0xbd273, 0xbd278, 0xbd27a, 0xbd300, 0xbd302, 0xbd1fa, 0xbd1fd, 0xbd201, 0xbd202,
                0xbd243, 0xbd245,
            ],
            ORIGINAL_LISTING,
        )
    } else {
        (
            0xbd040,
            0xbd0e3,
            0xbcfa0,
            [
                0xbd113, 0xbd118, 0xbd11a, 0xbd1a0, 0xbd1a2, 0xbd09a, 0xbd09d, 0xbd0a1, 0xbd0a2,
                0xbd0e3, 0xbd0e5,
            ],
            SERVICED_LISTING,
        )
    };
    let mut bytes = base();
    bytes.resize(0x2400, 0);
    long(&mut bytes, 0xb0, 0x180000000);
    for (at, n) in [
        (0xa8, entry),
        (0xd0, 0xc0000),
        (0x194, section),
        (0x190, 0x2000),
        (0x198, 0x2000),
    ] {
        put(&mut bytes, at, n);
    }
    bytes[0x343..0x347].copy_from_slice(&[0x3c, 1, 0x75, 0xb3]);
    bytes[0x373..0x380].copy_from_slice(&[
        0xe8, 0xf8, 0x11, 0, 0, 0x85, 0xc0, 0x0f, 0x88, 0x80, 0, 0, 0,
    ]);
    bytes[0x400..0x407].copy_from_slice(&[0x32, 0xc0, 0xe9, 0xf3, 0xfe, 0xff, 0xff]);
    bytes[0x2fa..0x303].copy_from_slice(&[0x0f, 0xb6, 0xc0, 0x48, 0x83, 0xc4, 0x40, 0x5b, 0xc3]);
    ObservationFixture {
        bytes,
        entry,
        site,
        rvas,
        listing,
    }
}

pub fn check_observation_validation() -> Result<()> {
    let profiles = observation_profiles();
    for (index, profile) in profiles.iter().enumerate() {
        let selected = select_optional(Some(&profile.identity))?;
        ensure!(
            selected.identity == profile.identity
                && selected.checkpoint == profile.checkpoint
                && selected.image_size == profile.image_size
                && selected.section == profile.section,
            "observation selector returned another profile"
        );
        let identity = &profile.identity;
        for changed in [
            None,
            Some(String::new()),
            Some(format!("{identity} ")),
            Some(identity.replace("pdb_age=1", "pdb_age=2")),
            Some(identity.replace("kernelbase.pdb", "other.pdb")),
            Some(identity.replace("module=kernelbase.dll", "module=kernel32.dll")),
            Some(identity.replace("pe_timestamp=", "pe_timestamp=0")),
            Some(identity.replace("file_size=", "file_size=0")),
            Some(identity.replace("image_size=", "image_size=0")),
            Some(identity.replace("pdb_guid=", "pdb_guid=0")),
            Some(identity.replace(HASHES[index], HASHES[1 - index])),
        ] {
            ensure!(
                select_optional(changed.as_deref()).is_err(),
                "altered observation identity accepted"
            );
        }
        let fixture = observation_fixture(index);
        let other = &profiles[1 - index];
        let other_fixture = observation_fixture(1 - index);
        let image = KernelImage::from_static(&fixture.bytes)?;
        ensure!(
            image.observation_bytes(profile)? == fixture.site
                && image.observation_bytes(other).is_err(),
            "observation literal profile boundary differs"
        );
        let view = image.qualify_static(fixture.listing)?;
        require_records(&view, profile)?;
        ensure!(
            view.records == 11 && require_records(&view, other).is_err(),
            "observation record profile boundary differs"
        );
        ensure!(
            image
                .require_observation_static(&view)
                .err()
                .is_some_and(|error| error.to_string()
                    == "fixed KernelBase observation profile refused check=identity"),
            "synthetic records bypassed the real observation identity gate"
        );
        let site = format!("{:016X}", 0x180000000u64 + u64::from(fixture.site));
        let jump = format!("{:016X}", 0x180000000u64 + u64::from(fixture.rvas[5]));
        let jump_site = format!("{:016X}", 0x180000000u64 + u64::from(fixture.rvas[10]));
        let test_site = format!("{:016X}", 0x180000000u64 + u64::from(fixture.rvas[1]));
        for changed in [
            fixture
                .listing
                .replace(&format!("  {site}: 3C 01     cmp al,1\n"), ""),
            fixture
                .listing
                .replace(&format!("  {jump_site}: 75 B3     jne {jump}\n"), ""),
            fixture
                .listing
                .replace(&format!("  {test_site}: 85 C0     test eax,eax\n"), ""),
            fixture.listing.replace("test eax,eax", "bogus eax,eax"),
            fixture.listing.replace("movzx eax,al", "movzx eax,0"),
            fixture.listing.replace("cmp al,1", "cmp eax,1"),
            fixture.listing.replace("75 B3     jne", "75 B3     je"),
            fixture
                .listing
                .replace("cmp al,1\n", "cmp al,1\n       00\n"),
            fixture.listing.replace(
                &format!("jne {jump}\n"),
                &format!("jne {jump}\n       00\n"),
            ),
            fixture.listing.replace(
                &site,
                &format!("{:016X}", 0x180000001u64 + u64::from(fixture.site)),
            ),
            fixture.listing.repeat(2),
            fixture.listing.replace(
                "85 C0     test eax,eax\n",
                "85 C0     test eax,eax\n       00\n",
            ),
            fixture.listing.replace(
                &format!("jne {jump}"),
                &format!("jne {:016X}", 0x180000001u64 + u64::from(fixture.rvas[5])),
            ),
        ] {
            ensure!(
                image
                    .qualify_static(&changed)
                    .and_then(|view| require_records(&view, profile))
                    .is_err(),
                "altered observation listing accepted"
            );
        }
        for rva in fixture.rvas {
            let mut bad = fixture.bytes.clone();
            bad[image.pe.map(rva, 1)?] ^= 1;
            ensure!(
                KernelImage::from_static(&bad)?
                    .observation_bytes(profile)
                    .is_err(),
                "altered observation code literal accepted"
            );
        }
        refuse(
            &fixture.bytes,
            &[
                Byte(0x374, 0),
                Byte(0x37c, 0),
                Byte(0x403, 0),
                Byte(0x346, 0xb4),
                Word(0xa8, fixture.entry + 1),
                Word(0xa8, other_fixture.entry),
                Word(0x190, 0x144),
                Word(0x198, 0x144),
                Word(0x190, 0x179),
                Word(0x198, 0x179),
                Word(0x1ac, 0x40000040),
                Word(0x178, 1),
                Word(0x190, 0x1200),
            ],
            |bad| {
                KernelImage::from_static(bad)?
                    .observation_bytes(profile)
                    .map(|_| ())
            },
        )?;
        ensure!(
            image.require_observation_profile().is_err(),
            "synthetic observation bytes satisfied full identity"
        );
    }
    let (first_raw, second_raw) = (0x101u32, 1u32);
    ensure!(
        first_raw != second_raw && first_raw & 0xff == 1 && second_raw & 0xff == 1,
        "raw exit values were collapsed to their low byte"
    );
    check_qualification_order()
}

#[derive(Debug)]
struct QualificationFailure(u8);
impl std::fmt::Display for QualificationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("fixed qualification fixture")
    }
}
impl std::error::Error for QualificationFailure {}
fn check_qualification_order() -> Result<()> {
    for (failed_phase, expected_order) in [
        ("identity", "identity,"),
        ("bytes", "identity,bytes,"),
        ("records", "identity,bytes,records,"),
    ] {
        let original = anyhow::Error::new(QualificationFailure(0x39));
        let original_pointer =
            original.downcast_ref::<QualificationFailure>().unwrap() as *const QualificationFailure;
        let original = RefCell::new(Some(original));
        let order = RefCell::new(String::new());
        let check = |phase: &str| -> Result<()> {
            order.borrow_mut().push_str(phase);
            order.borrow_mut().push(',');
            if phase == failed_phase {
                Err(original
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("fixture failure was consumed twice"))?)
            } else {
                Ok(())
            }
        };
        let error =
            qualify_observation(|| check("identity"), || check("bytes"), || check("records"))
                .err()
                .ok_or_else(|| anyhow::anyhow!("qualification failure was lost"))?;
        let retained = error
            .downcast_ref::<QualificationFailure>()
            .ok_or_else(|| anyhow::anyhow!("original qualification cause was replaced"))?;
        ensure!(
            error.to_string()
                == format!("fixed KernelBase observation profile refused check={failed_phase}")
                && std::ptr::eq(retained, original_pointer)
                && retained.0 == 0x39
                && order.borrow().as_str() == expected_order,
            "qualification failure phase, identity or ordering differs"
        );
    }
    let order = RefCell::new(String::new());
    let record = |phase: &str| -> Result<()> {
        order.borrow_mut().push_str(phase);
        order.borrow_mut().push(',');
        Ok(())
    };
    qualify_observation(
        || record("identity"),
        || record("bytes"),
        || record("records"),
    )?;
    ensure!(
        order.borrow().as_str() == "identity,bytes,records,",
        "successful qualification order differs"
    );
    Ok(())
}

pub fn check_checkpoint_validation() -> Result<()> {
    let profiles = observation_profiles();
    for (index, profile) in profiles.iter().enumerate() {
        let section = profile.section;
        let expected = if index == 0 { 0x18039b8f8 } else { 0x18039a7e8 };
        ensure!(
            checkpoint_address(&[section], profile.image_size, 0x180000000, profile)? == expected,
            "original checkpoint address differs"
        );
        for variant in 0..12 {
            let mut changed = section;
            match variant {
                0 => changed.rva += 1,
                1 => changed.raw += 1,
                2 => changed.raw_size += 1,
                3 => changed.virtual_size += 1,
                4 => changed.raw_size = profile.checkpoint - section.rva + 1,
                5 => changed.virtual_size = profile.checkpoint - section.rva + 1,
                6 => changed.flags = 0xe0000040,
                7 => changed.flags = 0x40000040,
                8 => changed.flags = 0x80000040,
                9 => changed.flags = 0xc0000080,
                10 => changed.rva = u32::MAX,
                _ => changed = profiles[1 - index].section,
            }
            ensure!(
                checkpoint_address(&[changed], profile.image_size, 0x180000000, profile).is_err(),
                "original checkpoint mutation accepted variant={variant}"
            );
        }
        for sections in [&[][..], &[section, section][..]] {
            ensure!(
                checkpoint_address(sections, profile.image_size, 0x180000000, profile).is_err(),
                "missing or duplicate checkpoint section accepted"
            );
        }
        for base in [0, 0x7fffffffffffffff, u64::MAX] {
            ensure!(
                checkpoint_address(&[section], profile.image_size, base, profile).is_err(),
                "invalid checkpoint base accepted"
            );
        }
        let fixture = observation_fixture(index);
        ensure!(
            checkpoint_address(&[section], profile.checkpoint + 1, 0x180000000, profile).is_err()
                && KernelImage::from_static(&fixture.bytes)?
                    .require_checkpoint_address()
                    .is_err(),
            "clipped or synthetic checkpoint identity accepted"
        );
    }
    Ok(())
}
