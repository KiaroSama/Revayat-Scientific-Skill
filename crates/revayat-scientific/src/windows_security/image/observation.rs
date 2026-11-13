//! Both reviewed KernelBase observation profiles, literal bytes, branch edges,
//! exact static records and qualification order. Synthetic bytes lack hash admission.
use super::*;
pub(super) struct Code {
    pub entry: u32,
    pub site: u32,
    pub call: u32,
    pub rvas: [u32; 11],
}
pub(super) const BYTES: [&[u8]; 11] = [
    &[0xe8, 0xf8, 0x11, 0, 0],
    &[0x85, 0xc0],
    &[0x0f, 0x88, 0x80, 0, 0, 0],
    &[0x32, 0xc0],
    &[0xe9, 0xf3, 0xfe, 0xff, 0xff],
    &[0x0f, 0xb6, 0xc0],
    &[0x48, 0x83, 0xc4, 0x40],
    &[0x5b],
    &[0xc3],
    &[0x3c, 1],
    &[0x75, 0xb3],
];
pub(super) fn code(profile: &ObservationProfile) -> Result<Code> {
    let index = observation_profiles()
        .iter()
        .position(|known| known.identity == profile.identity)
        .ok_or_else(|| anyhow::anyhow!("unsupported observation code profile"))?;
    Ok(if index == 0 {
        Code {
            entry: 0xbd1a0,
            site: 0xbd243,
            call: 0xbe470,
            rvas: [
                0xbd273, 0xbd278, 0xbd27a, 0xbd300, 0xbd302, 0xbd1fa, 0xbd1fd, 0xbd201, 0xbd202,
                0xbd243, 0xbd245,
            ],
        }
    } else {
        Code {
            entry: 0xbd040,
            site: 0xbd0e3,
            call: 0xbe310,
            rvas: [
                0xbd113, 0xbd118, 0xbd11a, 0xbd1a0, 0xbd1a2, 0xbd09a, 0xbd09d, 0xbd0a1, 0xbd0a2,
                0xbd0e3, 0xbd0e5,
            ],
        }
    })
}
impl KernelImage<'_> {
    pub fn require_observation_profile(&self) -> Result<u32> {
        self.observation_bytes(&select_optional(Some(&self.kernelbase_identity()?))?)
    }
    pub fn require_observation_static(&self, view: &StaticView) -> Result<()> {
        let profile = std::cell::RefCell::new(None);
        qualify_observation(
            || {
                *profile.borrow_mut() = Some(select_optional(Some(&self.kernelbase_identity()?))?);
                Ok(())
            },
            || {
                self.observation_bytes(
                    profile
                        .borrow()
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("observation profile absent"))?,
                )
                .map(|_| ())
            },
            || {
                require_records(
                    view,
                    profile
                        .borrow()
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("observation profile absent"))?,
                )
            },
        )
    }
    pub fn require_checkpoint_address(&self) -> Result<u64> {
        let profile = select_optional(Some(&self.kernelbase_identity()?))?;
        self.observation_bytes(&profile)?;
        checkpoint_address(
            &self.pe.sections,
            self.pe.image_size,
            self.pe.base,
            &profile,
        )
    }
    pub(super) fn observation_bytes(&self, profile: &ObservationProfile) -> Result<u32> {
        let c = code(profile)?;
        ensure!(
            self.subject == "kernelbase.dll" && self.pe.entry == c.entry,
            "wrong observation subject or entry"
        );
        let slice = self.entry_slice()?;
        for (index, (&rva, bytes)) in c.rvas.iter().zip(BYTES).enumerate() {
            let length = bytes.len() as u32;
            ensure!(
                rva >= c.entry
                    && u64::from(rva) + u64::from(length)
                        <= u64::from(c.entry) + u64::from(slice.length)
                    && self.full_executable(rva, length),
                "observation literal exceeds qualified code"
            );
            for (&old, old_bytes) in c.rvas[..index].iter().zip(BYTES) {
                ensure!(
                    !overlaps(
                        u64::from(rva),
                        u64::from(length),
                        u64::from(old),
                        old_bytes.len() as u64
                    ),
                    "observation literals overlap"
                );
            }
            ensure!(
                span(self.pe.bytes, self.pe.map(rva, length)?, bytes.len())? == bytes,
                "observation literal differs"
            );
        }
        let relative = |rva: u32, size: u32, offset: u32| -> Result<i64> {
            let raw = self.pe.map(rva + offset, 4)?;
            Ok(i64::from(rva)
                + i64::from(size)
                + i64::from(i32::from_le_bytes(span(self.pe.bytes, raw, 4)?.try_into()?)))
        };
        let short = i64::from(c.rvas[10])
            + 2
            + i64::from(self.pe.bytes[self.pe.map(c.rvas[10] + 1, 1)?] as i8);
        ensure!(
            relative(c.rvas[0], 5, 1)? == i64::from(c.call)
                && relative(c.rvas[2], 6, 2)? == i64::from(c.rvas[3])
                && relative(c.rvas[4], 5, 1)? == i64::from(c.rvas[5])
                && short == i64::from(c.rvas[5])
                && self.full_executable(c.call, 1)
                && self.full_executable(c.site, 2),
            "observation branch edge differs"
        );
        Ok(c.site)
    }
    fn full_executable(&self, rva: u32, length: u32) -> bool {
        length != 0
            && u64::from(rva) + u64::from(length) <= u64::from(self.pe.image_size)
            && self
                .pe
                .sections
                .iter()
                .filter(|s| {
                    s.flags & 0x20000000 != 0
                        && rva >= s.rva
                        && u64::from(rva) + u64::from(length)
                            <= u64::from(s.rva) + u64::from(s.virtual_size.min(s.raw_size))
                })
                .count()
                == 1
    }
}
pub(super) fn select_optional(identity: Option<&str>) -> Result<ObservationProfile> {
    select_observation(identity.ok_or_else(|| anyhow::anyhow!("unsupported fixed image identity"))?)
}
pub(super) fn require_records(view: &StaticView, profile: &ObservationProfile) -> Result<()> {
    let c = code(profile)?;
    let text = [
        format!("call operands=rva:0x{:08X}", c.call),
        "test operands=eax,eax".into(),
        format!("js operands=rva:0x{:08X}", c.rvas[3]),
        "xor operands=al,al".into(),
        format!("jmp operands=rva:0x{:08X}", c.rvas[5]),
        "movzx operands=eax,al".into(),
        "add operands=withheld".into(),
        "pop operands=rbx".into(),
        "ret operands=none".into(),
        "cmp operands=al,1".into(),
        format!("jne operands=rva:0x{:08X}", c.rvas[5]),
    ];
    for ((rva, bytes), text) in c.rvas.iter().zip(BYTES).zip(text) {
        let hex = bytes.iter().map(|b| format!("{b:02X}")).collect::<String>();
        let expected = format!("rva=0x{rva:08X} bytes={hex} mnemonic={text}");
        ensure!(
            view.text.lines().filter(|line| *line == expected).count() == 1,
            "observation record differs or repeats"
        );
    }
    Ok(())
}
pub(super) fn qualify_observation(
    identity: impl FnOnce() -> Result<()>,
    bytes: impl FnOnce() -> Result<()>,
    records: impl FnOnce() -> Result<()>,
) -> Result<()> {
    identity().map_err(|error| {
        error.context("fixed KernelBase observation profile refused check=identity")
    })?;
    bytes().map_err(|error| {
        error.context("fixed KernelBase observation profile refused check=bytes")
    })?;
    records().map_err(|error| {
        error.context("fixed KernelBase observation profile refused check=records")
    })
}
