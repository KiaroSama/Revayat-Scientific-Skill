//! Source-exact native registry inventory, with every observed API call made by actual ctypes.
use super::{
    ctypes::Ctypes,
    failure,
    object::{Owned, Result, require},
    token::TokenApi,
};

pub const KEY: &str = r"\Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide";
const DENIED: u32 = 0xc0000022;
pub struct Inventory {
    pub subkeys: usize,
    pub accessible: usize,
}
struct Registry<'a> {
    ct: &'a Ctypes,
    native: Owned,
    advapi: Owned,
    kernel: Owned,
    unicode: Owned,
    attributes: Owned,
    clock: Owned,
    started: Owned,
}
impl Registry<'_> {
    fn deadline(&self) -> Result<()> {
        require(
            self.clock
                .call(&[])?
                .subtract(&self.started)?
                .less(&Owned::unsigned(8)?)?,
        )
    }
    fn open(&self, name: &Owned, access: u64, root: Option<&Owned>) -> Result<(u32, Owned)> {
        self.deadline()?;
        let encoded = name.method(
            c"encode",
            &[&Owned::text("utf-16-le")?, &Owned::text("strict")?],
        )?;
        let bytes = encoded.raw_bytes(1024)?;
        require(!bytes.is_empty() && !super::ascii::contains(name.utf8(4096)?, 0))?;
        let mut text = [0u8; 1026];
        text.get_mut(..bytes.len())
            .ok_or(super::object::Fault::Control)?
            .copy_from_slice(bytes);
        let buffer = self.ct.bytes_buffer(
            text.get(..bytes.len() + 2)
                .ok_or(super::object::Fault::Control)?,
        )?;
        text.fill(0);
        let native_name = self.unicode.call(&[
            &Owned::unsigned(bytes.len() as u64)?,
            &Owned::unsigned(bytes.len() as u64 + 2)?,
            &Owned::unsigned(self.ct.address(&buffer)?)?,
        ])?;
        let root = root.map_or_else(Owned::none, Owned::clone_ref);
        let attrs = self.attributes.call(&[
            &Owned::unsigned(self.ct.size(&self.attributes)? as u64)?,
            &root,
            &Owned::unsigned(self.ct.address(&native_name)?)?,
            &Owned::unsigned(0x1040)?,
            &Owned::none(),
            &Owned::none(),
        ])?;
        let handle = self.ct.pointer.call(&[])?;
        let status = self
            .native
            .method(
                c"NtOpenKeyEx",
                &[
                    &self.ct.reference(&handle)?,
                    &Owned::unsigned(access)?,
                    &self.ct.reference(&attrs)?,
                    &Owned::unsigned(0)?,
                ],
            )?
            .i64()? as u32;
        Ok((status, handle))
    }
    fn valid(handle: &Owned) -> Result<bool> {
        let value = handle.attr(c"value")?;
        if value.is_none() {
            return Ok(false);
        }
        let value = value.u64()?;
        Ok(value > 0 && value < 0x7fffffffffffffff && !(0x80000000..=0x800000ff).contains(&value))
    }
    fn close(&self, handle: &Owned) -> Result<()> {
        if Self::valid(handle)? {
            require(self.native.method(c"NtClose", &[handle])?.i64()? == 0)?;
        }
        Ok(())
    }
    fn same_name(&self, first: &Owned, second: &Owned) -> Result<bool> {
        let result = self
            .kernel
            .method(
                c"CompareStringOrdinal",
                &[
                    first,
                    &Owned::signed(-1)?,
                    second,
                    &Owned::signed(-1)?,
                    &Owned::boolean(true)?,
                ],
            )?
            .i64()?;
        require((1..=3).contains(&result))?;
        Ok(result == 2)
    }
    fn qualify(&self, handle: &Owned, expected: &Owned, phase: &mut &'static str) -> Result<()> {
        *phase = "identity";
        require(Self::valid(handle)?)?;
        let basic = self.ct.buffer(56)?;
        let returned = self.ct.scalar(c"ULONG", 0)?;
        let status = self
            .native
            .method(
                c"NtQueryObject",
                &[
                    handle,
                    &Owned::unsigned(0)?,
                    &basic,
                    &Owned::unsigned(56)?,
                    &self.ct.reference(&returned)?,
                ],
            )?
            .i64()?;
        let attributes = self.ct.from_buffer(&self.ct.win(c"ULONG")?, &basic, 0)?;
        let granted = self.ct.from_buffer(&self.ct.win(c"ULONG")?, &basic, 4)?;
        require(
            status == 0
                && self.ct.value(&returned)? == 56
                && self.ct.value(&attributes)? == 0
                && self.ct.value(&granted)? == 0x20019,
        )?;
        let data = self.ct.buffer(4096)?;
        let status = self
            .native
            .method(
                c"NtQueryKey",
                &[
                    handle,
                    &Owned::unsigned(3)?,
                    &data,
                    &Owned::unsigned(4096)?,
                    &self.ct.reference(&returned)?,
                ],
            )?
            .i64()?;
        let bytes = data.attr(c"raw")?;
        let raw = bytes.raw_bytes(4096)?;
        let length = self.ct.value(&returned)? as usize;
        require(status == 0 && (4..=4096).contains(&length) && length <= raw.len())?;
        let count = u32::from_le_bytes(
            raw.get(..4)
                .ok_or(super::object::Fault::Control)?
                .try_into()
                .map_err(|_| super::object::Fault::Control)?,
        ) as usize;
        let encoded = expected.method(
            c"encode",
            &[&Owned::text("utf-16-le")?, &Owned::text("strict")?],
        )?;
        require(
            count == encoded.raw_bytes(4096)?.len()
                && count.is_multiple_of(2)
                && count <= length - 4,
        )?;
        let actual = Owned::bytes(raw.get(4..4 + count).ok_or(super::object::Fault::Control)?)?
            .method(
                c"decode",
                &[&Owned::text("utf-16-le")?, &Owned::text("strict")?],
            )?;
        require(
            !super::ascii::contains(actual.utf8(8192)?, 0) && self.same_name(&actual, expected)?,
        )
    }
    fn counts(&self, handle: &Owned) -> Result<(u64, u64, i64)> {
        let keys = self.ct.scalar(c"DWORD", 0)?;
        let values = self.ct.scalar(c"DWORD", 0)?;
        let modified = self.ct.module.attr(c"c_longlong")?.call(&[])?;
        require(
            self.advapi
                .method(
                    c"RegQueryInfoKeyW",
                    &[
                        handle,
                        &Owned::none(),
                        &Owned::none(),
                        &Owned::none(),
                        &self.ct.reference(&keys)?,
                        &Owned::none(),
                        &Owned::none(),
                        &self.ct.reference(&values)?,
                        &Owned::none(),
                        &Owned::none(),
                        &Owned::none(),
                        &self.ct.reference(&modified)?,
                    ],
                )?
                .i64()?
                == 0,
        )?;
        let keys = self.ct.value(&keys)?;
        let values = self.ct.value(&values)?;
        require(keys <= 256 && values <= 32)?;
        Ok((keys, values, modified.attr(c"value")?.i64()?))
    }
    fn inventory(&self, token: &TokenApi, phase: &mut &'static str) -> Result<Inventory> {
        *phase = "root";
        let (status, root) = self.open(&Owned::text(KEY)?, 0x20019, None)?;
        let operation = (|| {
            require(status == 0)?;
            self.qualify(&root, &Owned::text(KEY)?, phase)?;
            *phase = "mutation";
            for access in [2, 4, 0x10000, 0x40000, 0x80000] {
                let (status, denied) = self.open(&Owned::text(KEY)?, access, None)?;
                let result = require(status == DENIED && !denied.attr(c"value")?.truth()?);
                let closed = self.close(&denied);
                failure::close_result(result, closed, phase)?;
            }
            let before = self.counts(&root)?;
            let names = Owned::list(&[])?;
            let mut accessible = 0;
            for index in 0..257 {
                *phase = "inventory";
                self.deadline()?;
                let name = self
                    .ct
                    .module
                    .method(c"create_unicode_buffer", &[&Owned::unsigned(512)?])?;
                let length = self.ct.scalar(c"DWORD", 512)?;
                let status = self
                    .advapi
                    .method(
                        c"RegEnumKeyExW",
                        &[
                            &root,
                            &Owned::unsigned(index)?,
                            &name,
                            &self.ct.reference(&length)?,
                            &Owned::none(),
                            &Owned::none(),
                            &Owned::none(),
                            &Owned::none(),
                        ],
                    )?
                    .i64()?;
                if status == 259 {
                    require(index == before.0)?;
                    break;
                }
                let value = name.attr(c"value")?;
                let length = self.ct.value(&length)?;
                require(
                    status == 0
                        && index < 256
                        && (1..512).contains(&length)
                        && length as usize == value.length()?,
                )?;
                let text = value.utf8(4096)?;
                require(
                    !super::ascii::contains(text, b'\\') && !super::ascii::contains(text, b'/'),
                )?;
                for previous in 0..names.length()? {
                    require(!self.same_name(&value, &names.index(previous)?)?)?;
                }
                names.method(c"append", &[&value])?;
                let (status, child) = self.open(&value, 0x20019, Some(&root))?;
                let result = (|| {
                    require(status == 0 || status == DENIED)?;
                    if status == 0 {
                        let mut identity = super::wide::Name::new();
                        identity.push(KEY)?;
                        identity.push("\\")?;
                        identity.push(text)?;
                        self.qualify(&child, &Owned::text(identity.text()?)?, phase)?;
                        accessible += 1;
                    } else {
                        require(!child.attr(c"value")?.truth()?)?;
                    }
                    Ok(())
                })();
                let closed = self.close(&child);
                failure::close_result(result, closed, phase)?;
            }
            *phase = "inventory";
            let count = names.length()?;
            require(self.counts(&root)? == before && count as u64 == before.0)?;
            token.observe(self.ct, true, phase)?;
            *phase = "tf-deadline";
            self.deadline()?;
            Ok(Inventory {
                subkeys: count,
                accessible,
            })
        })();
        let closed = self.close(&root);
        failure::close_result(operation, closed, phase)
    }
}

pub fn controls(globals: &Owned, ct: &Ctypes, phase: &mut &'static str) -> Result<Inventory> {
    *phase = "ti-platform";
    require(globals.get(c"os")?.attr(c"name")?.utf8(16)? == "nt")?;
    *phase = "ti-x64";
    require(ct.size(&ct.pointer)? == 8)?;
    *phase = "ti-version";
    let version = globals.get(c"sys")?.attr(c"version_info")?;
    require(version.index(0)?.u64()? == 3 && version.index(1)?.u64()? == 11)?;
    let ushort = ct.win(c"USHORT")?;
    let ulong = ct.win(c"ULONG")?;
    let unicode = ct.structure(
        "Unicode",
        &[
            ("length", &ushort),
            ("maximum", &ushort),
            ("buffer", &ct.pointer),
        ],
    )?;
    let attributes = ct.structure(
        "Attributes",
        &[
            ("length", &ulong),
            ("root", &ct.pointer),
            ("name", &ct.pointer),
            ("flags", &ulong),
            ("descriptor", &ct.pointer),
            ("qos", &ct.pointer),
        ],
    )?;
    *phase = "ti-abi";
    require(ct.size(&unicode)? == 16 && ct.size(&attributes)? == 48)?;
    *phase = "ti-import";
    let token = TokenApi::import(ct)?;
    *phase = "ti-detached";
    token.detached(ct)?;
    token.observe(ct, false, phase)?;
    *phase = "ti-libraries";
    let native = ct.library("ntdll", false)?;
    let advapi = ct.library("advapi32", true)?;
    let kernel = ct.library("kernel32", true)?;
    *phase = "ti-prototypes";
    let long = ct.win(c"LONG")?;
    let integer = ct.module.attr(c"c_int")?;
    let dword = ct.win(c"DWORD")?;
    let pointer_ulong = ct.pointer_to(&ulong)?;
    let pointer_dword = ct.pointer_to(&dword)?;
    ct.prototype(
        &native,
        c"NtOpenKeyEx",
        &[
            &ct.pointer_to(&ct.pointer)?,
            &ulong,
            &ct.pointer_to(&attributes)?,
            &ulong,
        ],
        Some(&long),
    )?;
    ct.prototype(&native, c"NtClose", &[&ct.pointer], Some(&long))?;
    for name in [c"NtQueryObject", c"NtQueryKey"] {
        ct.prototype(
            &native,
            name,
            &[&ct.pointer, &integer, &ct.pointer, &ulong, &pointer_ulong],
            Some(&long),
        )?;
    }
    ct.prototype(
        &advapi,
        c"RegEnumKeyExW",
        &[
            &ct.pointer,
            &dword,
            &ct.win(c"LPWSTR")?,
            &pointer_dword,
            &ct.pointer,
            &ct.pointer,
            &ct.pointer,
            &ct.pointer,
        ],
        None,
    )?;
    ct.prototype(
        &advapi,
        c"RegQueryInfoKeyW",
        &[
            &ct.pointer,
            &ct.pointer,
            &ct.pointer,
            &ct.pointer,
            &pointer_dword,
            &ct.pointer,
            &ct.pointer,
            &pointer_dword,
            &ct.pointer,
            &ct.pointer,
            &ct.pointer,
            &ct.pointer_to(&ct.module.attr(c"c_longlong")?)?,
        ],
        None,
    )?;
    let boolean = ct.win(c"BOOL")?;
    let job = ct.prototype(
        &kernel,
        c"IsProcessInJob",
        &[&ct.pointer, &ct.pointer, &ct.pointer_to(&boolean)?],
        None,
    )?;
    ct.prototype(
        &kernel,
        c"CompareStringOrdinal",
        &[
            &ct.win(c"LPCWSTR")?,
            &integer,
            &ct.win(c"LPCWSTR")?,
            &integer,
            &boolean,
        ],
        None,
    )?;
    kernel
        .attr(c"GetCurrentProcess")?
        .set(c"restype", &ct.pointer)?;
    *phase = "ti-job-query";
    let in_job = boolean.call(&[])?;
    require(
        job.call(&[
            &kernel.method(c"GetCurrentProcess", &[])?,
            &Owned::none(),
            &ct.reference(&in_job)?,
        ])?
        .truth()?,
    )?;
    *phase = "ti-job-value";
    require(in_job.attr(c"value")?.truth()?)?;
    let clock = globals.get(c"time")?.attr(c"monotonic")?;
    let started = clock.call(&[])?;
    Registry {
        ct,
        native,
        advapi,
        kernel,
        unicode,
        attributes,
        clock,
        started,
    }
    .inventory(&token, phase)
}
