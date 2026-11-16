//! Original authority token controls through genuine ctypes function objects and ABI classes.
use super::{
    ctypes::Ctypes,
    object::{Exception, Fault, Owned, Result, require},
};
/// KernelProbe.require raises genuine AssertionError; the authority classifier
/// deliberately labels it "other". RegistryAuthority's own require stays Control.
pub fn kernel_require(value: bool, message: &str) -> Result<()> {
    if value {
        return Ok(());
    }
    kernel_assertion(&Owned::text(message)?)
}
fn kernel_assertion(message: &Owned) -> Result<()> {
    let class = unsafe { Owned::borrowed(super::ffi::PyExc_AssertionError) }?;
    let error = class.call(&[message])?;
    Err(Fault::Python(Exception::from_value(&error)?))
}

pub struct TokenApi {
    pub kernel: Owned,
    pub advapi: Owned,
    sid_attributes: Owned,
    groups: Owned,
    privilege: Owned,
    native_unicode: Owned,
    native_attribute: Owned,
    native_attributes: Owned,
}
impl TokenApi {
    /// Source counterpart of KernelProbe's imported ctypes declarations, not its unrelated probes.
    pub fn import(ct: &Ctypes) -> Result<Self> {
        // KernelProbe.py imports errno before constructing the real WinDLL objects.
        Owned::import(c"errno")?;
        let kernel = ct.library("kernel32", true)?;
        let advapi = ct.library("advapi32", true)?;
        let dword = ct.win(c"DWORD")?;
        let long = ct.win(c"LONG")?;
        let ushort = ct.win(c"USHORT")?;
        let ulong = ct.win(c"ULONG")?;
        let integer = ct.module.attr(c"c_int")?;
        let size = ct.module.attr(c"c_size_t")?;
        let pointer_pointer = ct.pointer_to(&ct.pointer)?;
        let pointer_dword = ct.pointer_to(&dword)?;
        kernel
            .attr(c"GetCurrentProcess")?
            .set(c"restype", &ct.pointer)?;
        kernel.attr(c"LocalFree")?.set(c"restype", &ct.pointer)?;
        ct.prototype(
            &kernel,
            c"VirtualAlloc",
            &[&ct.pointer, &size, &dword, &dword],
            Some(&ct.pointer),
        )?;
        ct.prototype(&kernel, c"VirtualFree", &[&ct.pointer, &size, &dword], None)?;
        ct.prototype(
            &advapi,
            c"OpenProcessToken",
            &[&ct.pointer, &dword, &pointer_pointer],
            None,
        )?;
        ct.prototype(
            &advapi,
            c"GetTokenInformation",
            &[&ct.pointer, &integer, &ct.pointer, &dword, &pointer_dword],
            None,
        )?;
        ct.prototype(&kernel, c"CloseHandle", &[&ct.pointer], None)?;
        ct.prototype(
            &kernel,
            c"QueryInformationJobObject",
            &[&ct.pointer, &integer, &ct.pointer, &dword, &ct.pointer],
            None,
        )?;
        let sid_attributes = ct.structure(
            "SidAttributes",
            &[("sid", &ct.pointer), ("attributes", &dword)],
        )?;
        let groups = ct.structure("Groups", &[("count", &dword), ("first", &sid_attributes)])?;
        let luid = ct.structure("Luid", &[("low", &dword), ("high", &long)])?;
        let privilege = ct.structure("Privilege", &[("luid", &luid), ("attributes", &dword)])?;
        let native_unicode = ct.structure(
            "NativeUnicode",
            &[
                ("length", &ushort),
                ("maximum", &ushort),
                ("buffer", &ct.pointer),
            ],
        )?;
        let native_attribute = ct.structure(
            "NativeAttribute",
            &[
                ("name", &native_unicode),
                ("kind", &ushort),
                ("reserved", &ushort),
                ("flags", &ulong),
                ("count", &ulong),
                ("values", &ct.pointer),
            ],
        )?;
        let native_attributes = ct.structure(
            "NativeAttributes",
            &[
                ("version", &ushort),
                ("reserved", &ushort),
                ("count", &ulong),
                ("entries", &ct.pointer),
            ],
        )?;
        Ok(Self {
            kernel,
            advapi,
            sid_attributes,
            groups,
            privilege,
            native_unicode,
            native_attribute,
            native_attributes,
        })
    }
    pub fn detached(&self, ct: &Ctypes) -> Result<()> {
        let dword = ct.win(c"DWORD")?;
        let pointer = ct.pointer_to(&dword)?;
        let console_query = ct.prototype(
            &self.kernel,
            c"GetConsoleProcessList",
            &[&pointer, &dword],
            Some(&dword),
        )?;
        let console = ct.array(&dword, 1)?.call(&[])?;
        ct.module
            .method(c"set_last_error", &[&Owned::unsigned(0)?])?;
        let count = console_query
            .call(&[&console, &Owned::unsigned(1)?])?
            .u64()?;
        let error = ct.last_error()?;
        kernel_require(
            count == 0 && error == 6,
            "contained worker unexpectedly has a console or cannot prove detachment",
        )?;
        let standard = ct.prototype(&self.kernel, c"GetStdHandle", &[&dword], Some(&ct.pointer))?;
        let file_type = ct.prototype(&self.kernel, c"GetFileType", &[&ct.pointer], Some(&dword))?;
        for (identifier, expected) in [(0xfffffff6u64, 2), (0xfffffff5, 3), (0xfffffff4, 3)] {
            let handle = standard.call(&[&Owned::unsigned(identifier)?])?;
            kernel_require(
                !handle.is_none()
                    && handle.u64()? != u64::MAX
                    && file_type.call(&[&handle])?.u64()? == expected,
                "contained standard handle is not the required NUL input or captured pipe",
            )?;
        }
        Ok(())
    }
    fn data(&self, ct: &Ctypes, token: &Owned, kind: u64) -> Result<Owned> {
        let returned = ct.scalar(c"DWORD", 0)?;
        let queried = self.advapi.method(
            c"GetTokenInformation",
            &[
                token,
                &Owned::unsigned(kind)?,
                &Owned::none(),
                &Owned::unsigned(0)?,
                &ct.reference(&returned)?,
            ],
        )?;
        kernel_require(
            !queried.truth()? && ct.last_error()? == 122,
            "unexpected token information size",
        )?;
        let size = ct.value(&returned)?;
        kernel_require(
            (4..=65536).contains(&size),
            "unexpected token information size",
        )?;
        let data = ct.buffer(size as usize)?;
        kernel_require(
            self.advapi
                .method(
                    c"GetTokenInformation",
                    &[
                        token,
                        &Owned::unsigned(kind)?,
                        &data,
                        &Owned::unsigned(size)?,
                        &ct.reference(&returned)?,
                    ],
                )?
                .truth()?,
            "token information unavailable",
        )?;
        kernel_require(
            (4..=size).contains(&ct.value(&returned)?),
            "token information returned invalid bounds",
        )?;
        Ok(data)
    }
    fn sid(&self, ct: &Ctypes, sid: &Owned) -> Result<Owned> {
        let text_class = ct.win(c"LPWSTR")?;
        let pointer_text = ct.pointer_to(&text_class)?;
        let convert = ct.prototype(
            &self.advapi,
            c"ConvertSidToStringSidW",
            &[&ct.pointer, &pointer_text],
            None,
        )?;
        let release = ct.prototype(&self.kernel, c"LocalFree", &[&ct.pointer], None)?;
        let text = text_class.call(&[])?;
        kernel_require(
            convert.call(&[sid, &ct.reference(&text)?])?.truth()?,
            "cannot stringify token SID",
        )?;
        let result = text.attr(c"value");
        let cast = ct.module.method(c"cast", &[&text, &ct.pointer]);
        let closed = cast.and_then(|value| release.call(&[&value]));
        // The original finally must attempt LocalFree even if reading the text failed.
        match (result, closed) {
            (_, Err(error)) => Err(error),
            (result, Ok(_)) => result,
        }
    }
    fn lpac(&self, ct: &Ctypes, token: &Owned) -> Result<bool> {
        kernel_require(
            ct.size(&ct.pointer)? == 8
                && ct.size(&self.native_unicode)? == 16
                && ct.size(&self.native_attributes)? == 16
                && ct.size(&self.native_attribute)? == 40
                && self
                    .native_attribute
                    .attr(c"values")?
                    .attr(c"offset")?
                    .u64()?
                    == 32,
            "LPAC query requires the verified Windows x64 ABI",
        )?;
        let expected =
            Owned::text("WIN://NOALLAPPPKG")?.method(c"encode", &[&Owned::text("utf-16-le")?])?;
        let bytes = expected.raw_bytes(128)?;
        let name = ct.bytes_buffer(bytes)?;
        let query = self.native_unicode.call(&[
            &Owned::unsigned(bytes.len() as u64)?,
            &Owned::unsigned(bytes.len() as u64)?,
            &Owned::unsigned(ct.address(&name)?)?,
        ])?;
        let output = ct.array(&ct.module.attr(c"c_uint64")?, 64)?.call(&[])?;
        let returned = ct.scalar(c"ULONG", 0)?;
        let native = ct.library("ntdll", false)?;
        let ulong = ct.win(c"ULONG")?;
        let function = ct.prototype(
            &native,
            c"NtQuerySecurityAttributesToken",
            &[
                &ct.pointer,
                &ct.pointer_to(&self.native_unicode)?,
                &ulong,
                &ct.pointer,
                &ulong,
                &ct.pointer_to(&ulong)?,
            ],
            Some(&ct.win(c"LONG")?),
        )?;
        let status = function
            .call(&[
                token,
                &ct.reference(&query)?,
                &Owned::unsigned(1)?,
                &output,
                &Owned::unsigned(ct.size(&output)? as u64)?,
                &ct.reference(&returned)?,
            ])?
            .i64()?;
        let length = ct.value(&returned)?;
        if status != 0 || !(16..=ct.size(&output)? as u64).contains(&length) {
            let code = Owned::import(c"builtins")?
                .attr(c"hex")?
                .call(&[&Owned::unsigned(status as u32 as u64)?])?;
            let message = Owned::text("LPAC named-attribute query failed status=")?
                .method(c"__add__", &[&code])?
                .method(c"__add__", &[&Owned::text(" bytes=")?])?
                .method(c"__add__", &[&Owned::unsigned(length)?.string()?])?;
            kernel_assertion(&message)?;
        }
        let start = ct.address(&output)?;
        let span = |pointer: u64, count: u64, alignment: u64| -> Result<u64> {
            kernel_require(
                pointer != 0
                    && pointer.is_multiple_of(alignment)
                    && pointer >= start
                    && pointer - start <= length
                    && count <= length - (pointer - start),
                "LPAC attribute pointer exceeds returned bounds/alignment",
            )?;
            Ok(pointer)
        };
        let header = ct.at(&self.native_attributes, span(start, 16, 8)?)?;
        kernel_require(
            header.attr(c"version")?.u64()? == 1
                && header.attr(c"reserved")?.u64()? == 0
                && header.attr(c"count")?.u64()? == 1,
            "LPAC attribute header is not exact",
        )?;
        let attribute = ct.at(
            &self.native_attribute,
            span(header.attr(c"entries")?.u64()?, 40, 8)?,
        )?;
        kernel_require(
            attribute.attr(c"kind")?.u64()? == 2
                && attribute.attr(c"reserved")?.u64()? == 0
                && attribute.attr(c"count")?.u64()? == 1
                && attribute.attr(c"flags")?.u64()? & 0x10 == 0,
            "LPAC attribute is not one active UInt64",
        )?;
        let attribute_name = attribute.attr(c"name")?;
        let maximum = attribute_name.attr(c"maximum")?.u64()?;
        kernel_require(
            attribute_name.attr(c"length")?.u64()? == bytes.len() as u64
                && maximum >= bytes.len() as u64
                && maximum.is_multiple_of(2),
            "LPAC attribute name length differs",
        )?;
        let pointer = span(attribute_name.attr(c"buffer")?.u64()?, maximum, 2)?;
        let actual = ct
            .module
            .method(
                c"string_at",
                &[
                    &Owned::unsigned(pointer)?,
                    &Owned::unsigned(bytes.len() as u64)?,
                ],
            )?
            .method(
                c"decode",
                &[&Owned::text("utf-16-le")?, &Owned::text("strict")?],
            )?;
        kernel_require(
            actual.utf8(128)? == "WIN://NOALLAPPPKG",
            "LPAC attribute name differs from fixed query",
        )?;
        let value = ct.at(
            &ct.module.attr(c"c_uint64")?,
            span(attribute.attr(c"values")?.u64()?, 8, 8)?,
        )?;
        kernel_require(
            ct.value(&value)? == 1,
            "LPAC attribute value is not exactly enabled",
        )?;
        Ok(true)
    }
    pub fn observe(&self, ct: &Ctypes, final_pass: bool, phase: &mut &'static str) -> Result<()> {
        *phase = stage(final_pass, "open")?;
        let token = ct.pointer.call(&[])?;
        require(
            self.advapi
                .method(
                    c"OpenProcessToken",
                    &[
                        &self.kernel.method(c"GetCurrentProcess", &[])?,
                        &Owned::unsigned(8)?,
                        &ct.reference(&token)?,
                    ],
                )?
                .truth()?,
        )?;
        let operation = (|| {
            let mut values = [0u64; 3];
            for (index, (kind, label)) in [(8, "type"), (20, "elevation"), (21, "restrictions")]
                .into_iter()
                .enumerate()
            {
                *phase = match label {
                    "type" => stage(final_pass, "type-query")?,
                    "elevation" => stage(final_pass, "elevation-query")?,
                    _ => stage(final_pass, "restrictions-query")?,
                };
                let value = ct.scalar(c"DWORD", 0)?;
                let returned = ct.scalar(c"DWORD", 0)?;
                require(
                    self.advapi
                        .method(
                            c"GetTokenInformation",
                            &[
                                &token,
                                &Owned::unsigned(kind)?,
                                &ct.reference(&value)?,
                                &Owned::unsigned(4)?,
                                &ct.reference(&returned)?,
                            ],
                        )?
                        .truth()?,
                )?;
                *phase = match label {
                    "type" => stage(final_pass, "type-length")?,
                    "elevation" => stage(final_pass, "elevation-length")?,
                    _ => stage(final_pass, "restrictions-length")?,
                };
                let length = ct.value(&returned)?;
                if kind == 21 {
                    require(length == 1 || length == 4)?;
                    let bytes = ct.module.method(
                        c"string_at",
                        &[&ct.reference(&value)?, &Owned::unsigned(length)?],
                    )?;
                    let raw = bytes.raw_bytes(4)?;
                    let mut decoded = [0u8; 8];
                    decoded
                        .get_mut(..raw.len())
                        .ok_or(Fault::Control)?
                        .copy_from_slice(raw);
                    values[index] = u64::from_le_bytes(decoded);
                } else {
                    require(length == 4)?;
                    values[index] = ct.value(&value)?;
                }
            }
            *phase = stage(final_pass, "primary-fields")?;
            require(values == [1, 0, 1])?;
            *phase = stage(final_pass, "lpac-query")?;
            let lpac = self.lpac(ct, &token)?;
            *phase = stage(final_pass, "lpac-value")?;
            require(lpac)?;
            *phase = stage(final_pass, "app-read")?;
            let data = self.data(ct, &token, 29)?;
            *phase = stage(final_pass, "app-value")?;
            require(
                ct.size(&data)? == 4
                    && ct.value(&ct.from_buffer(&ct.win(c"DWORD")?, &data, 0)?)? == 1,
            )?;
            *phase = stage(final_pass, "caps-read")?;
            let data = self.data(ct, &token, 30)?;
            *phase = stage(final_pass, "caps-value")?;
            require(ct.value(&ct.from_buffer(&ct.win(c"DWORD")?, &data, 0)?)? == 0)?;
            *phase = stage(final_pass, "priv-read")?;
            let data = self.data(ct, &token, 3)?;
            *phase = stage(final_pass, "priv-count")?;
            let count = ct.value(&ct.from_buffer(&ct.win(c"DWORD")?, &data, 0)?)?;
            let stride = ct.size(&self.privilege)?;
            require(count <= 128 && 4 + count as usize * stride <= ct.size(&data)?)?;
            for index in 0..count as usize {
                *phase = stage(final_pass, "priv-value")?;
                let luid = ct
                    .from_buffer(&self.privilege, &data, 4 + index * stride)?
                    .attr(c"luid")?;
                require(luid.attr(c"low")?.u64()? == 23 && luid.attr(c"high")?.i64()? == 0)?;
            }
            *phase = stage(final_pass, "groups-read")?;
            let data = self.data(ct, &token, 2)?;
            *phase = stage(final_pass, "groups-count")?;
            let count = ct.value(&ct.from_buffer(&ct.win(c"DWORD")?, &data, 0)?)?;
            let offset = self.groups.attr(c"first")?.attr(c"offset")?.u64()? as usize;
            let stride = ct.size(&self.sid_attributes)?;
            require(count <= 256 && offset + count as usize * stride <= ct.size(&data)?)?;
            for index in 0..count as usize {
                *phase = stage(final_pass, "sid-read")?;
                let item = ct.from_buffer(&self.sid_attributes, &data, offset + index * stride)?;
                let sid = self.sid(ct, &item.attr(c"sid")?)?;
                if sid.utf8(32768)? == "S-1-5-32-544" {
                    *phase = stage(final_pass, "admin")?;
                    let attributes = item.attr(c"attributes")?.u64()?;
                    require(attributes & (8 | 4 | 2) == 0 && attributes & 16 != 0)?;
                }
            }
            Ok(())
        })();
        let closed = self
            .kernel
            .method(c"CloseHandle", &[&token])
            .and_then(|value| require(value.truth()?));
        // Both results escape: the reporting owner must append close:cleanup after the
        // original operation event, rather than replacing it with a cleanup success.
        super::failure::close_result(operation, closed, phase)
    }
}
fn stage(final_pass: bool, suffix: &str) -> Result<&'static str> {
    const STAGES: [(&str, &str, &str); 24] = [
        ("open", "ti-open", "tf-open"),
        ("type-query", "ti-type-query", "tf-type-query"),
        ("type-length", "ti-type-length", "tf-type-length"),
        (
            "elevation-query",
            "ti-elevation-query",
            "tf-elevation-query",
        ),
        (
            "elevation-length",
            "ti-elevation-length",
            "tf-elevation-length",
        ),
        (
            "restrictions-query",
            "ti-restrictions-query",
            "tf-restrictions-query",
        ),
        (
            "restrictions-length",
            "ti-restrictions-length",
            "tf-restrictions-length",
        ),
        ("primary-fields", "ti-primary-fields", "tf-primary-fields"),
        ("lpac-query", "ti-lpac-query", "tf-lpac-query"),
        ("lpac-value", "ti-lpac-value", "tf-lpac-value"),
        ("app-read", "ti-app-read", "tf-app-read"),
        ("app-value", "ti-app-value", "tf-app-value"),
        ("caps-read", "ti-caps-read", "tf-caps-read"),
        ("caps-value", "ti-caps-value", "tf-caps-value"),
        ("priv-read", "ti-priv-read", "tf-priv-read"),
        ("priv-count", "ti-priv-count", "tf-priv-count"),
        ("priv-value", "ti-priv-value", "tf-priv-value"),
        ("groups-read", "ti-groups-read", "tf-groups-read"),
        ("groups-count", "ti-groups-count", "tf-groups-count"),
        ("sid-read", "ti-sid-read", "tf-sid-read"),
        ("admin", "ti-admin", "tf-admin"),
        ("traversal", "ti-traversal", "tf-traversal"),
        (
            "restrictions-len1",
            "ti-restrictions-len1",
            "tf-restrictions-len1",
        ),
        ("deadline", "ti-deadline", "tf-deadline"),
    ];
    STAGES
        .into_iter()
        .find(|(label, _, _)| *label == suffix)
        .map(|(_, initial, final_label)| if final_pass { final_label } else { initial })
        .ok_or(Fault::Control)
}
