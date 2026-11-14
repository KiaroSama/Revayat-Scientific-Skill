//! RegistryDescendant.Native through the real ctypes WinDLL objects and exact prototypes.
use super::{
    ctypes::Ctypes,
    object::{Exception, Fault, Owned, Result, require},
    wire::Text,
};
pub struct Native<'a> {
    pub ct: &'a Ctypes,
    pub kernel: Owned,
    bcrypt: Owned,
    security: Owned,
}
/// Exact RegistryDescendant.Native.valid contract, independently callable under the GIL.
pub fn valid_handle(handle: &Owned) -> Result<bool> {
    if !handle.exact(core::ptr::addr_of!(super::ffi::PyLong_Type))? {
        return Ok(false);
    }
    // Reject arbitrary-size Python integers before narrowing. In particular a
    // failed c_void_p call returns UINT64_MAX, which is not a signed i64.
    Ok(Owned::unsigned(0)?.less(handle)? && handle.less(&Owned::unsigned(0x7fffffffffffffff)?)?)
}
impl<'a> Native<'a> {
    pub fn new(ct: &'a Ctypes) -> Result<Self> {
        let kernel = ct.library("kernel32", true)?;
        let bcrypt = ct.library("bcrypt", false)?;
        let u32_type = ct.module.attr(c"c_uint32")?;
        let i32_type = ct.module.attr(c"c_int32")?;
        let security = ct.structure(
            "Security",
            &[
                ("length", &u32_type),
                ("descriptor", &ct.pointer),
                ("inherit", &i32_type),
            ],
        )?;
        let p = &ct.pointer;
        let pu32 = ct.pointer_to(&u32_type)?;
        let pp = ct.pointer_to(p)?;
        let ps = ct.pointer_to(&security)?;
        let wide = ct.win(c"LPCWSTR")?;
        for (name, args, result) in [
            (
                c"CreateNamedPipeW",
                &[
                    &wide, &u32_type, &u32_type, &u32_type, &u32_type, &u32_type, &u32_type, &ps,
                ][..],
                p,
            ),
            (
                c"CreateFileW",
                &[&wide, &u32_type, &u32_type, &ps, &u32_type, &u32_type, p][..],
                p,
            ),
            (c"ConnectNamedPipe", &[p, p][..], &i32_type),
            (c"GetNamedPipeClientProcessId", &[p, &pu32][..], &i32_type),
            (c"GetCurrentProcessId", &[][..], &u32_type),
            (c"GetCurrentProcess", &[][..], p),
            (c"GetStdHandle", &[&u32_type][..], p),
            (c"GetFileType", &[p][..], &u32_type),
            (
                c"SetHandleInformation",
                &[p, &u32_type, &u32_type][..],
                &i32_type,
            ),
            (c"GetHandleInformation", &[p, &pu32][..], &i32_type),
            (
                c"DuplicateHandle",
                &[p, p, p, &pp, &u32_type, &i32_type, &u32_type][..],
                &i32_type,
            ),
            (
                c"PeekNamedPipe",
                &[p, p, &u32_type, p, &pu32, p][..],
                &i32_type,
            ),
            (c"ReadFile", &[p, p, &u32_type, &pu32, p][..], &i32_type),
            (c"WaitForSingleObject", &[p, &u32_type][..], &u32_type),
            (c"GetExitCodeProcess", &[p, &pu32][..], &i32_type),
            (c"TerminateProcess", &[p, &u32_type][..], &i32_type),
            (c"CloseHandle", &[p][..], &i32_type),
        ] {
            ct.prototype(&kernel, name, args, Some(result))?;
        }
        ct.prototype(
            &bcrypt,
            c"BCryptGenRandom",
            &[p, p, &u32_type, &u32_type],
            Some(&i32_type),
        )?;
        require(ct.size(p)? == 8 && ct.size(&security)? == 24)?;
        Ok(Self {
            ct,
            kernel,
            bcrypt,
            security,
        })
    }
    pub fn valid(&self, handle: &Owned) -> Result<bool> {
        valid_handle(handle)
    }
    fn winerror(&self, error: u64) -> Result<Fault> {
        let value = self
            .ct
            .module
            .method(c"WinError", &[&Owned::unsigned(error)?])?;
        Ok(Fault::Python(Exception::from_value(&value)?))
    }
    fn checked(&self, success: &Owned) -> Result<()> {
        if success.truth()? {
            Ok(())
        } else {
            Err(self.winerror(self.ct.last_error()?)?)
        }
    }
    pub fn pair(
        &self,
        role: &str,
        own: &mut impl FnMut(&Owned) -> Result<()>,
        check: &impl Fn() -> Result<()>,
    ) -> Result<(Owned, Owned)> {
        require(role == "output" || role == "error")?;
        check()?;
        let nonce = self
            .ct
            .array(&self.ct.module.attr(c"c_ubyte")?, 16)?
            .call(&[])?;
        let mut path = None;
        let operation = (|| {
            require(
                self.bcrypt
                    .method(
                        c"BCryptGenRandom",
                        &[
                            &Owned::none(),
                            &nonce,
                            &Owned::unsigned(16)?,
                            &Owned::unsigned(2)?,
                        ],
                    )?
                    .i64()?
                    == 0,
            )?;
            let mut text = Text::<128>::new();
            text.push("\\\\.\\pipe\\LOCAL\\RegistryAuthority-")?;
            for index in 0..16 {
                text.hex(nonce.index(index)?.u64()?, 2)?;
            }
            text.push("-")?;
            text.push(role)?;
            path = Some(
                self.ct
                    .module
                    .method(c"create_unicode_buffer", &[&Owned::text(text.text())?])?,
            );
            let path = path.as_ref().ok_or(Fault::Control)?;
            let security = self.security.call(&[
                &Owned::unsigned(self.ct.size(&self.security)? as u64)?,
                &Owned::none(),
                &Owned::unsigned(0)?,
            ])?;
            let server = self.kernel.method(
                c"CreateNamedPipeW",
                &[
                    path,
                    &Owned::unsigned(0x80001)?,
                    &Owned::unsigned(9)?,
                    &Owned::unsigned(1)?,
                    &Owned::unsigned(4096)?,
                    &Owned::unsigned(4096)?,
                    &Owned::unsigned(0)?,
                    &self.ct.reference(&security)?,
                ],
            )?;
            let error = if !server.is_none() && server.u64()? == u64::MAX {
                Some(self.ct.last_error()?)
            } else {
                None
            };
            own(&server)?;
            if let Some(error) = error {
                return Err(self.winerror(error)?);
            }
            require(self.valid(&server)?)?;
            check()?;
            security.set(c"inherit", &Owned::unsigned(1)?)?;
            let client = self.kernel.method(
                c"CreateFileW",
                &[
                    path,
                    &Owned::unsigned(0x40000000)?,
                    &Owned::unsigned(0)?,
                    &self.ct.reference(&security)?,
                    &Owned::unsigned(3)?,
                    &Owned::unsigned(0x100000)?,
                    &Owned::none(),
                ],
            )?;
            let error = if !client.is_none() && client.u64()? == u64::MAX {
                Some(self.ct.last_error()?)
            } else {
                None
            };
            own(&client)?;
            if let Some(error) = error {
                return Err(self.winerror(error)?);
            }
            require(self.valid(&client)?)?;
            let connected = self
                .kernel
                .method(c"ConnectNamedPipe", &[&server, &Owned::none()])?
                .truth()?;
            let error = if !connected {
                Some(self.ct.last_error()?)
            } else {
                None
            };
            require(!connected && error == Some(535))?;
            let pid = self.ct.module.attr(c"c_uint32")?.call(&[])?;
            self.checked(&self.kernel.method(
                c"GetNamedPipeClientProcessId",
                &[&server, &self.ct.reference(&pid)?],
            )?)?;
            require(
                self.ct.value(&pid)? == self.kernel.method(c"GetCurrentProcessId", &[])?.u64()?,
            )?;
            self.checked(&self.kernel.method(
                c"SetHandleInformation",
                &[&server, &Owned::unsigned(1)?, &Owned::unsigned(0)?],
            )?)?;
            check()?;
            Ok((server, client))
        })();
        let erased = self.ct.module.method(
            c"memset",
            &[
                &nonce,
                &Owned::unsigned(0)?,
                &Owned::unsigned(self.ct.size(&nonce)? as u64)?,
            ],
        );
        let erased_path = path
            .as_ref()
            .map(|path| {
                self.ct.module.method(
                    c"memset",
                    &[
                        path,
                        &Owned::unsigned(0)?,
                        &Owned::unsigned(self.ct.size(path)? as u64)?,
                    ],
                )
            })
            .transpose();
        erased?;
        erased_path?;
        operation
    }
    pub fn input(
        &self,
        own: &mut impl FnMut(&Owned) -> Result<()>,
        check: &impl Fn() -> Result<()>,
    ) -> Result<Owned> {
        check()?;
        let borrowed = self
            .kernel
            .method(c"GetStdHandle", &[&Owned::unsigned(0xfffffff6)?])?;
        require(
            self.valid(&borrowed)? && self.kernel.method(c"GetFileType", &[&borrowed])?.u64()? == 2,
        )?;
        let current = self.kernel.method(c"GetCurrentProcess", &[])?;
        let duplicate = self.ct.pointer.call(&[])?;
        let success = self
            .kernel
            .method(
                c"DuplicateHandle",
                &[
                    &current,
                    &borrowed,
                    &current,
                    &self.ct.reference(&duplicate)?,
                    &Owned::unsigned(0)?,
                    &Owned::boolean(true)?,
                    &Owned::unsigned(2)?,
                ],
            )?
            .truth()?;
        let error = if success {
            None
        } else {
            Some(self.ct.last_error()?)
        };
        let handle = duplicate.attr(c"value")?;
        own(&handle)?;
        if let Some(error) = error {
            return Err(self.winerror(error)?);
        }
        require(
            self.valid(&handle)? && self.kernel.method(c"GetFileType", &[&handle])?.u64()? == 2,
        )?;
        check()?;
        Ok(handle)
    }
    pub fn standards(&self, handles: [&Owned; 3]) -> Result<()> {
        for (index, (handle, expected)) in handles.into_iter().zip([2, 3, 3]).enumerate() {
            for prior in &handles[..index] {
                require(!handle.equal(prior)?)?;
            }
            require(
                self.valid(handle)?
                    && handle.u64()? & 3 != 3
                    && self.kernel.method(c"GetFileType", &[handle])?.u64()? == expected,
            )?;
            let flags = self.ct.module.attr(c"c_uint32")?.call(&[])?;
            self.checked(&self.kernel.method(
                c"GetHandleInformation",
                &[handle, &self.ct.reference(&flags)?],
            )?)?;
            require(self.ct.value(&flags)? & 1 == 1)?;
        }
        Ok(())
    }
    pub fn peek(&self, handle: &Owned) -> Result<Option<usize>> {
        let available = self.ct.module.attr(c"c_uint32")?.call(&[])?;
        if self
            .kernel
            .method(
                c"PeekNamedPipe",
                &[
                    handle,
                    &Owned::none(),
                    &Owned::unsigned(0)?,
                    &Owned::none(),
                    &self.ct.reference(&available)?,
                    &Owned::none(),
                ],
            )?
            .truth()?
        {
            return Ok(Some(self.ct.value(&available)? as usize));
        }
        let error = self.ct.last_error()?;
        if error == 109 {
            Ok(None)
        } else {
            Err(self.winerror(error)?)
        }
    }
    pub fn read(&self, handle: &Owned, capacity: usize) -> Result<Owned> {
        require((1..=1024).contains(&capacity))?;
        let buffer = self.ct.buffer(capacity)?;
        let count = self.ct.module.attr(c"c_uint32")?.call(&[])?;
        let result = (|| {
            self.checked(&self.kernel.method(
                c"ReadFile",
                &[
                    handle,
                    &buffer,
                    &Owned::unsigned(capacity as u64)?,
                    &self.ct.reference(&count)?,
                    &Owned::none(),
                ],
            )?)?;
            let count = self.ct.value(&count)? as usize;
            require((1..=capacity).contains(&count))?;
            let raw = buffer.attr(c"raw")?;
            Owned::bytes(raw.raw_bytes(1024)?.get(..count).ok_or(Fault::Control)?)
        })();
        self.ct.module.method(
            c"memset",
            &[
                &buffer,
                &Owned::unsigned(0)?,
                &Owned::unsigned(capacity as u64)?,
            ],
        )?;
        result
    }
    pub fn wait(&self, handle: &Owned, milliseconds: u64) -> Result<bool> {
        let value = self
            .kernel
            .method(
                c"WaitForSingleObject",
                &[handle, &Owned::unsigned(milliseconds)?],
            )?
            .u64()?;
        if value == 0xffffffff {
            return Err(self.winerror(self.ct.last_error()?)?);
        }
        require(value == 0 || value == 0x102)?;
        Ok(value == 0)
    }
    pub fn exit(&self, handle: &Owned) -> Result<u32> {
        let code = self.ct.module.attr(c"c_uint32")?.call(&[])?;
        self.checked(
            &self
                .kernel
                .method(c"GetExitCodeProcess", &[handle, &self.ct.reference(&code)?])?,
        )?;
        Ok(self.ct.value(&code)? as u32)
    }
    pub fn kill(&self, handle: &Owned) -> Result<()> {
        self.checked(
            &self
                .kernel
                .method(c"TerminateProcess", &[handle, &Owned::unsigned(125)?])?,
        )
    }
    pub fn close(&self, handle: &Owned) -> Result<()> {
        self.checked(&self.kernel.method(c"CloseHandle", &[handle])?)
    }
}
