//! Genuine ctypes classes, objects, function prototypes and calls; no direct Win32 substitute.
use super::object::{Owned, Result, require};
use core::ffi::CStr;

pub struct Ctypes {
    pub module: Owned,
    pub wintypes: Owned,
    pub pointer: Owned,
    builtins: Owned,
}
impl Ctypes {
    pub fn from_imports(globals: &Owned) -> Result<Self> {
        let module = globals.get(c"ctypes")?;
        let wintypes = globals.get(c"w")?;
        let pointer = module.attr(c"c_void_p")?;
        Ok(Self {
            module,
            wintypes,
            pointer,
            builtins: Owned::import(c"builtins")?,
        })
    }
    pub fn size(&self, object: &Owned) -> Result<usize> {
        let size = self.module.method(c"sizeof", &[object])?.u64()?;
        require(size <= 65536)?;
        Ok(size as usize)
    }
    pub fn reference(&self, value: &Owned) -> Result<Owned> {
        self.module.method(c"byref", &[value])
    }
    pub fn address(&self, value: &Owned) -> Result<u64> {
        self.module.method(c"addressof", &[value])?.u64()
    }
    pub fn pointer_to(&self, class: &Owned) -> Result<Owned> {
        self.module.method(c"POINTER", &[class])
    }
    pub fn win(&self, name: &CStr) -> Result<Owned> {
        self.wintypes.attr(name)
    }
    pub fn scalar(&self, name: &CStr, initial: u64) -> Result<Owned> {
        self.win(name)?.call(&[&Owned::unsigned(initial)?])
    }
    pub fn value(&self, value: &Owned) -> Result<u64> {
        value.attr(c"value")?.u64()
    }
    pub fn library(&self, name: &str, last_error: bool) -> Result<Owned> {
        let keywords = Owned::dict()?;
        if last_error {
            keywords.put(c"use_last_error", &Owned::boolean(true)?)?;
        }
        self.module
            .attr(c"WinDLL")?
            .call_kw(&[&Owned::text(name)?], &keywords)
    }
    pub fn prototype(
        &self,
        library: &Owned,
        name: &CStr,
        args: &[&Owned],
        result: Option<&Owned>,
    ) -> Result<Owned> {
        let function = library.attr(name)?;
        function.set(c"argtypes", &Owned::list(args)?)?;
        if let Some(result) = result {
            function.set(c"restype", result)?;
        }
        Ok(function)
    }
    pub fn structure(&self, name: &str, fields: &[(&str, &Owned)]) -> Result<Owned> {
        require(fields.len() <= 16)?;
        let names =
            super::small::Objects::<16>::collect(fields.iter().map(|(name, _)| Owned::text(name)))?;
        let tuples = super::small::Objects::<16>::collect(
            fields
                .iter()
                .enumerate()
                .map(|(index, (_, class))| Owned::tuple(&[names.get(index)?, class])),
        )?;
        let attrs = Owned::dict()?;
        attrs.put(c"_fields_", &tuples.list()?)?;
        attrs.put(c"__module__", &Owned::text("__main__")?)?;
        let bases = Owned::tuple(&[&self.module.attr(c"Structure")?])?;
        self.builtins
            .attr(c"type")?
            .call(&[&Owned::text(name)?, &bases, &attrs])
    }
    pub fn array(&self, class: &Owned, count: usize) -> Result<Owned> {
        require(count <= 65536)?;
        class.multiply(&Owned::unsigned(count as u64)?)
    }
    pub fn buffer(&self, size: usize) -> Result<Owned> {
        require((1..=65536).contains(&size))?;
        self.module
            .method(c"create_string_buffer", &[&Owned::unsigned(size as u64)?])
    }
    pub fn bytes_buffer(&self, bytes: &[u8]) -> Result<Owned> {
        require(bytes.len() <= 65536)?;
        self.module
            .method(c"create_string_buffer", &[&Owned::bytes(bytes)?])
    }
    pub fn at(&self, class: &Owned, address: u64) -> Result<Owned> {
        class.method(c"from_address", &[&Owned::unsigned(address)?])
    }
    pub fn from_buffer(&self, class: &Owned, buffer: &Owned, offset: usize) -> Result<Owned> {
        class.method(c"from_buffer", &[buffer, &Owned::unsigned(offset as u64)?])
    }
    pub fn last_error(&self) -> Result<u64> {
        self.module.method(c"get_last_error", &[])?.u64()
    }
}
