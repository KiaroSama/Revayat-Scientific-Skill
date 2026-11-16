//! Single fixed METH_VARARGS dispatcher. Prerequisite failures cannot mint authority receipts.
use super::{
    body,
    ffi::{self, Object},
    object::{Owned, Result, require},
    wide::Name,
};
use core::{ffi::c_void, ptr};
fn binding(module: &Owned, globals: &Owned) -> Result<()> {
    require(globals.exact(ptr::addr_of!(ffi::PyDict_Type))?)?;
    let sys = globals.get(c"sys")?;
    require(sys.same(&Owned::import(c"sys")?))?;
    let version = sys.attr(c"version_info")?;
    require(
        version.index(0)?.u64()? == 3
            && version.index(1)?.u64()? == 11
            && sys.attr(c"maxsize")?.u64()? == 0x7fffffffffffffff
            && sys.attr(c"flags")?.attr(c"isolated")?.u64()? == 1,
    )?;
    let executable = sys.attr(c"executable")?;
    let executable = executable.utf8(32768)?;
    let directory = executable
        .strip_suffix("\\python.exe")
        .ok_or(super::object::Fault::Control)?;
    let mut image = Name::new();
    image.push(directory)?;
    image.push("\\DLLs\\_registry_authority.pyd")?;
    require(
        module.attr(c"__name__")?.utf8(128)? == "_registry_authority"
            && module.attr(c"__file__")?.utf8(8192)? == image.text()?,
    )?;
    let spec = module.attr(c"__spec__")?;
    let loader = module.attr(c"__loader__")?;
    require(
        spec.attr(c"name")?.utf8(128)? == "_registry_authority"
            && spec.attr(c"origin")?.utf8(8192)? == image.text()?
            && spec.attr(c"loader")?.same(&loader)
            && spec.attr(c"has_location")?.truth()?
            && spec.attr(c"submodule_search_locations")?.is_none(),
    )?;
    require(
        loader.attr(c"name")?.utf8(128)? == "_registry_authority"
            && loader.attr(c"path")?.utf8(8192)? == image.text()?,
    )?;
    let mut script = Name::new();
    script.push(directory)?;
    script.push("\\RegistryAuthorityProbe.py")?;
    require(
        globals.get(c"__file__")?.utf8(8192)? == script.text()?
            && sys.attr(c"argv")?.index(0)?.utf8(8192)? == script.text()?,
    )?;
    Ok(())
}
unsafe extern "C" fn dispatch(module: *mut Object, arguments: *mut Object) -> *mut Object {
    let operation = (|| {
        let module = unsafe { Owned::borrowed(module) }?;
        let arguments = unsafe { Owned::borrowed(arguments) }?;
        require(arguments.exact(ptr::addr_of!(ffi::PyTuple_Type))? && arguments.length()? == 3)?;
        let globals = arguments.index(0)?;
        binding(&module, &globals)?;
        let phase = arguments.index(1)?;
        let original = arguments.index(2)?;
        require(original.is_none() || original.instance(unsafe { ffi::PyExc_Exception })?)?;
        Owned::signed(body::dispatch(&globals, &phase, &original)?)
    })();
    match operation {
        Ok(value) => {
            let pointer = value.pointer();
            core::mem::forget(value);
            pointer
        }
        Err(_) => {
            unsafe {
                ffi::PyErr_SetString(
                    ffi::PyExc_RuntimeError,
                    c"fixed authority dispatch prerequisite differs".as_ptr(),
                )
            };
            ptr::null_mut()
        }
    }
}
static mut METHODS: [ffi::Method; 2] = [
    ffi::Method {
        name: c"dispatch".as_ptr(),
        function: Some(dispatch),
        flags: 1,
        doc: ptr::null(),
    },
    ffi::Method {
        name: ptr::null(),
        function: None,
        flags: 0,
        doc: ptr::null(),
    },
];
static mut DEFINITION: ffi::ModuleDef = ffi::ModuleDef {
    base: ffi::ModuleBase {
        object: Object {
            references: 1,
            kind: ptr::null_mut::<c_void>(),
        },
        init: ptr::null_mut(),
        index: 0,
        copy: ptr::null_mut(),
    },
    name: c"_registry_authority".as_ptr(),
    doc: ptr::null(),
    size: -1,
    methods: (&raw mut METHODS).cast(),
    slots: ptr::null_mut(),
    traverse: ptr::null_mut(),
    clear: ptr::null_mut(),
    free: ptr::null_mut(),
};
#[unsafe(no_mangle)]
pub extern "C" fn PyInit__registry_authority() -> *mut Object {
    unsafe { ffi::PyModule_Create2(&raw mut DEFINITION, 1013) }
}
