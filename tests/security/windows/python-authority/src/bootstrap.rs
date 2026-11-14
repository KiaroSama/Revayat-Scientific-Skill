//! Actual bootstrap error/frame and original ExtensionFileLoader cache/spec/result qualification.
use super::{
    classify, ffi,
    object::{Exception, Owned, Result, require},
    wire::{self, Loader, Role},
};

fn equal(value: &Owned, expected: &str) -> Result<()> {
    require(value.equal(&Owned::text(expected)?)?)
}
fn exact_text(value: &Owned, expected: &str) -> Result<()> {
    require(value.utf8(32768)? == expected)
}
pub fn role(sys: &Owned) -> Result<Role> {
    let args = sys.attr(c"argv")?;
    let count = args.length()?;
    // Bootstrap has the original exact ['--descendant'] test; all other shapes are primary.
    Ok(
        if count == 2 && args.index(1)?.equal(&Owned::text("--descendant")?)? {
            Role::Descendant
        } else {
            Role::Primary
        },
    )
}
pub fn require_arguments(sys: &Owned) -> Result<Role> {
    let args = sys.attr(c"argv")?;
    match args.length()? {
        1 => Ok(Role::Primary),
        2 if args.index(1)?.equal(&Owned::text("--descendant")?)? => Ok(Role::Descendant),
        _ => Err(super::object::Fault::Control),
    }
}
pub fn write(sys: &Owned, stream: &core::ffi::CStr, text: &str, require_count: bool) -> Result<()> {
    let output = sys.attr(stream)?;
    let count = output.method(c"write", &[&Owned::text(text)?])?;
    if require_count {
        require(count.equal(&Owned::unsigned(text.len() as u64)?)?)?;
    }
    output.method(c"flush", &[])?;
    Ok(())
}
pub fn report(sys: &Owned, phase: &'static str, original: &Owned) -> Result<()> {
    let role = role(sys)?;
    let exception = Exception::from_value(original)?;
    let category = classify::import_category(&exception)?;
    let frame = wire::bootstrap(role, phase, category)?;
    write(sys, c"stderr", frame.text(), true)?;
    if phase == "import-ctypes"
        && exception
            .kind
            .as_ref()
            .is_some_and(|kind| kind.pointer() == unsafe { ffi::PyExc_ImportError })
    {
        let name = original.attr(c"name")?;
        if name.exact(core::ptr::addr_of!(ffi::PyUnicode_Type))?
            && name.equal(&Owned::text("_ctypes")?)?
        {
            let outcome = followup(sys).unwrap_or(Loader::Unqualified);
            let tail = outcome.followup(role)?;
            require(frame.text().len() + tail.text().len() <= 512)?;
            write(sys, c"stderr", tail.text(), true)?;
        }
    }
    Ok(())
}
fn followup(sys: &Owned) -> Result<Loader> {
    // These imports occur only after the original bootstrap failure receipt is flushed.
    let machinery = Owned::import(c"importlib.machinery")?;
    let extension = machinery.attr(c"ExtensionFileLoader")?;
    let util = Owned::import(c"importlib.util")?;
    let module_from_spec = util.attr(c"module_from_spec")?;
    let spec_from_file = util.attr(c"spec_from_file_location")?;
    let os = Owned::import(c"os")?;
    exact_text(&sys.attr(c"implementation")?.attr(c"name")?, "cpython")?;
    let version = sys.attr(c"version_info")?;
    require(version.index(0)?.u64()? == 3 && version.index(1)?.u64()? == 11)?;
    require(sys.attr(c"maxsize")?.u64()? == 0x7fffffffffffffff)?;
    let builtins = Owned::import(c"builtins")?;
    require(
        !builtins
            .attr(c"hasattr")?
            .call(&[sys, &Owned::text("gettotalrefcount")?])?
            .truth()?,
    )?;
    require(sys.attr(c"flags")?.attr(c"isolated")?.u64()? == 1)?;
    let executable = sys.attr(c"executable")?;
    executable.utf8(32768)?;
    let name = Owned::text("_registry_loader")?;
    let path_api = os.attr(c"path")?;
    let directory = path_api.method(c"dirname", &[&executable])?;
    let path = path_api.method(
        c"join",
        &[
            &directory,
            &Owned::text("DLLs")?,
            &Owned::text("_registry_loader.pyd")?,
        ],
    )?;
    require(
        path_api.method(c"isabs", &[&path])?.truth()?
            && path_api.method(c"normpath", &[&path])?.equal(&path)?,
    )?;
    let modules = sys.attr(c"modules")?;
    require(
        modules.exact(core::ptr::addr_of!(ffi::PyDict_Type))?
            && modules.optional(c"_registry_loader")?.is_none(),
    )?;
    let values = builtins
        .attr(c"tuple")?
        .call(&[&modules.method(c"values", &[])?])?;
    let count = values.length()?;
    require(count <= 100000)?;
    let normalized = path_api.method(c"normcase", &[&path])?;
    for index in 0..count {
        let module = values.index(index)?;
        if module.is_none() {
            continue;
        }
        let fields = builtins.attr(c"vars")?.call(&[&module])?;
        let origin = fields.method(c"get", &[&Owned::text("__file__")?])?;
        let spec = fields.method(c"get", &[&Owned::text("__spec__")?])?;
        let spec_origin =
            builtins
                .attr(c"getattr")?
                .call(&[&spec, &Owned::text("origin")?, &Owned::none()])?;
        for candidate in [&origin, &spec_origin] {
            if candidate.exact(core::ptr::addr_of!(ffi::PyUnicode_Type))? {
                let absolute = path_api.method(c"abspath", &[candidate])?;
                require(
                    !path_api
                        .method(c"normcase", &[&absolute])?
                        .equal(&normalized)?,
                )?;
            }
        }
    }
    let loader = extension.call(&[&name, &path])?;
    let keywords = Owned::dict()?;
    keywords.put(c"loader", &loader)?;
    let spec = spec_from_file.call_kw(&[&name, &path], &keywords)?;
    require(loader.kind()?.same(&extension))?;
    exact_text(&loader.attr(c"name")?, "_registry_loader")?;
    require(loader.attr(c"path")?.utf8(32768)? == path.utf8(32768)? && !spec.is_none())?;
    exact_text(&spec.attr(c"name")?, "_registry_loader")?;
    require(
        spec.attr(c"origin")?.utf8(32768)? == path.utf8(32768)?
            && spec.attr(c"loader")?.same(&loader)
            && spec.attr(c"has_location")?.truth()?
            && spec.attr(c"submodule_search_locations")?.is_none(),
    )?;
    let module = module_from_spec.call(&[&spec])?;
    loader.method(c"exec_module", &[&module])?;
    equal(&module.attr(c"__name__")?, "_registry_loader")?;
    require(
        module.attr(c"__file__")?.equal(&path)?
            && module.attr(c"__spec__")?.same(&spec)
            && module.attr(c"__loader__")?.same(&loader),
    )?;
    let mut fields = [0u64; 4];
    for (index, field) in [c"loaded", c"load_error", c"release_error", c"version"]
        .into_iter()
        .enumerate()
    {
        let value = module.attr(field)?;
        require(value.exact(core::ptr::addr_of!(ffi::PyLong_Type))?)?;
        fields[index] = value.u64()?;
    }
    Loader::from_fields(fields[0], fields[1], fields[2], fields[3])
}
