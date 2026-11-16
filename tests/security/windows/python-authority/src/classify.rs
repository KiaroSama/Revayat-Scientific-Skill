//! Source-exact bootstrap categories, using the actual exception's type/name/message objects.
use super::{
    ffi,
    object::{Exception, Owned, Result, require},
};

pub fn import_category(error: &Exception) -> Result<&'static str> {
    let value = error.value.as_ref().ok_or(super::object::Fault::Control)?;
    if value.instance(unsafe { ffi::PyExc_ImportError })? {
        let kind = error
            .kind
            .as_ref()
            .ok_or(super::object::Fault::Control)?
            .pointer();
        let missing = kind == unsafe { ffi::PyExc_ModuleNotFoundError };
        if !missing && kind != unsafe { ffi::PyExc_ImportError } {
            return Ok("import-unrecognized");
        }
        let name = value.attr(c"name")?;
        let label = if name.is_none() {
            "absent"
        } else if name.exact(core::ptr::addr_of!(ffi::PyUnicode_Type))? {
            // Compare actual Unicode objects as the original dict lookup does.
            // Unknown strings (including lone surrogates) never need UTF-8 encoding.
            let mut label = "unrecognized";
            for (text, category) in [
                ("ctypes", "ctypes"),
                ("_ctypes", "ctypes-native"),
                ("struct", "struct"),
                ("_struct", "struct-native"),
                ("ctypes._endian", "endian"),
                ("os", "os"),
                ("types", "types"),
            ] {
                if name.equal(&Owned::text(text)?)? {
                    label = category;
                    break;
                }
            }
            if label == "ctypes-native" && !missing {
                let message = value.attr(c"msg")?;
                if message.exact(core::ptr::addr_of!(ffi::PyUnicode_Type))? {
                    for (text, category) in [
                        (
                            "DLL load failed while importing _ctypes: Access is denied.",
                            "import-ctypes-denied",
                        ),
                        (
                            "DLL load failed while importing _ctypes: The specified module could not be found.",
                            "import-ctypes-module",
                        ),
                        (
                            "DLL load failed while importing _ctypes: The specified procedure could not be found.",
                            "import-ctypes-procedure",
                        ),
                        (
                            "DLL load failed while importing _ctypes: A dynamic link library (DLL) initialization routine failed.",
                            "import-ctypes-init",
                        ),
                        (
                            "DLL load failed while importing _ctypes: Not enough memory resources are available to process this command.",
                            "import-ctypes-memory",
                        ),
                        (
                            "DLL load failed while importing _ctypes: %1 is not a valid Win32 application.",
                            "import-ctypes-format",
                        ),
                    ] {
                        if message.equal(&Owned::text(text)?)? {
                            return Ok(category);
                        }
                    }
                }
            }
            label
        } else {
            "unrecognized"
        };
        return Ok(match (missing, label) {
            (true, "ctypes") => "missing-ctypes",
            (false, "ctypes") => "import-ctypes",
            (true, "ctypes-native") => "missing-ctypes-native",
            (false, "ctypes-native") => "import-ctypes-native",
            (true, "struct") => "missing-struct",
            (false, "struct") => "import-struct",
            (true, "struct-native") => "missing-struct-native",
            (false, "struct-native") => "import-struct-native",
            (true, "endian") => "missing-endian",
            (false, "endian") => "import-endian",
            (true, "os") => "missing-os",
            (false, "os") => "import-os",
            (true, "types") => "missing-types",
            (false, "types") => "import-types",
            (true, "absent") => "missing-absent",
            (false, "absent") => "import-absent",
            (true, _) => "missing-unrecognized",
            (false, _) => "import-unrecognized",
        });
    }
    Ok(if value.instance(unsafe { ffi::PyExc_OSError })? {
        "native"
    } else {
        "other"
    })
}

pub fn general(error: &Exception, subprocess: &Owned) -> Result<&'static str> {
    let value = error.value.as_ref().ok_or(super::object::Fault::Control)?;
    if value.instance(unsafe { ffi::PyExc_TimeoutError })?
        || value.instance(subprocess.attr(c"TimeoutExpired")?.pointer())?
    {
        return Ok("timeout");
    }
    for (class, label) in [
        (unsafe { ffi::PyExc_UnicodeDecodeError }, "decode"),
        (unsafe { ffi::PyExc_UnicodeEncodeError }, "encode"),
        (unsafe { ffi::PyExc_OSError }, "native"),
        (unsafe { ffi::PyExc_RuntimeError }, "control"),
    ] {
        if value.instance(class)? {
            return Ok(label);
        }
    }
    Ok("other")
}

pub fn bootstrap_phase(value: &Owned) -> Result<&'static str> {
    let text = value.utf8(64)?;
    let phases = [
        "import-ctypes",
        "import-ctypes-wintypes",
        "import-json",
        "import-os",
        "import-pathlib",
        "import-runpy",
        "import-subprocess",
        "import-time",
    ];
    require(phases.contains(&text))?;
    phases
        .into_iter()
        .find(|phase| *phase == text)
        .ok_or(super::object::Fault::Control)
}
