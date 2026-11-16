//! Rust authority entry operations; JSON/streams/subprocess remain genuine external runtime objects.
use super::{
    bootstrap, child_wire,
    ctypes::Ctypes,
    descendant,
    descendant_api::Native,
    failure::Events,
    object::{Fault, Owned, Result, require},
    registry,
    wire::Role,
};

fn record(inventory: registry::Inventory, role: Role) -> Result<Owned> {
    let result = Owned::dict()?;
    result.put(
        c"accessible",
        &Owned::unsigned(inventory.accessible as u64)?,
    )?;
    result.put(c"capabilities", &Owned::unsigned(0)?)?;
    result.put(c"granted_access", &Owned::unsigned(0x20019)?)?;
    for key in [
        c"lpac",
        c"mutation_denied",
        c"no_reparse",
        c"read",
        c"restricted",
        c"x64",
    ] {
        result.put(key, &Owned::boolean(true)?)?;
    }
    result.put(c"read_surface_approved", &Owned::boolean(false)?)?;
    result.put(c"subkeys", &Owned::unsigned(inventory.subkeys as u64)?)?;
    result.put(c"version", &Owned::unsigned(1)?)?;
    result.put(c"role", &Owned::text(role.name())?)?;
    Ok(result)
}
fn json(globals: &Owned, record: &Owned) -> Result<Owned> {
    let keywords = Owned::dict()?;
    keywords.put(c"sort_keys", &Owned::boolean(true)?)?;
    keywords.put(
        c"separators",
        &Owned::tuple(&[&Owned::text(",")?, &Owned::text(":")?])?,
    )?;
    keywords.put(c"ensure_ascii", &Owned::boolean(true)?)?;
    let encoded = globals
        .get(c"json")?
        .attr(c"dumps")?
        .call_kw(&[record], &keywords)?;
    encoded.method(c"__add__", &[&Owned::text("\n")?])
}
fn child_result(child: &descendant::Complete) -> Result<Owned> {
    if let Some(mut events) = child_wire::bootstrap(child.stderr.utf8(512)?.as_bytes()) {
        events.label("descendant", "transport");
        events.child_exit = Some(child.code);
        return Err(Fault::Events(events));
    }
    if child.code != 0 {
        let mut errors = child_wire::nonzero(child.stderr.utf8(512)?.as_bytes());
        errors.child_exit = Some(child.code);
        return Err(Fault::Events(errors));
    }
    if child.stderr.length()? != 0 || child.stdout.length()? > 1024 {
        let mut errors = Events::new();
        errors.label("descendant", "transport");
        errors.child_exit = Some(child.code);
        return Err(Fault::Events(errors));
    }
    Ok(child.stdout.clone_ref())
}
fn complete(
    globals: &Owned,
    child: &descendant::Complete,
    record: &Owned,
    phase: &mut &'static str,
) -> Result<()> {
    *phase = "descendant";
    let result = (|| {
        let descendant = child_result(child)?;
        let parsed = globals.get(c"json")?.method(c"loads", &[&descendant])?;
        require(
            parsed.exact(core::ptr::addr_of!(super::ffi::PyDict_Type))?
                && parsed.get(c"role")?.equal(&Owned::text("descendant")?)?
                && parsed
                    .method(c"keys", &[])?
                    .equal(&record.method(c"keys", &[])?)?,
        )?;
        let own = json(globals, record)?;
        let output = own.method(c"__add__", &[&descendant])?;
        require(
            output
                .method(c"encode", &[&Owned::text("utf-8")?])?
                .length()?
                <= 2048
                && output.method(c"isascii", &[])?.truth()?,
        )?;
        *phase = "report";
        bootstrap::write(&globals.get(c"sys")?, c"stdout", output.utf8(2048)?, false)
    })();
    result.map_err(|error| {
        let mut errors = Events::from_fault(error, phase);
        errors.child_exit = Some(child.code);
        Fault::Events(errors)
    })
}
pub fn main(globals: &Owned, ct: &Ctypes, phase: &mut &'static str) -> Result<()> {
    let sys = globals.get(c"sys")?;
    let role = bootstrap::require_arguments(&sys)?;
    let inventory = registry::controls(globals, ct, phase)?;
    let record = record(inventory, role)?;
    // The original also performs this first serialization before launching a primary's child.
    let own = json(globals, &record)?;
    if role == Role::Descendant {
        *phase = "report";
        return bootstrap::write(&sys, c"stdout", own.utf8(2048)?, false);
    }
    *phase = "descendant";
    let api = Native::new(ct)?;
    let child = match descendant::run(globals, &api) {
        Ok(child) => child,
        Err(capture) => {
            let receipt = child_wire::captured(capture.stderr.bytes(), capture.errors.child_exit);
            let mut errors = receipt.unwrap_or_else(Events::new);
            errors.append_fault(Fault::Events(capture.errors), "descendant");
            return Err(Fault::Events(errors));
        }
    };
    complete(globals, &child, &record, phase)
}
pub fn dispatch(globals: &Owned, phase: &Owned, original: &Owned) -> Result<i64> {
    require(globals.exact(core::ptr::addr_of!(super::ffi::PyDict_Type))?)?;
    let sys = globals.get(c"sys")?;
    let phase = super::classify::bootstrap_phase(phase)?;
    if !original.is_none() {
        // A report fault cannot emit another traceback or secondary receipt.
        let _ = bootstrap::report(&sys, phase, original);
        return Ok(1);
    }
    require(phase == "import-time")?;
    let mut phase = "start";
    let result = Ctypes::from_imports(globals).and_then(|ct| main(globals, &ct, &mut phase));
    match result {
        Ok(()) => Ok(0),
        Err(error) => {
            let errors = Events::from_fault(error, phase);
            let reported = errors
                .wire(bootstrap::role(&sys)?, &globals.get(c"subprocess")?)
                .and_then(|text| bootstrap::write(&sys, c"stderr", text.text(), false));
            // As in entry(), an unsuccessful reporter stays fatal; no private error reaches Python.
            let _ = reported;
            Ok(1)
        }
    }
}
