//! Genuine subprocess.Popen owner, LOCAL pipes, fair bounded capture and all-attempt cleanup.
use super::{
    descendant_api::Native,
    failure::Events,
    object::{Exception, Fault, Owned, Result, require},
};

pub struct Buffer<const N: usize> {
    bytes: [u8; N],
    length: usize,
}
impl<const N: usize> Buffer<N> {
    pub fn new() -> Self {
        Self {
            bytes: [0; N],
            length: 0,
        }
    }
    pub fn bytes(&self) -> &[u8] {
        // Only append mutates length, after checking the fixed capacity.
        unsafe { core::slice::from_raw_parts(self.bytes.as_ptr(), self.length) }
    }
    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        require(bytes.len() <= N - self.length)?;
        self.bytes
            .get_mut(self.length..self.length + bytes.len())
            .ok_or(Fault::Control)?
            .copy_from_slice(bytes);
        self.length += bytes.len();
        Ok(())
    }
    fn text(&self) -> Result<Owned> {
        Owned::bytes(self.bytes())?
            .method(
                c"decode",
                &[&Owned::text("ascii")?, &Owned::text("strict")?],
            )?
            .method(c"replace", &[&Owned::text("\r\n")?, &Owned::text("\n")?])?
            .method(c"replace", &[&Owned::text("\r")?, &Owned::text("\n")?])
    }
}
impl<const N: usize> Drop for Buffer<N> {
    fn drop(&mut self) {
        self.bytes.fill(0);
        self.length = 0;
    }
}
pub struct Complete {
    pub code: u32,
    pub stdout: Owned,
    pub stderr: Owned,
}
pub struct CaptureFailure {
    pub errors: Events,
    pub stderr: Buffer<512>,
}
struct Handles {
    values: [Option<Owned>; 5],
}
impl Handles {
    fn new() -> Self {
        Self {
            values: core::array::from_fn(|_| None),
        }
    }
    fn own(&mut self, api: &Native<'_>, handle: &Owned) -> Result<()> {
        if api.valid(handle)? {
            for value in self.values.iter().flatten() {
                require(!value.equal(handle)?)?;
            }
            let slot = self
                .values
                .iter_mut()
                .find(|slot| slot.is_none())
                .ok_or(Fault::Control)?;
            *slot = Some(handle.clone_ref());
        }
        Ok(())
    }
    fn close(&mut self, api: &Native<'_>, handle: &Owned) -> Result<()> {
        let mut found = None;
        for (index, value) in self.values.iter().enumerate() {
            if let Some(value) = value {
                if value.equal(handle)? {
                    found = Some(index);
                    break;
                }
            }
        }
        // Remove ownership before the sole attempt; a recycled handle is never retried.
        let value = self
            .values
            .get_mut(found.ok_or(Fault::Control)?)
            .ok_or(Fault::Control)?
            .take()
            .ok_or(Fault::Control)?;
        api.close(&value)
    }
    fn retire(&mut self, api: &Native<'_>, errors: &mut Events) {
        for value in &mut self.values {
            if let Some(value) = value.take() {
                if let Err(error) = api.close(&value) {
                    errors.cleanup(error);
                }
            }
        }
    }
}
fn now(clock: &Owned) -> Result<Owned> {
    clock.call(&[])
}
fn timeout() -> Fault {
    let error = unsafe { Owned::borrowed(super::ffi::PyExc_TimeoutError) }
        .and_then(|class| class.call(&[&Owned::text("fixed descendant deadline exceeded")?]))
        .and_then(|value| Exception::from_value(&value));
    match error {
        Ok(error) => Fault::Python(error),
        Err(error) => error,
    }
}
fn check(clock: &Owned, end: &Owned) -> Result<()> {
    if !now(clock)?.less(end)? {
        Err(timeout())
    } else {
        Ok(())
    }
}
fn spawn(globals: &Owned, handles: [&Owned; 3]) -> Result<Owned> {
    let subprocess = globals.get(c"subprocess")?;
    let sys = globals.get(c"sys")?;
    let standard = Owned::list(&handles)?;
    let attributes = Owned::dict()?;
    attributes.put(c"handle_list", &standard)?;
    let keywords = Owned::dict()?;
    keywords.put(c"dwFlags", &subprocess.attr(c"STARTF_USESTDHANDLES")?)?;
    for (key, handle) in [c"hStdInput", c"hStdOutput", c"hStdError"]
        .into_iter()
        .zip(handles)
    {
        keywords.put(key, handle)?;
    }
    keywords.put(c"lpAttributeList", &attributes)?;
    let startup = subprocess.attr(c"STARTUPINFO")?.call_kw(&[], &keywords)?;
    let script = globals
        .get(c"Path")?
        .call(&[&globals.get(c"__file__")?])?
        .method(c"resolve", &[])?
        .string()?;
    let arguments = super::small::Objects::<8>::collect([
        sys.attr(c"executable"),
        Owned::text("-I"),
        Owned::text("-B"),
        Owned::text("-X"),
        Owned::text("utf8"),
        Ok(script),
        Owned::text("--descendant"),
    ])?
    .list()?;
    let keywords = Owned::dict()?;
    for key in [c"stdin", c"stdout", c"stderr"] {
        keywords.put(key, &Owned::none())?;
    }
    keywords.put(c"startupinfo", &startup)?;
    keywords.put(c"close_fds", &Owned::boolean(true)?)?;
    let flags = subprocess.attr(c"DETACHED_PROCESS")?.u64()?
        | subprocess.attr(c"CREATE_NO_WINDOW")?.u64()?;
    keywords.put(c"creationflags", &Owned::unsigned(flags)?)?;
    let environment = Owned::import(c"builtins")?
        .attr(c"dict")?
        .call(&[&globals.get(c"os")?.attr(c"environ")?])?;
    keywords.put(c"env", &environment)?;
    let directory = globals
        .get(c"Path")?
        .call(&[&sys.attr(c"executable")?])?
        .attr(c"parent")?
        .string()?;
    keywords.put(c"cwd", &directory)?;
    subprocess.attr(c"Popen")?.call_kw(&[&arguments], &keywords)
}
fn drain<const N: usize>(
    api: &Native<'_>,
    handle: &Owned,
    buffer: &mut Buffer<N>,
    final_round: bool,
    clock: &Owned,
    end: &Owned,
) -> Result<bool> {
    check(clock, end)?;
    let available = match api.peek(handle)? {
        Some(available) => available,
        None => return Ok(true),
    };
    require(available <= N - buffer.length)?;
    if available != 0 {
        let block = api.read(handle, available.min(1024))?;
        let bytes = block.raw_bytes(1024)?;
        require(!bytes.is_empty() && bytes.len() <= available.min(1024))?;
        buffer.append(bytes)?;
    } else if final_round {
        return Err(Fault::Control);
    }
    Ok(false)
}
pub fn run(globals: &Owned, api: &Native<'_>) -> core::result::Result<Complete, CaptureFailure> {
    let mut handles = Handles::new();
    let mut output = Buffer::<1024>::new();
    let mut stderr = Buffer::<512>::new();
    let mut child: Option<Owned> = None;
    let mut signaled = false;
    let mut code = None;
    let mut clock = None;
    let result = (|| {
        let os = globals.get(c"os")?;
        require(os.attr(c"name")?.utf8(16)? == "nt")?;
        let sys = globals.get(c"sys")?;
        let version = sys.attr(c"version_info")?;
        require(
            version.index(0)?.u64()? == 3
                && version.index(1)?.u64()? == 11
                && super::bootstrap::require_arguments(&sys)? == super::wire::Role::Primary,
        )?;
        clock = Some(globals.get(c"time")?.attr(c"monotonic")?);
        let clock = clock.as_ref().ok_or(Fault::Control)?;
        let end = now(clock)?.add(&Owned::unsigned(5)?)?;
        let check_time = || check(clock, &end);
        let mut own = |handle: &Owned| handles.own(api, handle);
        let (stdout, stdout_write) = api.pair("output", &mut own, &check_time)?;
        let (errors, stderr_write) = api.pair("error", &mut own, &check_time)?;
        let stdin = api.input(&mut own, &check_time)?;
        api.standards([&stdin, &stdout_write, &stderr_write])?;
        check_time()?;
        child = Some(spawn(globals, [&stdin, &stdout_write, &stderr_write])?);
        require(!child.as_ref().ok_or(Fault::Control)?.is_none())?;
        for handle in [&stdout_write, &stderr_write, &stdin] {
            handles.close(api, handle)?;
        }
        let process = child.as_ref().ok_or(Fault::Control)?.attr(c"_handle")?;
        let mut ended = [false, false];
        while !signaled {
            if !ended[0] {
                ended[0] = drain(api, &stdout, &mut output, false, clock, &end)?;
            }
            if !ended[1] {
                ended[1] = drain(api, &errors, &mut stderr, false, clock, &end)?;
            }
            check_time()?;
            let remaining = end
                .subtract(&now(clock)?)?
                .multiply(&Owned::unsigned(1000)?)?
                .integer()?
                .i64()?;
            signaled = api.wait(&process, remaining.clamp(1, 25) as u64)?;
        }
        let observed = api.exit(&process)?;
        code = Some(observed);
        child
            .as_ref()
            .ok_or(Fault::Control)?
            .set(c"returncode", &Owned::unsigned(observed as u64)?)?;
        check_time()?;
        for _ in 0..1024 + 512 + 2 {
            if !ended[0] {
                ended[0] = drain(api, &stdout, &mut output, true, clock, &end)?;
            }
            if !ended[1] {
                ended[1] = drain(api, &errors, &mut stderr, true, clock, &end)?;
            }
            if ended == [true, true] {
                break;
            }
        }
        require(ended == [true, true])?;
        Ok(Complete {
            code: observed,
            stdout: output.text()?,
            stderr: stderr.text()?,
        })
    })();
    let mut failures = Events::new();
    let cleanup_end = match clock
        .as_ref()
        .map(|clock| now(clock).and_then(|time| time.add(&Owned::unsigned(2)?)))
        .transpose()
    {
        Ok(end) => end,
        Err(error) => {
            failures.cleanup(error);
            None
        }
    };
    if let Some(child) = &child {
        if !signaled {
            if let Err(error) = child.attr(c"_handle").and_then(|handle| api.kill(&handle)) {
                failures.cleanup(error);
            }
            let reaped = child.attr(c"_handle").and_then(|handle| {
                let remaining = match cleanup_end.as_ref() {
                    Some(end) => end
                        .subtract(&now(clock.as_ref().ok_or(Fault::Control)?)?)?
                        .multiply(&Owned::unsigned(1000)?)?
                        .integer()?
                        .i64()?
                        .max(0) as u64,
                    None => 0,
                };
                require(api.wait(&handle, remaining)?)
            });
            if let Err(error) = reaped {
                failures.cleanup(error);
            }
        }
        handles.retire(api, &mut failures);
        if let Err(error) = child
            .attr(c"_handle")
            .and_then(|handle| handle.method(c"Close", &[]))
        {
            failures.cleanup(error);
        }
        if let Err(error) =
            Owned::boolean(false).and_then(|flag| child.set(c"_child_created", &flag))
        {
            failures.cleanup(error);
        }
    } else {
        handles.retire(api, &mut failures);
    }
    if let Some(end) = cleanup_end {
        if let Err(error) = clock
            .as_ref()
            .ok_or(Fault::Control)
            .and_then(|clock| check(clock, &end))
        {
            failures.cleanup(error);
        }
    }
    match result {
        Ok(complete) if failures.is_empty() => Ok(complete),
        result => {
            let mut errors = match result {
                Ok(_) => Events::new(),
                Err(error) => Events::from_fault(error, "descendant"),
            };
            errors.append_fault(Fault::Events(failures), "close");
            errors.child_exit = code;
            Err(CaptureFailure { errors, stderr })
        }
    }
}
