//! Fixed explicit-ID2 pipe transport. Handles remain owned through real child/job destruction.
use super::*;
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreatePipe(
        read: *mut Handle,
        write: *mut Handle,
        security: *const api::Security,
        size: u32,
    ) -> i32;
    fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> i32;
}
struct Pipe {
    reader: Handle,
    bytes: Vec<u8>,
    eof: bool,
}
impl Pipe {
    fn drain(&mut self) -> Result<()> {
        for _ in 0..=128 {
            let mut available = 0;
            let success = unsafe {
                api::PeekNamedPipe(
                    self.reader,
                    null_mut(),
                    0,
                    null_mut(),
                    &mut available,
                    null_mut(),
                )
            };
            let code = if success == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            if success == 0 {
                ensure!(
                    code == 109,
                    "explicit fixture pipe query failed winerror={code}"
                );
                self.eof = true;
                return Ok(());
            }
            if available == 0 {
                return Ok(());
            }
            let mut buffer = [0u8; 128];
            let capacity = (available as usize).min(buffer.len());
            let mut read = 0;
            let success = unsafe {
                api::ReadFile(
                    self.reader,
                    buffer.as_mut_ptr().cast(),
                    capacity as u32,
                    &mut read,
                    null_mut(),
                )
            };
            let code = if success == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            let result = (|| {
                ensure!(
                    success != 0 && read > 0 && read as usize <= capacity,
                    "explicit fixture pipe read failed winerror={code}"
                );
                ensure!(
                    !self.eof && read as usize <= 128usize.saturating_sub(self.bytes.len()),
                    "explicit fixture pipe transport exceeded bound"
                );
                self.bytes.extend(&buffer[..read as usize]);
                Ok(())
            })();
            buffer.fill(0);
            result?;
        }
        anyhow::bail!("explicit fixture pipe drain budget exceeded")
    }
    fn close(&mut self) -> Result<()> {
        self.bytes.fill(0);
        close(std::mem::replace(&mut self.reader, null_mut()))
    }
}
impl Drop for Pipe {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
pub(super) struct Transport {
    output: Pipe,
    error: Pipe,
}
impl Transport {
    pub fn attach(standard: &mut abi::StandardHandles) -> Result<Self> {
        let empty = || Pipe {
            reader: null_mut(),
            bytes: Vec::new(),
            eof: false,
        };
        let mut owner = Self {
            output: empty(),
            error: empty(),
        };
        let mut writers = [null_mut(); 2];
        let security = api::Security {
            length: size_of::<api::Security>() as u32,
            descriptor: null_mut(),
            inherit: 1,
        };
        let result = (|| {
            for (index, pipe) in [&mut owner.output, &mut owner.error]
                .into_iter()
                .enumerate()
            {
                let success =
                    unsafe { CreatePipe(&mut pipe.reader, &mut writers[index], &security, 4096) };
                let code = if success == 0 {
                    unsafe { GetLastError() }
                } else {
                    0
                };
                ensure!(
                    success != 0 && !pipe.reader.is_null() && !writers[index].is_null(),
                    "explicit fixture pipe creation failed winerror={code}"
                );
                let success = unsafe { SetHandleInformation(pipe.reader, 1, 0) };
                let code = if success == 0 {
                    unsafe { GetLastError() }
                } else {
                    0
                };
                ensure!(
                    success != 0,
                    "explicit fixture reader inheritance removal failed winerror={code}"
                );
            }
            for (index, writer) in writers.iter_mut().enumerate() {
                close(std::mem::replace(
                    &mut standard.handles[index + 1],
                    null_mut(),
                ))?;
                standard.handles[index + 1] = std::mem::replace(writer, null_mut());
            }
            // The later HANDLE_LIST uses this same boxed three-slot backing allocation.
            Ok(())
        })();
        if let Err(primary) = result {
            let mut errors = vec![primary];
            for writer in &mut writers {
                if let Err(error) = close(std::mem::replace(writer, null_mut())) {
                    errors.push(error);
                }
            }
            if let Err(error) = owner.close() {
                errors.push(error);
            }
            return Err(Failures { errors }.into());
        }
        Ok(owner)
    }
    pub fn require_pre_call(&mut self) -> Result<()> {
        self.output.drain()?;
        self.error.drain()?;
        ensure!(
            self.output.bytes == b"EXPLICIT_ID2_BEFORE_CALL\n" && self.error.bytes.is_empty(),
            "explicit CSR call precedes its exact pre-call receipt"
        );
        Ok(())
    }
    pub fn finish(&mut self) -> Result<()> {
        let result = (|| {
            self.output.drain()?;
            self.error.drain()?;
            ensure!(self.output.eof && self.error.eof && self.error.bytes.is_empty()
                && self.output.bytes==b"EXPLICIT_ID2_BEFORE_CALL\nWINDOWS_EXPLICIT_ID2_ACTIVATION entry_reached=True created=True win32_error=0x00000000\n",
                "explicit fixture completed transport differs");
            Ok(())
        })();
        let cleanup = self.close();
        match (result, cleanup) {
            (result, Ok(())) => result,
            (Err(first), Err(second)) => Err(Failures {
                errors: vec![first, second],
            }
            .into()),
            (Ok(_), Err(error)) => Err(error),
        }
    }
    pub(super) fn close(&mut self) -> Result<()> {
        let errors = [self.output.close(), self.error.close()]
            .into_iter()
            .filter_map(Result::err)
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Failures { errors }.into())
        }
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
