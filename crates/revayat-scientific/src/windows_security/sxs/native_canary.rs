//! Actual disposable canary token adapter for the shared bounded query and restoration scope.
use super::*;
use crate::windows_security::{
    activation::diagnostics::{self, Numbers, Stage},
    sxs::canary,
};
fn fixed(token: Raw, kind: i32) -> Result<Query> {
    let mut data = Query {
        words: vec![0; 32],
        length: 256,
    };
    let buffer = unsafe { &mut *data.words.as_mut_ptr().cast::<[u8; 256]>() };
    let returned = canary::query(token as usize, kind, buffer, |token, kind, buffer| {
        let mut returned = 0;
        let success = unsafe {
            GetTokenInformation(
                token as Raw,
                kind,
                buffer.as_mut_ptr().cast(),
                256,
                &mut returned,
            )
        };
        let code = if success == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        if success == 0 {
            return Err(diagnostics::native(
                Stage::SxsStorage,
                Numbers {
                    native_error: Some(code),
                    count: Some(kind as u32),
                    bytes: Some(returned),
                    ..Default::default()
                },
            ));
        }
        Ok(returned as usize)
    })?;
    data.length = returned;
    Ok(data)
}
fn scalar_fixed(token: Raw, kind: i32) -> Result<u32> {
    let data = fixed(token, kind)?;
    let bytes = unsafe { &*data.words.as_ptr().cast::<[u8; 256]>() };
    canary::scalar(bytes, data.length)
}
fn sid_fixed(token: Raw, kind: i32) -> Result<Vec<u8>> {
    let data = fixed(token, kind)?;
    let bytes = unsafe { &*data.words.as_ptr().cast::<[u8; 256]>() };
    canary::sid(bytes, data.words.as_ptr() as u64, data.length, kind)
}
pub(super) fn check_owner(
    token: Raw,
    expected: &[u8],
    duplicate: bool,
    strict: bool,
) -> Result<()> {
    let user = sid_fixed(token, 1)?;
    let kind = scalar_fixed(token, 8)?;
    let level = if duplicate {
        scalar_fixed(token, 9)?
    } else {
        0
    };
    let owner = sid_fixed(token, 4)?;
    super::require_owner_identity(expected, &user, &owner, kind, level, duplicate, strict)
}
struct OwnerScope<'a, F> {
    token: Raw,
    user: &'a [u8],
    body: Option<F>,
}
impl<T, F: FnOnce() -> Result<T>> canary::ScopeIo for OwnerScope<'_, F> {
    type Output = T;
    fn enter(&mut self) -> Result<bool> {
        require_host()?;
        let success = unsafe { ImpersonateLoggedOnUser(self.token) };
        let code = if success == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        if success == 0 {
            return Err(diagnostics::native(
                Stage::SxsStorage,
                Numbers {
                    native_error: Some(code),
                    ..Default::default()
                },
            ));
        }
        Ok(true)
    }
    fn effective(&mut self) -> Result<()> {
        let mut token = effective()?;
        let checked = check_owner(token.0, self.user, true, true);
        finish(checked, token.close().err().into_iter().collect())
    }
    fn body(&mut self) -> Result<T> {
        self.body
            .take()
            .ok_or_else(|| anyhow::anyhow!("canary body was consumed"))?()
    }
    fn revert(&mut self) -> Result<bool> {
        Ok(unsafe { RevertToSelf() } != 0)
    }
    fn absent(&mut self) -> Result<()> {
        require_host()
    }
    fn fatal(&mut self) -> Result<()> {
        std::process::abort()
    }
}
pub(super) fn owner<T>(body: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
    require_host()?;
    let mut primary = Handle(null_mut());
    let mut copy = Handle(null_mut());
    let mut input = None;
    let mut trusted = true;
    let result = (|| {
        input = Some(Query {
            words: vec![0; 32],
            length: 256,
        });
        primary = open(unsafe { GetCurrentProcess() })?;
        let user = sid_fixed(primary.0, 1)?;
        ensure!(
            user != [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            "SxS canary host cannot be SYSTEM"
        );
        check_owner(primary.0, &user, false, false)?;
        copy = duplicate(primary.0, true)?;
        check_owner(copy.0, &user, true, false)?;
        let input = input.as_mut().unwrap();
        let base = input.words.as_ptr() as u64;
        let buffer = unsafe { &mut *input.words.as_mut_ptr().cast::<[u8; 256]>() };
        canary::owner_input(buffer, base, &user)?;
        let success = unsafe { SetTokenInformation(copy.0, 4, input.words.as_mut_ptr().cast(), 8) };
        let code = if success == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        if success == 0 {
            return Err(diagnostics::native(
                Stage::SxsStorage,
                Numbers {
                    native_error: Some(code),
                    ..Default::default()
                },
            ));
        }
        check_owner(copy.0, &user, true, true)?;
        require_host()?;
        canary::scope(
            &mut OwnerScope {
                token: copy.0,
                user: &user,
                body: Some(|| body(&user)),
            },
            &mut trusted,
        )
    })();
    let duplicate_raw = copy.0;
    let input = std::cell::RefCell::new(input);
    canary::finish(
        result,
        trusted,
        vec![
            Box::new(|| copy.close()),
            Box::new(|| {
                if primary.0 != duplicate_raw {
                    primary.close()
                } else {
                    primary.0 = null_mut();
                    Ok(())
                }
            }),
            Box::new(|| {
                if let Some(input) = &mut *input.borrow_mut() {
                    input.words.fill(0);
                }
                Ok(())
            }),
            Box::new(|| {
                input.borrow_mut().take();
                Ok(())
            }),
        ],
    )
}
