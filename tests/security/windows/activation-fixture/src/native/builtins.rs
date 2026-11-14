//! Genuine compiler memory helpers; Windows x64 leaf code avoids core debug-precondition pulls.
//! Other hosts retain the original portable C ABI and volatile-loop implementation.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows_x64 {
    use core::ffi::c_void;

    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memcpy(
        _destination: *mut c_void,
        _source: *const c_void,
        _count: usize,
    ) -> *mut c_void {
        core::arch::naked_asm!(
            "mov rax, rcx",
            "test r8, r8",
            "jz 3f",
            "2:",
            "mov r9b, byte ptr [rdx]",
            "mov byte ptr [rcx], r9b",
            "inc rcx",
            "inc rdx",
            "dec r8",
            "jnz 2b",
            "3:",
            "ret",
        );
    }
    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memset(
        _destination: *mut c_void,
        _value: i32,
        _count: usize,
    ) -> *mut c_void {
        core::arch::naked_asm!(
            "mov rax, rcx",
            "test r8, r8",
            "jz 3f",
            "2:",
            "mov byte ptr [rcx], dl",
            "inc rcx",
            "dec r8",
            "jnz 2b",
            "3:",
            "ret",
        );
    }
    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memmove(
        _destination: *mut c_void,
        _source: *const c_void,
        _count: usize,
    ) -> *mut c_void {
        core::arch::naked_asm!(
            "mov rax, rcx",
            "test r8, r8",
            "jz 3f",
            "cmp rcx, rdx",
            "jbe memcpy",
            "2:",
            "mov r9b, byte ptr [rdx + r8 - 1]",
            "mov byte ptr [rcx + r8 - 1], r9b",
            "dec r8",
            "jnz 2b",
            "3:",
            "ret",
        );
    }
    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memcmp(
        _first: *const c_void,
        _second: *const c_void,
        _count: usize,
    ) -> i32 {
        core::arch::naked_asm!(
            "xor eax, eax",
            "test r8, r8",
            "jz 3f",
            "2:",
            "movzx r9d, byte ptr [rcx]",
            "movzx r10d, byte ptr [rdx]",
            "cmp r9d, r10d",
            "jne 4f",
            "inc rcx",
            "inc rdx",
            "dec r8",
            "jnz 2b",
            "3:",
            "ret",
            "4:",
            "mov eax, r9d",
            "sub eax, r10d",
            "ret",
        );
    }
    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bcmp(
        _first: *const c_void,
        _second: *const c_void,
        _count: usize,
    ) -> i32 {
        core::arch::naked_asm!("jmp memcmp");
    }
}
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
mod portable {
    use core::ffi::c_void;
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memcpy(
        destination: *mut c_void,
        source: *const c_void,
        count: usize,
    ) -> *mut c_void {
        let destination = destination.cast::<u8>();
        let source = source.cast::<u8>();
        for index in 0..count {
            unsafe {
                destination
                    .add(index)
                    .write_volatile(source.add(index).read_volatile())
            };
        }
        destination.cast()
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memset(
        destination: *mut c_void,
        value: i32,
        count: usize,
    ) -> *mut c_void {
        let destination = destination.cast::<u8>();
        for index in 0..count {
            unsafe { destination.add(index).write_volatile(value as u8) };
        }
        destination.cast()
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memmove(
        destination: *mut c_void,
        source: *const c_void,
        count: usize,
    ) -> *mut c_void {
        if destination as usize <= source as usize {
            unsafe { memcpy(destination, source, count) };
        } else {
            for index in (0..count).rev() {
                unsafe {
                    destination
                        .cast::<u8>()
                        .add(index)
                        .write_volatile(source.cast::<u8>().add(index).read_volatile())
                };
            }
        }
        destination
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memcmp(
        first: *const c_void,
        second: *const c_void,
        count: usize,
    ) -> i32 {
        let first = first.cast::<u8>();
        let second = second.cast::<u8>();
        for index in 0..count {
            let (first, second) = unsafe {
                (
                    first.add(index).read_volatile(),
                    second.add(index).read_volatile(),
                )
            };
            if first != second {
                return i32::from(first) - i32::from(second);
            }
        }
        0
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bcmp(
        first: *const c_void,
        second: *const c_void,
        count: usize,
    ) -> i32 {
        unsafe { memcmp(first, second, count) }
    }
}
