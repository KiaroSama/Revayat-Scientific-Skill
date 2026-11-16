//! Real Windows x64 compiler stack probe. Every crossed 4KiB page is read before allocation.
//! This is the __chkstk ABI, not an exception handler or an omitted/disabled stack check.
//!
//! RAX is the requested allocation; the caller's pre-call RSP is the high end.
//! Preserve RAX/RCX and RSP, touch each descending page and the final remainder.
//! Each volatile push has its own 8-byte unwind allocation, including the partial
//! prologue after the first push, so exceptions still find the real return address.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
core::arch::global_asm!(
    ".text",
    ".globl __chkstk",
    ".def __chkstk; .scl 2; .type 32; .endef",
    ".seh_proc __chkstk",
    "__chkstk:",
    "push rcx",
    ".seh_stackalloc 8",
    "push rax",
    ".seh_stackalloc 8",
    ".seh_endprologue",
    "lea rcx, [rsp + 24]",
    "cmp rax, 4096",
    "jb 3f",
    "2:",
    "sub rcx, 4096",
    "test dword ptr [rcx], eax",
    "sub rax, 4096",
    "cmp rax, 4096",
    "jae 2b",
    "3:",
    "sub rcx, rax",
    "test dword ptr [rcx], eax",
    "pop rax",
    "pop rcx",
    "ret",
    ".seh_endproc",
);
