// Bootstrap FFI + constants. The minimum static imports to pivot
// into the Halos syscall trampoline.
//
// Everything Nt* is hash-resolved through Halos, NOT via P/Invoke.

#![allow(dead_code)]
#![allow(non_snake_case, non_camel_case_types)]

use core::ffi::c_void;

// ---- Type aliases for Windows FFI (keeping it minimal) ----
pub type HANDLE  = *mut c_void;
pub type PVOID   = *mut c_void;
pub type NTSTATUS = i32;

// ---- Allocation / protection constants ----
pub const MEM_COMMIT:  u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;
pub const MEM_RELEASE: u32 = 0x00008000;

pub const PAGE_READWRITE:        u32 = 0x04;
pub const PAGE_EXECUTE_READ:     u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// ---- Process creation ----
pub const CREATE_SUSPENDED: u32 = 0x00000004;
pub const DETACHED_PROCESS: u32 = 0x00000008;
pub const CREATE_NO_WINDOW: u32 = 0x08000000;

// ---- Exception / HWBP ----
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
pub const EXCEPTION_CONTINUE_SEARCH:    i32 = 0;
pub const STATUS_SINGLE_STEP:           u32 = 0x80000004;
pub const CONTEXT_DEBUG_REGISTERS:      u32 = 0x00100010;

// ---- x64 CONTEXT struct byte offsets (sizeof = 0x4d0) ----
pub const CTX_SIZE:          usize = 0x4D0;
pub const CTX_CONTEXT_FLAGS: usize = 0x30;
pub const CTX_EFLAGS:        usize = 0x44;
pub const CTX_DR0:           usize = 0x48;
pub const CTX_DR1:           usize = 0x50;
pub const CTX_DR2:           usize = 0x58;
pub const CTX_DR3:           usize = 0x60;
pub const CTX_DR6:           usize = 0x68;
pub const CTX_DR7:           usize = 0x70;
pub const CTX_RAX:           usize = 0x78;
pub const CTX_RSP:           usize = 0x98;
pub const CTX_RIP:           usize = 0xF8;
pub const EFLAGS_RF:         u32   = 0x00010000;

// ---- SpecialUserAPC flag for NtQueueApcThreadEx (Win10 1809+) ----
pub const QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC: usize = 0x1;

// ---- Pseudohandles ----
pub const CURRENT_PROCESS: HANDLE = -1isize as HANDLE;
pub const CURRENT_THREAD:  HANDLE = -2isize as HANDLE;

// ---- STARTUPINFO flags ----
pub const STARTF_USESHOWWINDOW: u32 = 0x00000001;
pub const SW_HIDE:              u16 = 0;

// ---- Process spawn structs ----
#[repr(C)]
#[derive(Default)]
pub struct STARTUPINFOA {
    pub cb: u32,
    pub lpReserved: *mut u8,
    pub lpDesktop: *mut u8,
    pub lpTitle: *mut u8,
    pub dwX: u32,
    pub dwY: u32,
    pub dwXSize: u32,
    pub dwYSize: u32,
    pub dwXCountChars: u32,
    pub dwYCountChars: u32,
    pub dwFillAttribute: u32,
    pub dwFlags: u32,
    pub wShowWindow: u16,
    pub cbReserved2: u16,
    pub lpReserved2: *mut u8,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE,
}

#[repr(C)]
#[derive(Default)]
pub struct PROCESS_INFORMATION {
    pub hProcess: HANDLE,
    pub hThread: HANDLE,
    pub dwProcessId: u32,
    pub dwThreadId: u32,
}

// Rust requires Default for raw pointers to be defined manually.
// `*mut c_void` and `*mut u8` don't impl Default by default.
// But the #[derive(Default)] above expects it... use a custom impl below instead.
// Actually easier: zero-init the struct with core::mem::zeroed() at call site.

// ---- NTSTATUS helper ----
#[inline]
pub fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

// ================================================================
// Bootstrap FFI — the irreducible minimum.
// ================================================================

#[link(name = "kernel32")]
extern "system" {
    pub fn GetModuleHandleW(lpModuleName: *const u16) -> PVOID;
    pub fn LoadLibraryW(lpLibFileName: *const u16) -> PVOID;
    pub fn VirtualAlloc(
        lpAddress: PVOID,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> PVOID;
    pub fn VirtualFree(lpAddress: PVOID, dwSize: usize, dwFreeType: u32) -> i32;

    // heap-backed #[global_allocator] (src/alloc_impl.rs).
    pub fn GetProcessHeap() -> PVOID;
    pub fn HeapAlloc(hHeap: PVOID, dwFlags: u32, dwBytes: usize) -> PVOID;
    pub fn HeapFree(hHeap: PVOID, dwFlags: u32, lpMem: PVOID) -> i32;
    pub fn HeapReAlloc(hHeap: PVOID, dwFlags: u32, lpMem: PVOID, dwBytes: usize) -> PVOID;

    // process termination for #[panic_handler] and mainCRTStartup exit.
    pub fn ExitProcess(uExitCode: u32) -> !;
}
