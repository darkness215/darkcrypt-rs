// I/O — hash-resolved kernel32 for file read + command-line parse.
// Zero static imports beyond the ones already in native.rs.

#![allow(dead_code, non_camel_case_types)]

use core::mem;
use core::ptr;

use alloc::vec::Vec;

use crate::{hashes, native, peb};
use native::{HANDLE, PVOID};

// ---- kernel32 fn pointer types ----
pub type SleepFn            = unsafe extern "system" fn(u32);
pub type GetCommandLineAFn  = unsafe extern "system" fn() -> *const u8;
pub type CreateFileAFn      = unsafe extern "system" fn(
    *const u8, u32, u32, PVOID, u32, u32, HANDLE,
) -> HANDLE;
pub type ReadFileFn         = unsafe extern "system" fn(
    HANDLE, *mut u8, u32, *mut u32, PVOID,
) -> i32;
pub type GetFileSizeExFn    = unsafe extern "system" fn(HANDLE, *mut i64) -> i32;
pub type CloseHandleFn      = unsafe extern "system" fn(HANDLE) -> i32;

// ---- CreateFileA constants ----
pub const GENERIC_READ:        u32 = 0x80000000;
pub const FILE_SHARE_READ:     u32 = 0x00000001;
pub const OPEN_EXISTING:       u32 = 3;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
pub const INVALID_HANDLE_VALUE: isize = -1;

// ================================================================
// Sleep — hash-resolved, replaces std::thread::sleep across the loader.
// ================================================================
pub unsafe fn sleep(ms: u32) {
    if let Ok(va) = peb::resolve_by_hash(hashes::SLEEP) {
        let f: SleepFn = mem::transmute(va);
        f(ms);
    }
}

// ================================================================
// Argv parse — returns the full path pointer from GetCommandLineA, or null if
// the invocation has no argv[1]. Parses: `"argv[0]" argv[1]...` or
// `argv[0] argv[1]...`, returning a pointer into the live command-line string
// (which is NUL-terminated by Windows).
// ================================================================
pub unsafe fn argv_one() -> *const u8 {
    let cmd_va = match peb::resolve_by_hash(hashes::GET_COMMAND_LINE_A) {
        Ok(v) => v,
        Err(_) => return ptr::null(),
    };
    let get_cmd: GetCommandLineAFn = mem::transmute(cmd_va);
    let cmd = get_cmd();
    if cmd.is_null() { return ptr::null(); }

    let mut p = cmd;
    // Skip argv[0] — quoted or whitespace-terminated.
    if *p == b'"' {
        p = p.add(1);
        while *p != 0 && *p != b'"' { p = p.add(1); }
        if *p == b'"' { p = p.add(1); }
    } else {
        while *p != 0 && *p != b' ' && *p != b'\t' { p = p.add(1); }
    }
    // Skip whitespace between argv[0] and argv[1].
    while *p == b' ' || *p == b'\t' { p = p.add(1); }
    if *p == 0 { return ptr::null(); }
    p
}

// ================================================================
// read_file — open + size + read + close through hash-resolved kernel32.
// path_a must be NUL-terminated ASCII (live in GetCommandLineA's buffer).
// Returns the file contents as a fresh Vec<u8>.
// ================================================================
pub unsafe fn read_file(path_a: *const u8) -> Result<Vec<u8>, &'static str> {
    let cf_va = peb::resolve_by_hash(hashes::CREATE_FILE_A)
        .map_err(|_| "resolve CreateFileA")?;
    let rf_va = peb::resolve_by_hash(hashes::READ_FILE)
        .map_err(|_| "resolve ReadFile")?;
    let gs_va = peb::resolve_by_hash(hashes::GET_FILE_SIZE_EX)
        .map_err(|_| "resolve GetFileSizeEx")?;
    let ch_va = peb::resolve_by_hash(hashes::CLOSE_HANDLE)
        .map_err(|_| "resolve CloseHandle")?;

    let create_file: CreateFileAFn    = mem::transmute(cf_va);
    let read_file_f: ReadFileFn       = mem::transmute(rf_va);
    let get_size:    GetFileSizeExFn  = mem::transmute(gs_va);
    let close_h:     CloseHandleFn    = mem::transmute(ch_va);

    let h = create_file(
        path_a,
        GENERIC_READ,
        FILE_SHARE_READ,
        ptr::null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        ptr::null_mut(),
    );
    if h as isize == INVALID_HANDLE_VALUE || h.is_null() {
        return Err("CreateFileA failed");
    }

    let mut size_i64: i64 = 0;
    if get_size(h, &mut size_i64) == 0 || size_i64 <= 0 {
        close_h(h);
        return Err("GetFileSizeEx failed or zero-length");
    }
    let total = size_i64 as usize;

    let mut buf: Vec<u8> = Vec::with_capacity(total);
    buf.resize(total, 0);

    let mut off: usize = 0;
    while off < total {
        let chunk = core::cmp::min(total - off, 0x40_0000); // 4 MiB per ReadFile
        let mut got: u32 = 0;
        let ok = read_file_f(
            h,
            buf.as_mut_ptr().add(off),
            chunk as u32,
            &mut got,
            ptr::null_mut(),
        );
        if ok == 0 || got == 0 {
            close_h(h);
            return Err("ReadFile failed mid-stream");
        }
        off += got as usize;
    }

    close_h(h);
    Ok(buf)
}
