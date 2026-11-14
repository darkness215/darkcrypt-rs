// LLD on x86_64-pc-windows-gnu will still route memcpy/memset/memmove/memcmp
// to api-ms-win-crt-* DLL imports even with -nodefaultlibs + compiler_builtins'
// mem feature present — the DLL symbols win the resolution race. Define them
// here as strong #[no_mangle] symbols so LLD binds to us and drops the ApiSet
// imports entirely.
//
// Loader is single-threaded and these are leaf calls — a plain byte loop is
// correct and fast enough. ~200 bytes of .text total.

#![allow(dead_code)]

use core::ptr;

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        ptr::write(dest.add(i), ptr::read(src.add(i)));
        i += 1;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dest as usize) < (src as usize) {
        let mut i = 0;
        while i < n {
            ptr::write(dest.add(i), ptr::read(src.add(i)));
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            ptr::write(dest.add(i), ptr::read(src.add(i)));
        }
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let b = c as u8;
    let mut i = 0;
    while i < n {
        ptr::write(dest.add(i), b);
        i += 1;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let av = ptr::read(a.add(i)) as i32;
        let bv = ptr::read(b.add(i)) as i32;
        if av != bv { return av - bv; }
        i += 1;
    }
    0
}
