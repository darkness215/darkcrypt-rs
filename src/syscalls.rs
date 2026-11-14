// Typed Nt* function pointers resolved through the Halos trampoline.

#![allow(dead_code, non_camel_case_types)]

use core::mem;

use crate::{halos, hashes, native, peb};
use native::{HANDLE, PVOID, NTSTATUS};

// ================================================================
// NtAllocateVirtualMemory
// ================================================================
pub type NtAlloc_t = unsafe extern "system" fn(
    HANDLE, *mut PVOID, usize, *mut usize, u32, u32,
) -> NTSTATUS;

pub unsafe fn vm_alloc(
    process: HANDLE,
    base: &mut PVOID,
    zero_bits: usize,
    size: &mut usize,
    alloc_type: u32,
    protect: u32,
) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::VM_ALLOC));
    let f: NtAlloc_t = mem::transmute(halos::stub_addr());
    f(process, base as *mut PVOID, zero_bits, size as *mut usize, alloc_type, protect)
}

// ================================================================
// NtFreeVirtualMemory
// ================================================================
pub type NtFree_t = unsafe extern "system" fn(
    HANDLE, *mut PVOID, *mut usize, u32,
) -> NTSTATUS;

pub unsafe fn vm_free(
    process: HANDLE,
    base: &mut PVOID,
    size: &mut usize,
    free_type: u32,
) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::VM_FREE));
    let f: NtFree_t = mem::transmute(halos::stub_addr());
    f(process, base as *mut PVOID, size as *mut usize, free_type)
}

// ================================================================
// NtClose
// ================================================================
pub type NtClose_t = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

pub unsafe fn h_close(handle: HANDLE) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::NT_CLOSE));
    let f: NtClose_t = mem::transmute(halos::stub_addr());
    f(handle)
}

// ================================================================
// NtWriteVirtualMemory
// ================================================================
pub type NtWrite_t = unsafe extern "system" fn(
    HANDLE, PVOID, *const u8, usize, *mut usize,
) -> NTSTATUS;

pub unsafe fn vm_write(
    process: HANDLE,
    base: PVOID,
    buffer: *const u8,
    size: usize,
    written: &mut usize,
) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::VM_WRITE));
    let f: NtWrite_t = mem::transmute(halos::stub_addr());
    f(process, base, buffer, size, written as *mut usize)
}

// ================================================================
// NtProtectVirtualMemory
// ================================================================
pub type NtProtect_t = unsafe extern "system" fn(
    HANDLE, *mut PVOID, *mut usize, u32, *mut u32,
) -> NTSTATUS;

pub unsafe fn vm_protect(
    process: HANDLE,
    base: &mut PVOID,
    size: &mut usize,
    new_protect: u32,
    old_protect: &mut u32,
) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::VM_PROTECT));
    let f: NtProtect_t = mem::transmute(halos::stub_addr());
    f(process, base as *mut PVOID, size as *mut usize, new_protect, old_protect as *mut u32)
}

// ================================================================
// NtQueueApcThread
// ================================================================
pub type NtQueueApc_t = unsafe extern "system" fn(
    HANDLE, PVOID, PVOID, PVOID, PVOID,
) -> NTSTATUS;

pub unsafe fn apc_queue(
    thread: HANDLE,
    routine: PVOID,
    arg1: PVOID,
    arg2: PVOID,
    arg3: PVOID,
) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::APC_QUEUE));
    let f: NtQueueApc_t = mem::transmute(halos::stub_addr());
    f(thread, routine, arg1, arg2, arg3)
}

// ================================================================
// NtGetContextThread
// ================================================================
pub type NtCtxGet_t = unsafe extern "system" fn(HANDLE, PVOID) -> NTSTATUS;
pub unsafe fn ctx_get(thread: HANDLE, ctx: PVOID) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::CTX_GET));
    let f: NtCtxGet_t = mem::transmute(halos::stub_addr());
    f(thread, ctx)
}

// ================================================================
// NtSetContextThread
// ================================================================
pub type NtCtxSet_t = unsafe extern "system" fn(HANDLE, PVOID) -> NTSTATUS;
pub unsafe fn ctx_set(thread: HANDLE, ctx: PVOID) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::CTX_SET));
    let f: NtCtxSet_t = mem::transmute(halos::stub_addr());
    f(thread, ctx)
}

// ================================================================
// NtSuspendThread
// ================================================================
pub type NtThrSuspend_t = unsafe extern "system" fn(HANDLE, *mut u32) -> NTSTATUS;
pub unsafe fn thr_suspend(thread: HANDLE, prev: &mut u32) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::THR_SUSPEND));
    let f: NtThrSuspend_t = mem::transmute(halos::stub_addr());
    f(thread, prev as *mut u32)
}

// ================================================================
// NtResumeThread
// ================================================================
pub type NtThrResume_t = unsafe extern "system" fn(HANDLE, *mut u32) -> NTSTATUS;
pub unsafe fn thr_resume(thread: HANDLE, prev: &mut u32) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::THR_RESUME));
    let f: NtThrResume_t = mem::transmute(halos::stub_addr());
    f(thread, prev as *mut u32)
}

// ================================================================
// NtReadVirtualMemory
// ================================================================
pub type NtVmRead_t = unsafe extern "system" fn(
    HANDLE, PVOID, *mut u8, usize, *mut usize,
) -> NTSTATUS;
pub unsafe fn vm_read(
    process: HANDLE, base: PVOID, buffer: *mut u8, size: usize, read: &mut usize,
) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::VM_READ));
    let f: NtVmRead_t = mem::transmute(halos::stub_addr());
    f(process, base, buffer, size, read as *mut usize)
}

// ================================================================
// NtQueryInformationProcess
// ================================================================
pub type NtProcInfo_t = unsafe extern "system" fn(
    HANDLE, i32, PVOID, u32, *mut u32,
) -> NTSTATUS;
pub unsafe fn proc_info(
    process: HANDLE, class: i32, info: PVOID, info_len: u32, ret_len: &mut u32,
) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::PROC_INFO));
    let f: NtProcInfo_t = mem::transmute(halos::stub_addr());
    f(process, class, info, info_len, ret_len as *mut u32)
}

// ================================================================
// NtQueueApcThreadEx  (SpecialUserAPC flag=0x1)
// ================================================================
pub type NtApcQueueEx_t = unsafe extern "system" fn(
    HANDLE, usize, PVOID, PVOID, PVOID, PVOID,
) -> NTSTATUS;
pub unsafe fn apc_queue_ex(
    thread: HANDLE, reserve_or_flag: usize, routine: PVOID,
    arg1: PVOID, arg2: PVOID, arg3: PVOID,
) -> NTSTATUS {
    let _lock = halos::HALOS_LOCK.lock();
    halos::patch_ssn(peb::ssn(hashes::APC_QUEUE_EX));
    let f: NtApcQueueEx_t = mem::transmute(halos::stub_addr());
    f(thread, reserve_or_flag, routine, arg1, arg2, arg3)
}
