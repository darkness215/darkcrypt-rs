// Persistent RWX syscall trampoline (Halos Gate).
//
// One VirtualAlloc'd RWX page, 11-byte stub copied in once, SSN patched
// per-call under HALOS_LOCK. Typed `extern "system" fn` pointers
// transmuted from the stub address at each call site — zero reflection
// cost (unlike C#'s GetDelegateForFunctionPointer).

#![allow(dead_code)]

use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::native;
use crate::sync::SpinLock;

static STUB_ADDR: AtomicUsize = AtomicUsize::new(0);
pub static HALOS_LOCK: SpinLock<()> = SpinLock::new(());

// mov r10, rcx ; mov eax, SSN ; syscall ; ret
// bytes[4..=5] are the SSN low/high patched per call (upper 2 stay 0).
const STUB_TEMPLATE: [u8; 11] = [
    0x4c, 0x8b, 0xd1,
    0xb8, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0xc3,
];

pub fn init() -> Result<(), &'static str> {
    if STUB_ADDR.load(Ordering::SeqCst) != 0 { return Ok(()); }
    unsafe {
        let page = native::VirtualAlloc(
            ptr::null_mut(),
            0x1000,
            native::MEM_COMMIT | native::MEM_RESERVE,
            native::PAGE_EXECUTE_READWRITE,
        );
        if page.is_null() {
            return Err("VirtualAlloc returned null");
        }
        ptr::copy_nonoverlapping(STUB_TEMPLATE.as_ptr(), page as *mut u8, STUB_TEMPLATE.len());
        STUB_ADDR.store(page as usize, Ordering::SeqCst);
    }
    Ok(())
}

pub fn stub_addr() -> usize {
    STUB_ADDR.load(Ordering::SeqCst)
}

// Patch the SSN bytes. Caller MUST hold HALOS_LOCK.
pub unsafe fn patch_ssn(ssn: u32) {
    let addr = stub_addr() as *mut u8;
    ptr::write(addr.add(4), (ssn & 0xff) as u8);
    ptr::write(addr.add(5), ((ssn >> 8) & 0xff) as u8);
}
