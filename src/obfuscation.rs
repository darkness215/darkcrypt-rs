// XOR string obfuscation primitives. Direct port of
// darkcrypt/src/obfuscation.h and darkcrypt-cs/src/Obfuscation.cs.

#![allow(dead_code)]

use alloc::vec::Vec;

/// XOR-decode an ASCII byte buffer with a rolling key.
/// Returns a new Vec<u8> with a trailing 0 byte (NUL-terminated).
pub fn xor_dec_mb(enc: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(enc.len() + 1);
    for (i, &b) in enc.iter().enumerate() {
        out.push(b ^ key[i % key.len()]);
    }
    out.push(0);
    out
}

/// XOR-decode a UTF-16LE wide-char byte buffer with a rolling key.
/// Returns a Vec<u16> with a trailing 0 (NUL-terminated wide-C-string).
pub fn xor_dec_w_mb(enc: &[u8], key: &[u8]) -> Vec<u16> {
    let nchars = enc.len() / 2;
    let mut out = Vec::with_capacity(nchars + 1);
    for i in 0..nchars {
        let lo = enc[i * 2]     ^ key[(i * 2)     % key.len()];
        let hi = enc[i * 2 + 1] ^ key[(i * 2 + 1) % key.len()];
        out.push((lo as u16) | ((hi as u16) << 8));
    }
    out.push(0);
    out
}

/// Securely zero a slice via volatile writes. Prevents the optimizer from
/// eliding the clear.
pub fn secure_zero_u8(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b as *mut u8, 0) };
    }
}

pub fn secure_zero_u16(buf: &mut [u16]) {
    for w in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(w as *mut u16, 0) };
    }
}
