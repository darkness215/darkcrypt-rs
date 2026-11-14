// AES-256-CBC decrypt + HMAC-SHA256 verify via pure-Rust crates.
// Matches darkcrypt C's `cng.c` + `cng_hmac.c` wire format exactly.
// Zero `bcrypt.dll` import — the RustCrypto family handles everything.
//
// DCP1 payload layout:
//   [0..4)    magic "DCP1"
//   [4..6)    version (LE uint16, currently 1)
//   [6..22)   IV (16 bytes)
//   [22..N)   ciphertext (CBC + PKCS#7, multiple of 16 bytes)
//   [N..N+32) HMAC-SHA256(macKey, ciphertext)

#![allow(dead_code)]

use alloc::vec::Vec;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256   = Hmac<Sha256>;

pub const HDR_LEN:     usize = 6;    // "DCP1" + LE u16 version
pub const IV_LEN:      usize = 16;
pub const HMAC_LEN:    usize = 32;
pub const CT_OFFSET:   usize = HDR_LEN + IV_LEN;
pub const AES_KEY_LEN: usize = 32;
pub const MAC_KEY_LEN: usize = 32;

pub fn verify_and_decrypt_dcp1(
    blob: &[u8],
    aes_key: &[u8; AES_KEY_LEN],
    mac_key: &[u8; MAC_KEY_LEN],
) -> Result<Vec<u8>, &'static str> {
    let min_len = HDR_LEN + IV_LEN + IV_LEN + HMAC_LEN;
    if blob.len() < min_len { return Err("payload too short"); }

    if &blob[0..4] != b"DCP1" { return Err("DCP1 magic mismatch"); }
    let ver = u16::from_le_bytes([blob[4], blob[5]]);
    if ver != 1 { return Err("unsupported DCP1 version"); }

    let tag_off = blob.len() - HMAC_LEN;
    let ct_len  = tag_off - CT_OFFSET;
    if ct_len == 0 || ct_len % IV_LEN != 0 { return Err("bad ciphertext length"); }

    let ct  = &blob[CT_OFFSET..tag_off];
    let tag = &blob[tag_off..];

    // HMAC-SHA256 verify (constant-time via subtle).
    let mut mac = HmacSha256::new_from_slice(mac_key).map_err(|_| "mac key size")?;
    mac.update(ct);
    mac.verify_slice(tag).map_err(|_| "HMAC verify failed")?;

    // AES-256-CBC decrypt + PKCS#7 unpad.
    let iv = &blob[HDR_LEN..CT_OFFSET];
    let mut buf = ct.to_vec();
    let pt = Aes256CbcDec::new(aes_key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| "decrypt failed")?;

    Ok(pt.to_vec())
}
