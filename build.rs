// emit linker args via `cargo:rustc-link-arg=` so they compose
// additively with any RUSTFLAGS env the caller might export.
//
// Rationale: Cargo's rustflags precedence is RUSTFLAGS env > target.<triple>.rustflags
// > build.rustflags, and the higher-priority source *replaces* (not merges with)
// the lower ones. If a CI step or shell exports RUSTFLAGS for any reason, the
// entire [target.*].rustflags block in .cargo/config.toml gets discarded —
// silently, no warning — and we end up linking the full mingw CRT. Moving the
// link args here guarantees they ship regardless of how rustflags are set.

fn main() {
    // Only emit on windows-gnu (we don't build other targets, but belt-and-braces).
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("windows-gnu") {
        return;
    }

    let link_args = [
        // Strip mingw CRT + default-lib chain.
        "-nostartfiles",
        "-nodefaultlibs",

        // Our entry — PE AddressOfEntryPoint points here.
        "-Wl,--entry=mainCRTStartup",

        // Only kernel32 — no msvcrt, no api-ms-win-crt-*, no bcryptprimitives.
        "-lkernel32",

        // Link-time hygiene.
        "-Wl,--gc-sections",
        "-Wl,--no-insert-timestamp",
        "-Wl,-s",

        // PE hardening — lost with -nodefaultlibs, re-set explicitly.
        "-Wl,--nxcompat",
        "-Wl,--dynamicbase",
    ];

    for arg in link_args {
        println!("cargo:rustc-link-arg={}", arg);
    }
}
