//! The `riscv64` link proof (built with `--features bin`): a `#![no_std]` /
//! `#![no_main]` confined program that links `no_std` Wasmtime + the Pulley
//! interpreter + [`crate::platform`] + `lantern-abi`'s `rt`, then runs the
//! embedded Pulley component and reports the result.
//!
//! It **builds, links, and now loads** for `riscv64gc-unknown-none-elf` —
//! see `lantern-boot/src/wasm_probe_demo/loader.rs`. Loadable at all only
//! after shrinking [`crate::platform`]'s arena from an initial 64 MiB guess
//! to 256 KiB (`platform.rs`'s own doc): the 64 MiB version alone would have
//! needed ~32 of `lantern-kernel`'s only 16 total `MAX_FRAMES` — categorically
//! unloadable, not just large, discovered while scoping the RFC-0018
//! integration demo. This binary's own heap (below) needed the same
//! treatment.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use lantern_runtime_riscv64_probe::run_embedded_answer;

lantern_abi::entry!(run);

/// Slots the loader is expected to place `Notification` capabilities in, so
/// the result is observable from S-mode as a distinguishable outcome — same
/// convention every `lantern-boot` demo's `SUCCESS_CPTR`/`FAILURE_CPTR` use,
/// not the notification's own (loader-fixed) badge standing in for an
/// application-computed result.
const SUCCESS_CPTR: usize = 4;
const FAILURE_CPTR: usize = 5;

/// Heap for `lantern-abi`'s bump allocator (Wasmtime's own `Vec`/`Box`
/// bookkeeping for `Store`/`Linker`/`Instance` state) — distinct from
/// `platform.rs`'s Wasm-linear-memory arena. Must equal
/// `lantern_boot::launch::HEAP_VADDR` — this binary has no dependency on that
/// crate, so the value is duplicated here, the same convention
/// `keystore-service`'s `FRAME_VADDR` already established for a shared
/// constant across the loader/program boundary.
const HEAP_BASE: usize = 0x8620_0000;
/// One `FrameMega` (2 MiB) — empirically enough for this trivial component's
/// `Store`/`Linker`/`Instance` bookkeeping (`lantern-boot/src/wasm_probe_demo/
/// loader.rs`'s `heap_megapages: 1`); a real, non-trivial guest component's
/// own working set is a separate, later question.
const HEAP_LEN: usize = 0x20_0000;

fn run(_arg0: usize) -> ! {
    // SAFETY: the loader mapped `HEAP_BASE..+HEAP_LEN` read/write into this
    // program's own VSpace before its first instruction ran
    // (`ProgramSpec::heap_megapages`); one-time setup before the first
    // allocation.
    unsafe { lantern_abi::rt::init_heap(HEAP_BASE, HEAP_LEN) };
    lantern_abi::rt::report_panics_via(FAILURE_CPTR);

    let succeeded = matches!(run_embedded_answer(), Ok(42));
    let _ = lantern_abi::sys::signal(if succeeded { SUCCESS_CPTR } else { FAILURE_CPTR });

    loop {
        core::hint::spin_loop();
    }
}
