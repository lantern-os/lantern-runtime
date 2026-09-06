//! The `riscv64` link proof (built with `--features bin`): a `#![no_std]` /
//! `#![no_main]` confined program that links `no_std` Wasmtime + the Pulley
//! interpreter + [`crate::platform`] + `lantern-abi`'s `rt`, then runs the
//! embedded Pulley component and reports the result.
//!
//! It **builds and links** for `riscv64gc-unknown-none-elf` today. It cannot be
//! loaded by `lantern-boot`'s current one-megapage-per-segment loader (the
//! image plus its 64 MiB `.bss` arena is far larger than that) — running it
//! under QEMU is gated on the launcher work (RFC-0018 Part 1 / DTB memory
//! discovery). Until then the execution proof is this crate's host `cargo test`,
//! which drives the same Wasmtime `custom` platform path.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use lantern_runtime_riscv64_probe::run_embedded_answer;

lantern_abi::entry!(run);

/// Slot the launcher is expected to place a `Notification` capability in, so the
/// result is observable from S-mode.
const RESULT_NOTIFICATION: usize = 4;

/// Heap for `lantern-abi`'s bump allocator (Wasmtime's `Vec`/`Box`/`String`).
/// Distinct from `platform.rs`'s Wasm-memory arena.
const HEAP_BASE: usize = 0x9000_0000;
const HEAP_LEN: usize = 0x0200_0000; // 32 MiB

fn run(_arg0: usize) -> ! {
    // SAFETY: the launcher is expected to have mapped HEAP_BASE..+HEAP_LEN RW
    // for this program; one-time setup before the first allocation.
    unsafe { lantern_abi::rt::init_heap(HEAP_BASE, HEAP_LEN) };
    lantern_abi::rt::report_panics_via(RESULT_NOTIFICATION);

    // Signal badge = the component's result on success, or 0xERR on failure.
    let badge = match run_embedded_answer() {
        Ok(42) => 42,
        Ok(_other) => 0xE1,
        Err(_) => 0xE2,
    };
    let _ = lantern_abi::sys::signal(RESULT_NOTIFICATION);
    let _ = badge;

    loop {
        core::hint::spin_loop();
    }
}
