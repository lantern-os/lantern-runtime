//! **RFC-0018 Part 3 / [ADR-0023](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0023-wasmtime-no-std-pulley-hosting.md)
//! groundwork.** Proves the confined-runtime stack:
//!
//! - `wasmtime` 48 built `no_std` (`default-features = false`) with the
//!   **Pulley** interpreter and `custom-virtual-memory` /
//!   `custom-sync-primitives` compiles for `riscv64gc-unknown-none-elf` and
//!   links into a `#![no_std]` / `#![no_main]` binary (`src/main.rs`, built with
//!   `--features bin`);
//! - Wasmtime's `sys/custom` C API, implemented in [`platform`] over a `.bss`
//!   bump arena + a static TLS pointer + no-op locks, is enough to deserialize,
//!   instantiate, and run a Pulley `.cwasm` component.
//!
//! [`run_embedded_answer`] does the second part and is exercised by this
//! crate's own `cargo test` — which, having no `std` feature on `wasmtime`,
//! builds the `custom` platform layer and so runs the component **through
//! [`platform`]'s symbols**, the same code path the `riscv64` build takes.
//!
//! What this is not: the confined runtime itself (no host imports, no
//! `IpcKeystore`/`IpcFilesystem`, no launcher integration — the arena is a
//! `static`, not `Frame`-backed). Those are the rest of Part 3 and Parts 1–2.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod platform;

use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

/// A Pulley `.cwasm` for the component `(func (export "run") (result s32) → 42)`,
/// precompiled offline for `pulley64` (the compiler role, ADR-0023). Embedded so
/// the test/binary need no filesystem.
pub const ANSWER_CWASM: &[u8] = include_bytes!("../assets/answer.pulley.cwasm");

/// The runtime-role `Config`: Component Model + `pulley64`. Must match the target
/// the `.cwasm` was compiled for or `deserialize` rejects it.
pub fn pulley_config() -> Config {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.target("pulley64").expect("pulley64 is a valid target");
    config
}

/// Deserialize [`ANSWER_CWASM`], instantiate it, call `run`, return the result
/// (should be `42`). Every allocation and every `mmap` this drives goes through
/// [`platform`] when built without `wasmtime/std`.
pub fn run_embedded_answer() -> wasmtime::Result<i32> {
    let engine = Engine::new(&pulley_config())?;
    // SAFETY: `ANSWER_CWASM` is a build-time constant compiled by our own
    // trusted compiler-role engine — exactly the "trusted bytes" contract
    // `Component::deserialize` requires.
    let component = unsafe { Component::deserialize(&engine, ANSWER_CWASM)? };
    let mut store = Store::new(&engine, ());
    let linker = Linker::new(&engine);
    let instance = linker.instantiate(&mut store, &component)?;
    let run = instance.get_typed_func::<(), (i32,)>(&mut store, "run")?;
    Ok(run.call(&mut store, ())?.0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn pulley_component_runs_through_the_lanternos_platform_shim() {
        assert_eq!(super::run_embedded_answer().unwrap(), 42);
    }
}
