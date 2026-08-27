//! `lantern-runtime` — the confined Wasm execution environment
//! ([RFC-0013](../https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0013-wasm-engine-selection-and-aot-strategy.md)/
//! [ADR-0017](../https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0017-wasm-engine-selection-and-aot-strategy.md),
//! building on [ADR-0003](../https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0003-wasm-as-portable-app-abi.md)).
//!
//! Two roles, deliberately never linked into the same build:
//!
//! - [`verified`] — the **runtime role**: what actually runs inside a confined
//!   per-component host process. Loads only a `.cwasm` artifact whose Ed25519 signature
//!   ([`lantern_crypto::signing`], RFC-0007's ratified primitive) it has already checked,
//!   then calls Wasmtime's `Component::deserialize` — documented by Wasmtime as unsound on
//!   untrusted input, which is exactly why the signature check comes first. This is the
//!   only role built by default: this crate's default feature set excludes
//!   `cranelift`/`winch` entirely, so `Component::new`/`Engine::precompile_component`
//!   (Wasmtime's compile-from-source API) don't exist in this build at all — genuinely
//!   absent from the symbol table, not merely unused.
//! - [`compiler`] (behind the `compiler` Cargo feature) — the offline **compiler role**:
//!   compiles a `.wasm`/`.wat` component ahead-of-time via Cranelift and signs the result.
//!   Runs at packaging/install time, never inside a running confined app's own process.
//!
//! What this crate does not yet do (RFC-0013's explicit deferrals): capability-gated WASI
//! host bindings — no host functions are wired up at all yet, so today's components can
//! only export, never import — resource-accounting/fuel metering, and running under
//! anything but a native `std` host target. Bare-metal `riscv64` hosting needs Wasmtime's
//! custom-platform embedding support, real porting work RFC-0013 flagged but did not do.

#[cfg(feature = "compiler")]
pub mod compiler;
pub mod verified;

pub use verified::{load_verified_component, runtime_engine, LoadError};
