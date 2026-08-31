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
//! The capability-gated host bindings
//! ([RFC-0014](../https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0014-wit-handle-capability-mapping.md)/
//! [ADR-0018](../https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0018-wit-handle-capability-mapping.md),
//! [RFC-0016](../https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0016-filesystem-wit-interface.md)/
//! [ADR-0019](../https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0019-filesystem-wit-interface.md)) live in
//! [`host`]: the WIT-handle ⇄ capability mapping, its interfaces (`lantern:host/keystore`
//! and `lantern:host/filesystem` resource-scoped, `monotonic-clock` link-scoped), and the
//! link-or-refuse [`host::build_linker`]. Still custom, not `wasmtime-wasi` (ADR-0017).
//!
//! What this crate does not yet do (RFC-0013's explicit deferrals):
//! resource-accounting/fuel metering, and running under anything but a native `std` host
//! target. Bare-metal `riscv64` hosting needs Wasmtime's custom-platform embedding
//! support, real porting work RFC-0013 flagged but did not do.

#[cfg(feature = "compiler")]
pub mod compiler;
pub mod host;
pub mod verified;

pub use host::{
    build_linker, FilesystemService, GrantManifest, HostCapability, HostFile,
    InProcessFilesystem, KeystoreService, MonotonicClock, RuntimeState,
};
pub use verified::{
    deserialize_trusted_component, load_verified_component, runtime_engine, LoadError,
};
