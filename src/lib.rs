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
//! **Two build roles, matching Wasmtime's own two backing modes (`Cargo.toml`'s
//! `std`/`confined` features, RFC-0018 Part 3):** the `std` host role (default — native
//! OS, what every test and `lantern-example-signer`'s runner use), and the `confined`
//! `riscv64` role (`no_std`, Wasmtime's custom-platform hooks in [`platform`] instead of
//! a real OS — folded in from `lantern-runtime/riscv64-probe`'s own groundwork once
//! [`host::IpcKeystore`]/[`host::IpcFilesystem`] gave this crate a reason to actually run
//! confined).
//!
//! **Fuel metering is on unconditionally** ([`verified::runtime_engine`]'s `Config`,
//! [`DEFAULT_FUEL`]) — RFC-0018 Part 3's chosen v0 mechanism for preempting a runaway
//! component, deterministic and Pulley-native (no timer needed; confirmed empirically, not
//! assumed — a 2-billion-iteration loop against a tiny fuel budget traps cleanly). Because
//! it's unconditional, **every caller must call `Store::set_fuel` before running any guest
//! code** — Wasmtime does not default a budget once fuel metering is on, so a caller that
//! forgets gets an immediate "out of fuel" trap on the very first metered instruction, not
//! silent unlimited execution. Every caller in this crate's own tests (and `compiler.rs`'s
//! round-trip test) does this now; an out-of-tree host embedder (`lantern-example-signer`'s
//! runner, pinned to an older `lantern-runtime` commit) will need the same one-line change
//! before its next `lantern-runtime` bump.
//!
//! **`confined-probe-guest`** (a sibling crate, not part of this workspace's own build) is
//! RFC-0018's first real (non-trivial) confined guest component — genuine Rust, compiled
//! via `wasm32-wasip2`/`wit-bindgen`, precompiled to `pulley64` by this crate's own
//! `compiler` role, importing the real resource-scoped `keystore` interface. Proven here
//! (`host::tests::through_wasmtime::confined_probe_guest_signs_through_a_real_keystore`)
//! against a real, `Broker`-granted in-process `Keystore` — the wiring shape (component
//! instantiation, a resource-scoped grant, a real `sign` call through the generated `Host`
//! trait) is what's new, not the transport; [`host::IpcKeystore`] over a real `Channel`
//! still needs an actual confined `riscv64` process and `keystore-service` to prove end to
//! end, not a host test.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "compiler")]
pub mod compiler;
pub mod host;
#[cfg(all(target_arch = "riscv64", feature = "confined"))]
pub mod platform;
pub mod verified;

pub use host::{
    build_linker, FilesystemService, GrantManifest, HostCapability, HostFile,
    InProcessFilesystem, IpcFilesystem, IpcKeystore, KeystoreService, MonotonicClock, RuntimeState,
};
pub use verified::{
    deserialize_trusted_component, load_verified_component, runtime_engine, LoadError, DEFAULT_FUEL,
};
