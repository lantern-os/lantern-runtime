# lantern-runtime — Status

**Phase:** 2 (Capability runtime & first services) — open per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md). First prototype code now exists — see "Done".

## Done
- Service framework + WASM runtime split documented and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Capability-backed WASI approach fixed ([ADR-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0003-wasm-as-portable-app-abi.md)).
- Threat model drafted and reviewed.
- ~~Select a Wasm engine and AOT strategy.~~ Resolved —
  [RFC-0013](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0013-wasm-engine-selection-and-aot-strategy.md)/[ADR-0017](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0017-wasm-engine-selection-and-aot-strategy.md)
  (Accepted) fix Wasmtime, split into a runtime role (no `cranelift`/`winch` linked in —
  `Component::new`/`Engine::precompile_component` are themselves `#[cfg]`-gated out of
  Wasmtime's own API surface without them, so they're absent from this build, not merely
  unused) and an offline compiler role (behind the `compiler` Cargo feature).
- **First prototype code merged** (`src/`): `verified::load_verified_component` — the
  runtime role — verifies a `.cwasm` artifact's Ed25519 signature
  ([RFC-0007](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0007-cryptographic-primitive-set.md)'s ratified
  primitive, via [`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)'s `signing::verify`) and only then
  calls Wasmtime's `Component::deserialize` — required ordering, since Wasmtime documents
  `deserialize` as unsound on untrusted input. `compiler::precompile_and_sign` (behind the
  `compiler` feature) is the offline counterpart: `Engine::precompile_component` +
  `SigningKey::sign`. 3 unit tests pass: two against `verified` alone (a tampered artifact
  is rejected before deserialization is ever attempted; a validly-signed non-artifact still
  fails Wasmtime's own validation — signature and format are checked separately, not
  conflated), and — only under `cargo test --features compiler` — a full round trip
  (compile a trivial WAT component → sign → hand the bytes to a *fresh* runtime-role
  `Engine` → verify → deserialize → instantiate → call, returning the expected value),
  proving the compiler/runtime split is real rather than a paper distinction. `cargo
  clippy --all-targets -D warnings` clean, both with and without `--features compiler`;
  `cargo tree` confirms `cranelift-codegen`/`regalloc2`/`wasmtime-cranelift` are absent
  from the default (runtime-role) dependency tree.
- **Host-target only, for now.** This crate builds and tests against a native `std` host
  target (Wasmtime requires OS-level mmap/threads/signals it doesn't have a LanternOS
  equivalent for yet) — it does not build for `riscv64gc-unknown-none-elf` the way
  `lantern-hal`/`lantern-kernel`/`lantern-capabilities`/`lantern-crypto`/`lantern-filesystem`
  do. See "Next"/"Blocked on".

## Next
- Specify the WIT-handle ⇄ capability mapping — RFC-0013 explicitly deferred this; needs
  its own RFC before any real WASI host binding is wired up. Today's runtime role can load
  and run a component with no host imports at all (the round-trip test's component only
  exports); no host function surface exists yet.
- Custom, capability-gated WASI 0.2 host bindings — depends on the above, and on
  [`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)'s `Broker`/badge-check shape
  (`lantern-crypto`/`lantern-filesystem` already show the pattern one layer down).
- Resource accounting (CPU/memory budgets) tied to scheduling contexts — Wasmtime's
  fuel/epoch-interruption mechanism is the identified attachment point (RFC-0013), not yet
  wired up.
- Wasmtime's custom-platform embedding hooks (virtual memory, traps, threading) against
  `lantern-hal`/VSpace-Frame capabilities directly ([ADR-0012](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0012-vspace-frame-capabilities-and-elf-loader.md))
  — real, unstarted porting work needed before this crate can run inside a confined
  `riscv64` process rather than only on a host target.
- Where the compiler role physically runs (`lantern-sdk`/packaging tooling vs. an
  on-device install-time service) and the `.cwasm` artifact's signing-key management story
  — both left to `lantern-sdk`/packaging design, not decided here.

## Blocked on
- ~~Kernel IPC/endpoints ([`lantern-kernel`](https://github.com/lantern-os/lantern-kernel)).~~ Resolved —
  RFC-0009/ADR-0014.
- ~~Capability brokering API ([`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)).~~
  Resolved — `Broker` is real and proven (`lantern-capabilities/STATUS.md`); this crate
  doesn't consume it yet (see "Next"), but the API this was blocked on now exists.
