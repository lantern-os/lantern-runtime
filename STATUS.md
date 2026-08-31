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
- **The WIT-handle ⇄ capability mapping is fixed and first-implemented** —
  ~~specify it~~ / ~~custom capability-gated host bindings~~ resolved.
  [RFC-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0014-wit-handle-capability-mapping.md)/[ADR-0018](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0018-wit-handle-capability-mapping.md)
  (Accepted) fix two mapping shapes; `src/host.rs` + `wit/host.wit` implement both:
  - **Resource-scoped** (`lantern:crypto/keystore`, a new LanternOS-owned WIT interface —
    no keystore in the stable WASI 0.2 snapshot): each `key` handle is backed by a
    `HostCapability` (a `Broker` badge + `KeyId`) in a Wasmtime `ResourceTable`;
    `encrypt`/`decrypt`/`sign` forward to a real `lantern_crypto::Keystore` (a
    `KeystoreService` trait — an in-process stand-in for the not-yet-confined crypto
    service, `lantern-crypto/STATUS.md`), which re-checks the badge every call.
    Denied/revoked/wrong-key all relay as `error-code::access`; the mapping adds no check
    of its own. `keystore.open(slot)` is the only way a guest obtains a handle — `slot`
    indexes the manifest's explicit grant list, nothing ambient.
  - **Link-scoped** (`monotonic-clock`, mirroring `wasi:clocks/monotonic-clock@0.2.x`):
    `build_linker` links the whole interface or leaves it unlinked; an importing
    component fails to instantiate when it's unlinked. `now` reads a manifest-supplied
    `fn() -> u64` (production: `lantern-hal`'s `monotonic_time_ns()`; a host shim on the
    current x86-64 test target, whose HAL clock is still an `unimplemented!` stub — a
    `riscv64`-only follow-up).
  - `GrantManifest` is the runtime-side contract only (one badge per resource-scoped
    grant, one yes/no per link-scoped facility); the manifest *file format* stays
    `lantern-sdk`'s job. `wasi:filesystem` is deliberately unmapped (ADR-0018 — its
    path/directory shape doesn't fit `lantern-filesystem`'s CAS store; its own future RFC).
  - 16 tests pass (13 new): the resource-scoped mapping against a **real** `Keystore`
    with a real `Broker`-minted badge (encrypt/decrypt round trip, ENCRYPT-not-DECRYPT
    denial, post-revocation denial, signature length), a fault-injecting `KeystoreService`
    double for the error-translation and argument-validation edges, and — under
    `--features compiler` — the link-scoped clock end to end through real Wasmtime
    instantiation (granted → readable; denied → instantiation refused). `cargo clippy
    --all-targets -D warnings` clean, with and without `--features compiler`.
- **`lantern:host/filesystem` implemented** — RFC-0014's deferred filesystem choice,
  resolved by [RFC-0016](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0016-filesystem-wit-interface.md)/[ADR-0019](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0019-filesystem-wit-interface.md)
  (Accepted) in favour of a custom interface shaped like `lantern-filesystem`'s `Store`:
  a `file` handle backed by a `HostFile` (`Store` badge + `FileId`, a distinct host type
  from `HostCapability` — R5), `read`/`write` forwarding to a real `lantern_filesystem::Store`
  (a `FilesystemService` trait / `InProcessFilesystem` stand-in), `filesystem.open(slot)`
  the only acquisition path. **No paths, no directories, no listing, no guest-driven file
  creation.** Denied / revoked / wrong-`FileId` all relay as `error-code::access`; an
  unwritten file reads as empty; an oversized write is `invalid` (pre-checked before the
  store is consulted). `RuntimeState::new` is now a builder (`.with_keystore` /
  `.with_filesystem`). 26 tests total (10 new fs tests, against a real `Store` with real
  `Store`-minted badges — read/write round trip, read-denied, write-denied,
  wrong-file → `access`, oversize → `invalid`, unwritten → empty, dropped handle,
  `open` only for granted slots). `lantern-runtime` gains a normal dep on
  `lantern-filesystem` (not TCB). clippy clean both feature sets.
- **`GrantManifest` resource-scoped fields are now `Vec<Option<…>>`** (positional with
  holes) per [RFC-0015](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0015-capability-manifest-format.md)/[ADR-0020](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0020-capability-manifest-format.md)
  (Accepted): declaration order is the permanent `open(slot)` index, a `None` slot is a
  declined-or-unbound role that reads as `none`, and a non-empty all-`None` vec means the
  interface was *declared* (so it's linked) but every role declined. An empty vec still
  means "not declared" → interface unlinked. 27 tests.
- **Wasmtime pin bumped `24` → `48`** (2026-08-29, maintenance — ADR-0017's decision is
  unchanged). Wasmtime 24 (mid-2024) cannot parse a component produced by a current Rust
  toolchain (`wasm32-wasip2` / `wit-bindgen`), which the `lantern-example-signer` demo
  needs. The runtime-role dependency tree is still free of `cranelift-codegen`/`winch`
  (`cargo tree` confirmed); `wit-component` now appears, but only as a **proc-macro**
  build dependency of `bindgen!`, not linked into any runtime binary. Migration was small:
  `bindgen!`'s `with:` resource key is now `"pkg:ns/iface.resource"` (dot, was slash) and
  `add_to_linker` takes an explicit `HasSelf<T>` type parameter. Full test + clippy matrix
  re-run green.
- **Host-target only, for now.** This crate builds and tests against a native `std` host
  target (Wasmtime requires OS-level mmap/threads/signals it doesn't have a LanternOS
  equivalent for yet) — it does not build for `riscv64gc-unknown-none-elf` the way
  `lantern-hal`/`lantern-kernel`/`lantern-capabilities`/`lantern-crypto`/`lantern-filesystem`
  do. See "Next"/"Blocked on".

## Next
- Wire `monotonic-clock`'s `now` to `lantern-hal`'s real `monotonic_time_ns()` on
  `riscv64` (host target keeps the shim until the x86-64 HAL clock stops being a stub).
- `filesystem` v0 follow-ups (RFC-0016 "Unresolved"): `read-at`/`write-at` + a `size`
  accessor when `Store` grows chunking; `flush`/durability once `Store` has a persistence
  story; a `history` sub-interface for the version pillar.
- More interfaces on the established shapes: randomness once `lantern-hal` has a CSPRNG
  (link-scoped); a socket/network interface once `lantern-network` has a real service.
- Feed a verified sealed-capability token ([RFC-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0011-sealed-capability-token-format.md))
  into a resource-scoped grant, once a real cross-machine-sharing consumer exists.
- Benchmark resource-scoped per-call cost once the owning services are real IPC processes
  — RFC-0014 flags hot-loop crypto as a real latency risk, unmeasured.
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
  Resolved — `Broker` is real and proven (`lantern-capabilities/STATUS.md`), and the
  resource-scoped mapping now consumes badges it minted (via `lantern-crypto`'s `Keystore`).
