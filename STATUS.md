# lantern-runtime — Status

**Phase:** 2 — opened per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md), **closed** per [RFC-0017](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0017-phase-2-to-phase-3-transition.md)/[ADR-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0021-phase-2-complete-phase-3-opened.md): the Phase 2 exit criterion is met (a third-party Wasm app confined, adversarially — `lantern-example-signer` + `lantern-sdk build`). This crate's "Next" items continue as ordinary engineering work; the Roadmap's gate has moved to Phase 3. **Carried forward (ADR-0021):** this crate builds and runs only on a native `std` host target — the Wasmtime `riscv64` custom-platform port (against `lantern-hal`/VSpace-Frame) is **Phase 3's first work**, not a Phase 2 gap.

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
- **Two helpers for the `lantern-sdk` package flow (RFC-0015):** `compiler::component_import_names`
  (a component's import identifiers, for the SDK's "imports ≤ declarations" build check —
  `compiler` feature) and `deserialize_trusted_component` (the raw `Component::deserialize`
  for callers who verified integrity via `lantern_sdk::package::verify_package`, whose
  signature is over the manifest+cwasm digest, not the bare `.cwasm`). 28 tests.
- **Wasmtime pin bumped `24` → `48`** (2026-08-29, maintenance — ADR-0017's decision is
  unchanged). Wasmtime 24 (mid-2024) cannot parse a component produced by a current Rust
  toolchain (`wasm32-wasip2` / `wit-bindgen`), which the `lantern-example-signer` demo
  needs. The runtime-role dependency tree is still free of `cranelift-codegen`/`winch`
  (`cargo tree` confirmed); `wit-component` now appears, but only as a **proc-macro**
  build dependency of `bindgen!`, not linked into any runtime binary. Migration was small:
  `bindgen!`'s `with:` resource key is now `"pkg:ns/iface.resource"` (dot, was slash) and
  `add_to_linker` takes an explicit `HasSelf<T>` type parameter. Full test + clippy matrix
  re-run green.
- **The lib is host-target only, for now** — it builds and tests against a native `std`
  host target. The confined-runtime port (RFC-0018 Part 3 / [ADR-0023](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0023-wasmtime-no-std-pulley-hosting.md))
  is groundwork-complete, in `riscv64-probe/` rather than the main lib (see below).
- **RFC-0018 Part 3 groundwork — Wasmtime `no_std` + Pulley proven** (2026-09-06,
  `riscv64-probe/`):
  - The runtime + compiler roles now target **`pulley64`**
    (`verified::pulley_config`, shared by `runtime_engine`/`compiler_engine`): the compiler
    role AOT-compiles to portable Pulley bytecode, the runtime role runs it through the
    interpreter — no native codegen, traps as `Result::Err`. All 28 existing tests
    (compile→sign→verify→deserialize→instantiate→call, the clock e2e) pass unchanged on
    Pulley; runtime role still free of `cranelift-codegen`/`wasmtime-cranelift`/`regalloc2`
    (`pulley-interpreter` pulls the tiny `cranelift-{bitset,entity,bforest}` data-structure
    crates only).
  - `riscv64-probe/` — a nested crate proving the rest: `wasmtime` 48 built
    `default-features = false` with `["runtime", "component-model", "pulley",
    "custom-virtual-memory", "custom-sync-primitives"]` (**not** `custom-native-signals` —
    Pulley needs no signal handler; a refinement of ADR-0023's feature list) **compiles for
    `riscv64gc-unknown-none-elf` and links** into a `#![no_std]` / `#![no_main]` binary
    (`--features bin`, with `lantern-abi`'s `rt`). `src/platform.rs` implements Wasmtime's
    `sys/custom` C API — `wasmtime_mmap_*`/`mprotect`/`page_size` over a `.bss` bump arena,
    `wasmtime_tls_*` as one static pointer, `wasmtime_sync_*` as uncontended no-ops,
    `wasmtime_memory_image_*` as "unsupported" (zero-fill fallback); no `wasmtime_init_traps`,
    no `wasmtime_fiber_*`. The crate's host `cargo test` deserializes + instantiates + runs
    an embedded Pulley `.cwasm` **through that shim** (Wasmtime's `custom` path, `std`
    feature off) → returns 42.
  - ~~Not done: ... the `riscv64` binary links but can't be loaded by `lantern-boot`'s
    one-megapage-per-segment loader yet (needs the launcher / DTB memory discovery)~~ —
    **loaded and run under the real kernel for the first time, 2026-09-13**
    (`lantern-boot-wasm-probe-demo`, `lantern-boot/STATUS.md`): the launcher/DTB
    prerequisite named here shipped weeks ago, but a real, much more precise blocker
    surfaced only once someone actually tried to load this binary — the original 64 MiB
    `.bss` arena alone needed ~32 of `lantern-kernel`'s `MAX_FRAMES` (a hard 16
    system-wide, `lantern-kernel/src/limits.rs`), categorically too many, not just a lot.
    Bisected the arena down to the smallest round number the embedded component actually
    needs (256 KiB — a ~500x cut, found by testing 64 KiB fails, 128 KiB passes) and gave
    the binary's own heap the same treatment (32 MiB → 2 MiB, one `FrameMega`, via the
    launcher's existing `ProgramSpec::heap_megapages`) — the whole program now needs only
    ~4 `FrameMega`s total. Also fixed a real, separate bug while making this observable
    from S-mode: the probe's result (`run_embedded_answer()`'s `Ok(42)`) was computed but
    never actually signalled — `let _ = badge;` silently discarded it — now signals one of
    two distinguishable notifications, this project's usual convention. **4/4 reproducible
    `Signal'd SUCCESS`** under real QEMU; existing `riscv64-probe` host tests (3) and
    clippy (host + `riscv64 --features bin`) still green.
  - **Still not done**: the arena is a `static`, not `FrameInvoke::Map`-backed; no host
    imports / `IpcKeystore`/`IpcFilesystem`; no real (non-trivial) guest component — this
    demo's `answer.pulley.cwasm` is still the trivial `(func (export "run") (result s32)
    → 42)` fixture. Those, not the loader, are what's actually left before the full
    RFC-0018 integration demo (keystore + store + a confined runtime together). Regenerate
    `riscv64-probe/assets/answer.pulley.cwasm` with any `compiler`-feature engine at
    `target("pulley64")`.
- **The `Frame`-backed platform layer is implemented and live end-to-end (2026-09-15)** —
  `platform.rs`'s `wasmtime_mmap_new`/`wasmtime_munmap` now have a real `riscv64` backing
  (`mod backing`, gated `target_arch = "riscv64"` + `feature = "bin"`): a bounded pool of
  *unmapped* `FrameMega` capabilities plus a capability to the program's own VSpace, granted
  by `lantern-boot`'s new `ProgramSpec::arena`/`launch::ArenaGrant` and mapped/unmapped by
  the program itself via real `FrameInvoke::Map`/`Unmap` (`lantern_abi::sys::frame`), on
  demand, at a reserved virtual range (`ARENA_VADDR`) — not a `.bss` static array. Host
  `cargo test` keeps the original static-arena fallback unchanged (3 host tests still
  green); the checked-in `wasm-probe.elf` demo asset is now built *with* the real backing,
  **4/4 reproducible `Signal'd SUCCESS`**.
  - **Getting this working for real found — and fixed, same day — a genuine,
    previously-unexercised `lantern-kernel` bug.** Every prior `FrameInvoke::Map`/`Unmap`
    call in this project's demos was issued by the launcher as a plain Rust function call
    pre-`enter_first_thread`, while `satp` is still Bare (no translation) — every physical
    address is directly addressable then. `ArenaGrant`'s confined-program *self*-mapping is
    the first real `ecall` into `FrameInvoke` after paging is active, and RISC-V traps don't
    switch page tables — so S-mode code servicing that `ecall` keeps running under the
    *program's own* active table, which had no mapping for the `VSpace` root table's own
    physical memory (bump-allocated from the general-memory `Untyped`, a range loaded
    programs' own virtual addresses also numerically overlap). Diagnosed live under QEMU via
    the monitor (`info registers`, same PC/`scause`/`stval` across two reads — a genuine
    stuck load page fault at the VSpace root's own physical address). A first fix attempt
    (identity-mapping the whole general-memory range S-mode-only in `map_kernel_shared`)
    collided with exactly that address reuse (`riscv64-probe`'s own `BASE_ADDRESS =
    0x8400_0000` sits inside general memory) and was reverted rather than shipped broken.
    **Fixed properly in `lantern-kernel`**: a new `object::KernelPageTables` — `VSpace`
    roots and `FrameInvoke::Map`'s on-demand branch pages now live in a small, fixed-size
    arena embedded in `KernelState` itself (kernel `.bss`), always inside the one megapage
    every loaded VSpace already maps S-mode-only, instead of the general-memory `Untyped`
    range. No `lantern-hal` changes, no relinking any service crate. See
    `lantern-kernel/STATUS.md` and `lantern-boot/STATUS.md` for the full writeup.
- **`IpcKeystore`/`IpcFilesystem` — the real RFC-0018 Part 2 IPC transport under
  `KeystoreService`/`FilesystemService` (2026-09-15, `host.rs`)** — both reach a real,
  confined `keystore-service`/`store-service` over one `lantern_abi::frame::Channel` each,
  alongside the existing in-process stand-ins (`lantern_crypto::Keystore`'s own
  `KeystoreService` impl, `InProcessFilesystem`). `IpcKeystore` uses `lantern_crypto::wire`'s
  already-built client-side codecs (the same ones `lantern-boot`'s `keystore-client` demo
  uses); `IpcFilesystem` needs none — `lantern_filesystem::wire`'s READ/WRITE are raw bytes,
  so it calls `Channel::call` directly with the caller's own buffers, no scratch copy, no
  fixed cap (`Channel::call` chunks transparently past one `Frame` regardless of size).
  Both use `std::sync::Mutex<Channel>` for `KeystoreService`/most of `FilesystemService`'s
  `&self` methods — never actually contended (single-hart, non-reentrant, ADR-0010), just
  avoids a hand-rolled `unsafe impl Sync`. **v0 scope, documented in `IpcKeystore`'s own
  doc**: one instance wraps exactly one granted `(endpoint, Frame)` relationship — matching
  every real demo built so far (`keystore-client` only ever holds one key); the trait's own
  `badge` parameter is accepted but not used to pick between multiple relationships. New
  `lantern_crypto::KeystoreError::Channel`/`RemoteDenied` variants mirror
  `lantern_filesystem::StoreError::Channel`/`RemoteCryptoDenied`'s existing shape (built for
  `lantern_filesystem::cipher::ChannelCipher`, the direct one-layer-down precedent this
  round's design copies); `host.rs`'s `to_error_code`/`to_fs_error_code` map a genuine
  remote `ACCESS` denial through to the WIT interface's own `access` code rather than the
  generic `invalid` bucket. Added `lantern-abi` as a new, unconditional (non-TCB) dependency
  — first time this crate has needed it. 24 tests green (host `cargo test`, `--features
  compiler` both checked; `IpcKeystore`/`IpcFilesystem` get one `Send + Sync` trait-bound
  check — a real `Channel` round trip needs a real `ecall`, so, like `ChannelCipher`, no
  host tests exercise the wire path itself; QEMU is the real proof once there's a demo to
  run).
- **The `no_std`/`riscv64` build is folded into this crate's own main lib (2026-09-16,
  `Cargo.toml`'s new `std`/`confined` features)** — the last piece named in RFC-0018 Part
  3's "Next": `lantern-runtime/riscv64-probe`'s job (prove the concept) is done; this crate
  now builds and links for `riscv64gc-unknown-none-elf` itself, `#[cfg_attr(not(feature =
  "std"), no_std)]` at the crate root, `extern crate alloc` for `Vec`/`Box`. `wasmtime`
  dropped its always-on `std` feature — `default = ["std"]` keeps every existing host
  caller (tests, `lantern-example-signer`'s runner) unchanged; `--no-default-features
  --features confined` instead forwards `wasmtime/custom-virtual-memory`/
  `custom-sync-primitives` and pulls in [`platform`] (folded in verbatim from
  `riscv64-probe/src/platform.rs`, dropping its host-test fallback arena — this crate's own
  host build never needs a custom platform at all, real Wasmtime handles memory there).
  `lantern-crypto`/`lantern-filesystem` switched to `default-features = false` in
  `[dependencies]` (this crate's own use of both is post-grant operation only —
  `Keystore::encrypt/decrypt/sign`, `Store::read/write` — never the `Broker`-backed
  grant-issuing side `kernel-backend` gates; works unchanged for either role, no per-role
  split needed) with a `[dev-dependencies]` re-add of `lantern-crypto` (default features)
  so this crate's own real-`Keystore`-backed tests keep working. **De-risked before
  committing to the refactor**: a standalone scratch probe confirmed
  `wasmtime::component::bindgen!` against the real `app` WIT world (resource-scoped
  `keystore`/`filesystem`, link-scoped `monotonic-clock`) compiles clean for `riscv64gc-
  unknown-none-elf` with `custom-virtual-memory` — the actual unknown, not the mechanical
  Cargo/cfg restructuring around it. `IpcKeystore`/`IpcFilesystem` dropped `std::sync::Mutex`
  for a new `SingleThreadCell` (`core::cell::RefCell` + `unsafe impl Sync`, ADR-0010) so
  they work identically in both roles without a second implementation. Verified: host
  `cargo build`/`test` (24 tests) and `--features compiler` (29 tests) unchanged;
  `--no-default-features --features confined --target riscv64gc-unknown-none-elf` builds
  clean (dev *and* release) and clippy-clean; a local-path smoke test against
  `lantern-example-signer`'s runner confirmed the public API shape (`GrantManifest`/
  `RuntimeState`/`build_linker`/`MonotonicClock`) is unaffected — that runner's own
  `fixture.rs` has independently drifted from current `lantern-filesystem`/
  `lantern-capabilities` APIs (`Store::write`'s `&mut Cipher` param, `BrokerBackend`,
  `InProcessFilesystem`'s 4-arg ctor), pre-existing staleness unrelated to this round, not
  fixed here. **Still not built**: an actual confined binary (a `_start`/entry point, a
  `GrantManifest` from real launcher grants, `lantern-abi/rt`'s allocator/panic-handler —
  belongs in a new, separate binary crate the way `riscv64-probe`'s own `[[bin]]` split
  works, not this library) and the new demo/loader granting it a real
  `keystore-service`/`store-service` endpoint and shared `Frame` — the actual RFC-0018
  integration proof, still ahead.
- **Fuel wiring — RFC-0018 Part 3's chosen v0 mechanism for preempting a runaway component
  (2026-09-16, `verified.rs`)** — `pulley_config()` now turns `Config::consume_fuel(true)`
  on unconditionally, and a new `DEFAULT_FUEL` constant (10,000,000 — generous, explicitly
  *not tuned*, same philosophy as `lantern-kernel/src/limits.rs`'s fixed capacities; no real
  non-trivial guest component exists yet to calibrate against). **De-risked empirically
  before wiring it in** (same discipline as the `bindgen!` no_std check): a scratch WAT
  component with a 2-billion-iteration loop, run against a 1000-fuel budget, traps cleanly
  with `"all fuel consumed by WebAssembly"` — confirms Pulley (the interpreter, no
  Cranelift-generated code) genuinely respects fuel, not assumed from the RFC text alone.
  Turning `consume_fuel` on unconditionally means **every caller must now call
  `Store::set_fuel` before running any guest code** — Wasmtime does not default a budget,
  so a caller that forgets gets an immediate out-of-fuel trap, not silent unlimited
  execution. Fixed every call site in this crate (3 `host/tests.rs` cases, 1
  `compiler.rs` round-trip test); the crate-level doc now calls out that an out-of-tree
  embedder (`lantern-example-signer`'s runner) will need the same one-line fix on its next
  `lantern-runtime` bump — not fixed here, flagged, matching the fixture-staleness note
  above (that repo has independent, pre-existing drift already). Two new tests: a runaway
  loop actually traps (not hangs); the new default budget is enough for a trivial
  component. 31 tests green with `--features compiler` (24 without); riscv64 `confined`
  build/clippy unaffected (fuel is Engine/Store config, no platform-specific code).
- **Resolved the `KeyId` construction gap a real confined-runtime binary would hit
  (2026-09-17)** — `lantern_crypto::KeyId::from_raw` (pushed separately, see that repo's
  STATUS.md) gives a caller with no real `Keystore` to mint one from (an `IpcKeystore`
  user) a documented, always-panic-safe way to construct a `HostCapability::keystore_key`.
  `HostCapability::keystore_key`'s own doc here now points at it. Checked before deciding,
  not assumed: `KeyId`'s field privacy was never a safety-critical invariant (bounds-checked
  lookup, equality-checked authorization) — this was a real design question worth a
  deliberate call, not a `pub fn from_raw` added unilaterally.
- **`confined-probe-guest` — RFC-0018's first real (non-trivial) confined guest component,
  proven end to end against a real `Keystore` (2026-09-17)** — a new sibling crate, genuine
  Rust compiled via `wasm32-wasip2`/`wit-bindgen` (no extra tooling needed, matching
  `reference_wasm_component_toolchain`'s own notes), importing exactly one capability-gated
  interface — `lantern:host/keystore` — deliberately narrower than
  `lantern-example-signer`'s own three-interface `signer` world (whose `attest`/`probe`
  this crate's own `probe` borrows its keystore-calling shape from, with attribution): no
  real confined `store-service`/filesystem grant or link-scoped clock grant needed just to
  instantiate. Precompiled to `pulley64` by this crate's own `compiler` role
  (`compiler_engine`/`precompile_and_sign`) into the checked-in `assets/probe.pulley.cwasm`
  (regenerate the same way `riscv64-probe`'s own fixture is regenerated: any
  `compiler`-feature engine at `target("pulley64")`, here against `confined-probe-guest`'s
  `wasm32-wasip2` release output). **New test
  (`confined_probe_guest_signs_through_a_real_keystore`) proves the whole pipeline for
  real**: component instantiation, the resource-scoped `keystore` grant, and an actual
  `sign` call landing through the generated `Host` trait onto a real, `Broker`-granted
  in-process `Keystore` — with the ungranted slot correctly reading back `none`. Needed
  `Linker::define_unknown_imports_as_traps` (a `std` `wasm32-wasip2` cdylib imports
  ~10 `wasi:cli/*`/`wasi:io/*` interfaces from its own startup machinery even when unused —
  known, documented friction, not a surprise). **What this proves and doesn't**: the wiring
  *shape* (a real, non-trivial guest genuinely calling through the resource-scoped mapping)
  is now demonstrated — the *transport* (`IpcKeystore` over a real `Channel`) still isn't;
  this test uses the in-process `Keystore` backend, the same as every other keystore test in
  this file. 32 tests green with `--features compiler`; riscv64 `confined` build/clippy
  unaffected (this is a host-only test, gated with everything else `compiler` implies).

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
- **The confined-execution port** — running this crate inside a confined `riscv64` process
  and forwarding host calls to real `Keystore`/`Store` services over IPC.
  [RFC-0018](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0018-confined-execution-port.md) (Accepted) is the design,
  fixed by two ADRs:
  [ADR-0022](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0022-confined-service-model-and-call-transport.md) —
  `IpcKeystore`/`IpcFilesystem` trait impls holding a badged service endpoint + a shared
  `Frame` view (no in-memory IPC buffer), the services as confined U-mode programs on a new
  non-TCB `lantern-abi` substrate — with the actual marshal/unmarshal wire format each
  trait impl uses now fixed by
  [ADR-0024](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0024-confined-service-call-protocol.md) (Accepted
  2026-09-12: the 16-byte request/reply header, the SIGN/ENCRYPT/DECRYPT and READ/WRITE
  layouts, and `lantern_abi::frame::Channel`, the helper `IpcKeystore`/`IpcFilesystem` call
  through); and
  [ADR-0023](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0023-wasmtime-no-std-pulley-hosting.md) — Wasmtime `no_std`
  + the Pulley bytecode interpreter behind its custom-platform C API (over `Frame`
  capabilities), the compiler role emitting portable Pulley `.cwasm`, fuel for v0
  interruption. Adds nothing to the TCB. **Phase 3's foundational work** (ADR-0021); Part 3
  (this crate's `riscv64` build) has no hard dependency on Part 1 (the services port).
  **Part 3 groundwork is done** (`riscv64-probe/`, see "Done") — Pulley builds, links for
  `riscv64`, and runs a component through a LanternOS platform shim. **The real
  `Frame`-backed platform layer is implemented and live** (see "Done"). **`IpcKeystore`/
  `IpcFilesystem` over the shared `Frame` (Part 2) are implemented too, the `no_std` build
  is folded into this crate's own main lib, fuel metering is wired in and on by default,
  and a real (non-trivial) guest component exists and is proven against a real `Keystore`**
  (see "Done", `confined-probe-guest`) — this crate itself now builds and links for
  `riscv64`, `IpcKeystore`/`IpcFilesystem` included, every guest execution is
  fuel-bounded, and the wiring shape for a genuine resource-scoped host call is
  demonstrated end to end (in-process transport). Remaining: a new, separate
  confined-runtime *binary* crate (entry point, allocator, a `GrantManifest` built with
  `KeyId::from_raw` from real launcher grants — this library deliberately doesn't provide
  one, same split `riscv64-probe`'s own `[lib]`/`[[bin]]` division uses); and a new
  demo/loader granting that binary a real `keystore-service` endpoint and shared `Frame`
  (+ an `ArenaGrant` for its own Wasm memory) — proving `IpcKeystore` over a real `Channel`
  with `confined-probe-guest` as the actual guest, the last piece of the RFC-0018
  integration proof.
- Where the compiler role physically runs (`lantern-sdk`/packaging tooling vs. an
  on-device install-time service) and the `.cwasm` artifact's signing-key management story
  — both left to `lantern-sdk`/packaging design, not decided here.

## Blocked on
- ~~Kernel IPC/endpoints ([`lantern-kernel`](https://github.com/lantern-os/lantern-kernel)).~~ Resolved —
  RFC-0009/ADR-0014.
- ~~Capability brokering API ([`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)).~~
  Resolved — `Broker` is real and proven (`lantern-capabilities/STATUS.md`), and the
  resource-scoped mapping now consumes badges it minted (via `lantern-crypto`'s `Keystore`).
