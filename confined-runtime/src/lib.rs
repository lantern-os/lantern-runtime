//! What both confined-runtime binaries share — [RFC-0018](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0018-confined-execution-port.md)'s
//! integration proofs, one per host interface:
//!
//! - `src/main.rs` (`lantern-confined-runtime`): `confined-probe-guest`, `keystore` over
//!   [`lantern_runtime::IpcKeystore`] to a confined `keystore-service`
//!   (`lantern-boot-runtime-demo`).
//! - `src/bin/fs.rs` (`lantern-confined-runtime-fs`): `confined-fs-guest`, `filesystem`
//!   over [`lantern_runtime::IpcFilesystem`] to a confined `store-service`, whose own AEAD
//!   goes through a confined `keystore-service` (`lantern-boot-runtime-fs-demo`).
//!
//! Each is one real U-mode program under the real kernel, with everything RFC-0018 split
//! into Parts 1–3: Wasmtime `no_std` + Pulley, its code and linear memory in `FrameMega`s
//! the program maps itself (`lantern_runtime::platform`, granted by `lantern-boot`'s
//! `ArenaGrant`), fuel on (Part 3); the guest's grant served over a real shared `Frame`
//! (Part 2) by a separately confined service (Part 1), of which this process holds only
//! the badged endpoint it was handed over IPC.
//!
//! **The guest arrives as a signed package, not in this image.** The launcher maps the
//! guest's `.lpkg` (built by `lantern-sdk build`: manifest + `.cwasm` + an Ed25519
//! signature over `BLAKE3(manifest) ‖ BLAKE3(cwasm)`) read-only at [`PACKAGE_VADDR`] and
//! passes its exact length in `arg0`. [`verify_package`] checks it against
//! [`PUBLISHER_KEY`], the one key this image trusts, and only a [`VerifiedCwasm`] that
//! check produced ever reaches Wasmtime's `deserialize`. The launcher is not trusted to
//! hand over the right bytes: a package it altered, or one signed by anyone else, fails
//! here at [`Stage::Package`].
//!
//! Two binaries, not one that picks its host wiring at run time: the wiring
//! (`IpcKeystore` vs `IpcFilesystem`) still differs per guest. Choosing it from the
//! package's own manifest needs a `no_std` manifest reader and the launch binder
//! (RFC-0015, `lantern-shell`) — later work.
//!
//! **Diagnostics**: every `Signal` either binary sends carries a [`Stage`] code in `a1`
//! and a detail word in `a2` (heap bytes used, on success). The kernel ignores both;
//! `lantern-boot`'s runtime-demo trap handlers print them. There is no console syscall,
//! and a confined program's only output channel is a capability it was granted.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use lantern_abi::sys;
use lantern_abi::wire::{syscall, MessageTag};
use lantern_runtime::{build_linker, deserialize_trusted_component, runtime_engine, GrantManifest, RuntimeState, DEFAULT_FUEL};

/// The service's endpoint — matches `keystore-service`'s `ENDPOINT_CPTR` and the endpoint
/// slot every `lantern-boot` demo client uses.
pub const ENDPOINT_CPTR: usize = 1;
/// Where the service's granted, badged copy lands (the reply-leg slot).
pub const DEST_CPTR: usize = 2;
/// Proof notifications — matches `lantern-boot/src/runtime_demo/loader.rs` and
/// `runtime_fs_demo/loader.rs`.
pub const SUCCESS_CPTR: usize = 3;
pub const FAILURE_CPTR: usize = 4;
// Slots 6.. hold the `ArenaGrant` (`lantern_runtime::platform`'s `SELF_VSPACE_CPTR`/
// `ARENA_FRAME_CPTR_BASE`); nothing here names them.

/// Where the loader mapped this program's half of the shared `Frame` — must match the
/// service's own `FRAME_VADDR` (`keystore-service`) or `CLIENT_FRAME_VADDR`-peer
/// (`store-service`).
pub const FRAME_VADDR: usize = 0x9000_0000;

/// Heap for `lantern-abi`'s bump allocator: Wasmtime's `Engine`/`Component`/`Store`
/// bookkeeping and Pulley's interpreter stack. Must equal `lantern_boot::launch::HEAP_VADDR`,
/// sized by the loader's `heap_megapages`. One `FrameMega`: measured under QEMU, a full
/// run uses ~840 KiB (keystore guest) to ~910 KiB (filesystem guest). The bump allocator
/// never frees, so that is the whole run's total, reported back in the `SUCCESS` signal's
/// detail word. About a third of it is [`verify_package`]'s tampered `.cwasm` copy.
pub const HEAP_BASE: usize = 0x8620_0000;
pub const HEAP_LEN: usize = 0x20_0000;

/// Where the launcher maps the guest's `.lpkg`, read-only — must equal
/// `lantern_boot::launch::PACKAGE_VADDR`. Its exact length arrives in `arg0`.
pub const PACKAGE_VADDR: usize = 0x8c00_0000;
/// The most the launcher maps there: one `FrameMega`.
pub const PACKAGE_MAX_LEN: usize = 0x20_0000;

/// The one publisher whose packages this image runs: the verifying half of the **demo**
/// key both guests' `.lpkg`s are signed with (`lantern-sdk build --seed 4c4c…4c`, 32
/// bytes of `0x4c`). The seed is public, so this proves the verification path, not
/// any real publisher's identity. Choosing which publishers a device trusts belongs to
/// the launch binder's trust store (RFC-0015), not to a constant in a runtime image.
pub const PUBLISHER_KEY: [u8; 32] = [
    0x92, 0x73, 0x08, 0xf5, 0x3d, 0x67, 0x65, 0x50, 0x3d, 0x2b, 0x64, 0xc1, 0x03, 0xab, 0x5a, 0xa4,
    0x72, 0x06, 0xab, 0x39, 0x50, 0x2c, 0xfe, 0x8f, 0x98, 0x44, 0x2f, 0xdb, 0x54, 0x31, 0x00, 0xb7,
];

/// What a `Signal`'s `a1` reports — see the crate doc.
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Stage {
    Done = 0,
    Grant = 1,
    Attenuation = 2,
    Deserialize = 3,
    Link = 4,
    Instantiate = 5,
    Lookup = 6,
    Call = 7,
    Verdict = 8,
    /// The launcher-provided `.lpkg`: detail `1` bad length, `2` malformed, `3` a
    /// tampered copy verified (the check itself is broken), `4` the real package did
    /// not verify.
    Package = 9,
}

pub type StageResult<T> = Result<T, (Stage, usize)>;

/// The whole program, after `lantern_abi::entry!`: set up the heap and panic reporting,
/// run `host` with `arg0` (the package length), signal its outcome, park.
pub fn run_and_report(arg0: usize, host: fn(usize) -> StageResult<()>) -> ! {
    // SAFETY: the loader mapped `HEAP_BASE..+HEAP_LEN` read/write into this program's own
    // VSpace before its first instruction ran (`ProgramSpec::heap_megapages`).
    unsafe { lantern_abi::rt::init_heap(HEAP_BASE, HEAP_LEN) };
    lantern_abi::rt::report_panics_via(FAILURE_CPTR);

    let (cptr, stage, detail) = match host(arg0) {
        // `heap_stats().0` is the bump pointer (an address), not a byte count.
        Ok(()) => (SUCCESS_CPTR, Stage::Done, lantern_abi::rt::heap_stats().0 - HEAP_BASE),
        Err((stage, detail)) => (FAILURE_CPTR, stage, detail),
    };
    signal_with(cptr, stage, detail);

    loop {
        core::hint::spin_loop();
    }
}

/// `Call` the service at [`ENDPOINT_CPTR`] to be granted a badged endpoint, which lands in
/// [`DEST_CPTR`] (`keystore-client`'s convention; stands in for the launch-binder flow,
/// RFC-0015/`lantern-shell`).
pub fn request_grant() -> StageResult<()> {
    sys::call_with_reply_slot(ENDPOINT_CPTR, DEST_CPTR, [0, 0]).map(drop).map_err(|_| (Stage::Grant, 0))
}

/// A `.cwasm` whose package signature verified under [`PUBLISHER_KEY`]. Only
/// [`verify_package`] constructs one, which is what lets [`run_probe`] be safe.
pub struct VerifiedCwasm(&'static [u8]);

/// Read the launcher's `.lpkg` at [`PACKAGE_VADDR`] and verify it under
/// [`PUBLISHER_KEY`].
///
/// First, a self-check: a copy with one `.cwasm` byte flipped must be **rejected**. A
/// broken verifier that accepted everything would otherwise pass this demo just as well
/// as a working one. The copy costs one `.cwasm` of heap, which never frees.
pub fn verify_package(package_len: usize) -> StageResult<VerifiedCwasm> {
    if package_len == 0 || package_len > PACKAGE_MAX_LEN {
        return Err((Stage::Package, 1));
    }
    // SAFETY: the loader mapped `PACKAGE_MAX_LEN` bytes read-only at `PACKAGE_VADDR` for
    // this program's whole life (`ProgramSpec::package`), and nothing maps over it.
    let bytes: &'static [u8] = unsafe { core::slice::from_raw_parts(PACKAGE_VADDR as *const u8, package_len) };
    let package = lantern_sdk::package::decode_package_ref(bytes).map_err(|_| (Stage::Package, 2))?;

    let mut tampered: Vec<u8> = package.cwasm_bytes.to_vec();
    if let Some(byte) = tampered.last_mut() {
        *byte ^= 1;
    }
    let forged = lantern_sdk::package::PackageRef { cwasm_bytes: &tampered, ..package };
    if forged.verify(&PUBLISHER_KEY).is_ok() {
        return Err((Stage::Package, 3));
    }

    package.verify(&PUBLISHER_KEY).map_err(|_| (Stage::Package, 4))?;
    Ok(VerifiedCwasm(package.cwasm_bytes))
}

/// Deserialize `cwasm`, link exactly what `manifest` declares, instantiate against
/// `state` with [`DEFAULT_FUEL`], and call the guest's `probe: func() -> string` export.
///
/// The manifest inside the package is signed but not read here: turning it into grants
/// is the launch binder's job. `manifest` is still this binary's fixed demo grant.
pub fn run_probe(cwasm: VerifiedCwasm, manifest: &GrantManifest, state: RuntimeState) -> StageResult<String> {
    let engine = runtime_engine();
    // SAFETY: `VerifiedCwasm` exists only for bytes whose package signature verified
    // under `PUBLISHER_KEY` (`verify_package`) — `deserialize_trusted_component`'s
    // contract, the `.lpkg` case its own doc names.
    let component = unsafe { deserialize_trusted_component(&engine, cwasm.0) }.map_err(|_| (Stage::Deserialize, 0))?;

    let mut linker = build_linker(&engine, manifest).map_err(|_| (Stage::Link, 0))?;
    // `std` `wasm32-wasip2` startup imports (`wasi:cli/*`, `wasi:io/*`) the guest never
    // calls: trap stubs, not WASI. Same as the host-side tests of these guests.
    linker.define_unknown_imports_as_traps(&component).map_err(|_| (Stage::Link, 1))?;

    let mut store = wasmtime::Store::new(&engine, state);
    store.set_fuel(DEFAULT_FUEL).map_err(|_| (Stage::Instantiate, 0))?;
    let instance = linker.instantiate(&mut store, &component).map_err(|_| (Stage::Instantiate, 1))?;

    let probe = instance
        .get_typed_func::<(), (String,)>(&mut store, "probe")
        .map_err(|_| (Stage::Lookup, 0))?;
    let (report,) = probe.call(&mut store, ()).map_err(|_| (Stage::Call, 0))?;
    Ok(report)
}

/// The guest's report must start `ok: ` and contain every `required` marker; detail is
/// the index of the first one missing (`0` for the `ok: ` prefix itself).
pub fn check_report(report: &str, required: &[&str]) -> StageResult<()> {
    if !report.starts_with("ok: ") {
        return Err((Stage::Verdict, 0));
    }
    match required.iter().position(|marker| !report.contains(marker)) {
        Some(i) => Err((Stage::Verdict, i + 1)),
        None => Ok(()),
    }
}

/// `Signal` with a [`Stage`] in `a1` and `detail` in `a2` — the same syscall
/// [`sys::signal`] issues, plus two words the kernel ignores. Hand-rolled because
/// `lantern_abi::sys`'s raw `ecall` is private.
fn signal_with(notification: usize, stage: Stage, detail: usize) {
    // SAFETY: an `ecall` from U-mode always traps cleanly to the kernel (see
    // `lantern_abi::sys::raw`'s own contract); `Signal` reads only `a0`.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") notification => _,
            inout("a1") stage as usize => _,
            inout("a2") detail => _,
            inout("a3") 0usize => _,
            inout("a4") MessageTag::EMPTY.into_raw() => _,
            in("a7") syscall::SIGNAL,
            options(nostack),
        );
    }
}
