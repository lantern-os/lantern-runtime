//! The library half of `lantern-confined-runtime`, [RFC-0018](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0018-confined-execution-port.md)'s
//! integration proof. One binary, two wirings, chosen by the guest's own package:
//!
//! - `confined-probe-guest` declares `keystore`: [`lantern_runtime::IpcKeystore`] to a
//!   confined `keystore-service` (`lantern-boot-runtime-demo`).
//! - `confined-fs-guest` declares `filesystem`: [`lantern_runtime::IpcFilesystem`] to a
//!   confined `store-service`, whose own AEAD goes through a confined `keystore-service`
//!   (`lantern-boot-runtime-fs-demo`).
//!
//! It is one real U-mode program under the real kernel, with everything RFC-0018 split
//! into Parts 1–3: Wasmtime `no_std` + Pulley, its code and linear memory in `FrameMega`s
//! the program maps itself (`lantern_runtime::platform`, granted by `lantern-boot`'s
//! `ArenaGrant`), fuel on (Part 3); the guest's grant served over a real shared `Frame`
//! (Part 2) by a separately confined service (Part 1), of which this process holds only
//! the badged endpoint it was handed. It gets that from the launch binder
//! ([RFC-0020](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0020-launch-binder.md)): it holds no endpoint to the
//! service until the binder decides it should.
//!
//! **The guest arrives as a signed package, not in this image.** The launcher maps the
//! guest's `.lpkg` (built by `lantern-sdk build`: manifest + `.cwasm` + an Ed25519
//! signature over `BLAKE3(manifest) ‖ BLAKE3(cwasm)`) read-only at [`PACKAGE_VADDR`] and
//! passes its exact length in `arg0`. [`verify_package`] checks it against
//! [`TRUSTED_PUBLISHERS`], and only a [`VerifiedPackage`] that check produced ever reaches Wasmtime's `deserialize` or the manifest parser. The
//! launcher is not trusted to hand over the right bytes: a package it altered, or one
//! signed by anyone else, fails here at [`Stage::Package`].
//!
//! **The manifest is a request, not authority (RFC-0015).** [`VerifiedPackage::plan`] reads
//! it with the same parser `lantern-sdk build` validated it with, and it decides only which
//! host wiring this process builds and how many `open(slot)` indices exist. Everything the
//! guest can actually reach is the capabilities this process was handed, attenuated by the
//! services that enforce them: a manifest asking for more gets nothing more. What a request
//! binds to is the launch binder's decision (`lantern-shell`).
//!
//! **A grant can end ([RFC-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0021-grant-ledger-and-revocation.md)).**
//! After the guest's first `probe` passes, this process leaves a request open at the service and
//! has `grant-control` revoke the grant. The open request must then fail with `ACCESS`, and a second
//! `probe` on the same instance must report the refusal. The guest's handle hasn't changed: the
//! service just stops honouring the badge.
//!
//! **Diagnostics**: every `Signal` this program sends carries a [`Stage`] code in `a1`
//! and a detail word in `a2` (heap bytes used, on success). The kernel ignores both;
//! `lantern-boot`'s runtime-demo trap handlers print them. There is no console syscall,
//! and a confined program's only output channel is a capability it was granted.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use lantern_abi::frame::{status, RequestHeader, FLAG_MORE};
use lantern_abi::grant;
use lantern_abi::sys;
use lantern_runtime::{build_linker, deserialize_trusted_component, runtime_engine, GrantManifest, RuntimeState, DEFAULT_FUEL};
use lantern_sdk::GrantPlan;

/// The launch binder's endpoint, the only thing this process can ask for a grant.
pub const ENDPOINT_CPTR: usize = 1;
/// Where the service's badged endpoint lands, if the binder grants one.
pub const DEST_CPTR: usize = 2;
/// Proof notifications — matches `lantern-boot/src/runtime_demo/loader.rs` and
/// `runtime_fs_demo/loader.rs`.
pub const SUCCESS_CPTR: usize = 3;
pub const FAILURE_CPTR: usize = 4;
/// Empty, and stays empty unless a [`request_grant`] self-check is about to fail.
const PROBE_CPTR: usize = 5;
// Slots 6..=9 hold the `ArenaGrant` (`lantern_runtime::platform`'s `SELF_VSPACE_CPTR`/
// `ARENA_FRAME_CPTR_BASE`); nothing here names them.
/// A demo-only pair with `grant-control`, no part of RFC-0021's protocol: ask it to revoke, and
/// wait until it has. Must match the runtime demos' loaders.
const REVOKE_REQUEST_CPTR: usize = 10;
const REVOKE_DONE_CPTR: usize = 11;

/// Where the loader mapped this program's half of the shared `Frame` — must match the
/// service's own `FRAME_VADDR` (`keystore-service`) or `CLIENT_FRAME_VADDR`-peer
/// (`store-service`).
pub const FRAME_VADDR: usize = 0x9000_0000;

/// Heap for `lantern-abi`'s bump allocator: Wasmtime's `Engine`/`Component`/`Store`
/// bookkeeping and Pulley's interpreter stack. Must equal `lantern_boot::launch::HEAP_VADDR`,
/// sized by the loader's `heap_megapages`. One `FrameMega`: measured under QEMU, a full
/// run uses ~855 KiB (keystore guest) to ~925 KiB (filesystem guest). The bump allocator
/// never frees, so that is the whole run's total, reported back in the `SUCCESS` signal's
/// detail word. About a third of it is [`verify_package`]'s tampered `.cwasm` copy.
pub const HEAP_BASE: usize = 0x8620_0000;
pub const HEAP_LEN: usize = 0x20_0000;

/// Where the launcher maps the guest's `.lpkg`, read-only — must equal
/// `lantern_boot::launch::PACKAGE_VADDR`. Its exact length arrives in `arg0`.
pub const PACKAGE_VADDR: usize = 0x8c00_0000;
/// The most the launcher maps there: one `FrameMega`.
pub const PACKAGE_MAX_LEN: usize = 0x20_0000;

/// The publishers whose packages this image runs: the verifying halves of the **demo**
/// seeds `lantern-sdk build --seed 4c4c…4c` and `4d4d…4d`. Both are public, so this proves
/// the verification path, not any real publisher's identity. It duplicates the launch
/// binder's own set (RFC-0020, unresolved question 3): this process must not `deserialize`
/// on the binder's word.
pub const TRUSTED_PUBLISHERS: [[u8; 32]; 2] = [
    [
        0x92, 0x73, 0x08, 0xf5, 0x3d, 0x67, 0x65, 0x50, 0x3d, 0x2b, 0x64, 0xc1, 0x03, 0xab, 0x5a, 0xa4,
        0x72, 0x06, 0xab, 0x39, 0x50, 0x2c, 0xfe, 0x8f, 0x98, 0x44, 0x2f, 0xdb, 0x54, 0x31, 0x00, 0xb7,
    ],
    [
        0x62, 0xa6, 0x11, 0xb4, 0x72, 0xd8, 0x9b, 0x0e, 0x5f, 0xc9, 0x3c, 0x06, 0x9b, 0x9f, 0x70, 0x0b,
        0x4c, 0x55, 0x2d, 0x55, 0xbc, 0x0e, 0x87, 0xb5, 0x60, 0x08, 0xef, 0x17, 0xb6, 0xb2, 0xbe, 0xbe,
    ],
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
    /// The verified package's manifest: detail `1` failed validation, `2` declares no
    /// resource-scoped interface, `3` declares more than this process can wire (it holds
    /// one service endpoint), `4` asks for `monotonic-clock`, which has no confined backend.
    Manifest = 10,
    /// RFC-0021's sequence: detail `1` opening a chunked request failed, `2` the signal to
    /// `grant-control` failed, `3` the second `probe` didn't report a refusal, or `0x100 | status`
    /// when the request open during the revocation came back as anything but `ACCESS`.
    Revocation = 11,
    /// `grant-control` found something wrong; detail is its step. It signals this itself.
    Control = 12,
}

/// What a guest's two `probe` calls must show.
pub struct ProbeChecks<'a> {
    /// In the first report, after `ok: `.
    pub required: &'a [&'a str],
    /// An op to leave open at the service during the revocation.
    pub open_op: u16,
    /// In the second report, after `error: `.
    pub refused: &'a str,
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

/// Ask the launch binder for slot 0 of `interface` (`lantern_abi::grant::INTERFACE_*`). The
/// slot is the only one bound today: `IpcKeystore` and `IpcFilesystem` each wrap one
/// `(endpoint, Frame)`. `Ok(false)` means declined, and the guest's `open(0)` reads `none`.
///
/// When granted, three self-checks, so a binder or service that had stopped refusing can't pass
/// these demos: binding the same slot again must be declined; sending `GRANT` on the badge just
/// received must come back `ACCESS`; and this process's own badge mustn't reach the binder's
/// control ops. Under it, `LIST` and `REVOKE` read as `BIND`s and are declined, so entry 0 stays
/// live, which the first `probe` then shows.
pub fn request_grant(interface: usize) -> StageResult<bool> {
    if !grant::bind(ENDPOINT_CPTR, DEST_CPTR, interface, 0).map_err(|_| (Stage::Grant, 1))? {
        return Ok(false);
    }
    if grant::bind(ENDPOINT_CPTR, PROBE_CPTR, interface, 0).map_err(|_| (Stage::Grant, 1))? {
        return Err((Stage::Grant, 2));
    }
    if !matches!(grant::request_grant(DEST_CPTR, PROBE_CPTR, 0, 0xf), Ok((status::ACCESS, _))) {
        return Err((Stage::Grant, 3));
    }
    if !matches!(grant::list(ENDPOINT_CPTR, 0), Ok(None)) {
        return Err((Stage::Grant, 4));
    }
    if matches!(grant::revoke(ENDPOINT_CPTR, 0), Ok(status::OK)) {
        return Err((Stage::Grant, 5));
    }
    Ok(true)
}

/// A package whose signature verified under one of [`TRUSTED_PUBLISHERS`]. Only [`verify_package`]
/// constructs one, which is what lets [`run_probe`] be safe, and what keeps unauthenticated
/// bytes away from the manifest parser.
pub struct VerifiedPackage {
    manifest_bytes: &'static [u8],
    cwasm_bytes: &'static [u8],
}

impl VerifiedPackage {
    /// What this package's signed manifest requests, in `open(slot)` order.
    pub fn plan(&self) -> StageResult<GrantPlan> {
        lantern_sdk::parse_bytes(self.manifest_bytes).map(|m| m.plan()).map_err(|_| (Stage::Manifest, 1))
    }
}

/// Read the launcher's `.lpkg` at [`PACKAGE_VADDR`] and verify it under
/// [`TRUSTED_PUBLISHERS`].
///
/// First, a self-check: a copy with one `.cwasm` byte flipped must be **rejected**. A
/// broken verifier that accepted everything would otherwise pass this demo just as well
/// as a working one. The copy costs one `.cwasm` of heap, which never frees.
pub fn verify_package(package_len: usize) -> StageResult<VerifiedPackage> {
    if package_len == 0 || package_len > PACKAGE_MAX_LEN {
        return Err((Stage::Package, 1));
    }
    // SAFETY: the loader mapped `PACKAGE_MAX_LEN` bytes read-only at `PACKAGE_VADDR` for
    // this program's whole life (`launch::map_package`), and nothing maps over it.
    let bytes: &'static [u8] = unsafe { core::slice::from_raw_parts(PACKAGE_VADDR as *const u8, package_len) };
    let package = lantern_sdk::package::decode_package_ref(bytes).map_err(|_| (Stage::Package, 2))?;

    let mut tampered: Vec<u8> = package.cwasm_bytes.to_vec();
    if let Some(byte) = tampered.last_mut() {
        *byte ^= 1;
    }
    let forged = lantern_sdk::package::PackageRef { cwasm_bytes: &tampered, ..package };
    if TRUSTED_PUBLISHERS.iter().any(|key| forged.verify(key).is_ok()) {
        return Err((Stage::Package, 3));
    }

    if !TRUSTED_PUBLISHERS.iter().any(|key| package.verify(key).is_ok()) {
        return Err((Stage::Package, 4));
    }
    Ok(VerifiedPackage { manifest_bytes: package.manifest_bytes, cwasm_bytes: package.cwasm_bytes })
}

/// Deserialize `package`'s `.cwasm`, link exactly what `manifest` declares, instantiate
/// against `state` with [`DEFAULT_FUEL`], and call the guest's `probe: func() -> string`
/// export. If its report passes `checks`, have the grant revoked and call it again.
pub fn run_probe(package: VerifiedPackage, manifest: &GrantManifest, state: RuntimeState, checks: ProbeChecks) -> StageResult<()> {
    let engine = runtime_engine();
    // SAFETY: `VerifiedPackage` exists only for bytes whose package signature verified
    // under `TRUSTED_PUBLISHERS` (`verify_package`) — `deserialize_trusted_component`'s
    // contract, the `.lpkg` case its own doc names.
    let component = unsafe { deserialize_trusted_component(&engine, package.cwasm_bytes) }.map_err(|_| (Stage::Deserialize, 0))?;

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
    check_report(&report, checks.required)?;

    revoke_during_open_request(checks.open_op)?;

    let (report,) = probe.call(&mut store, ()).map_err(|_| (Stage::Call, 1))?;
    if report.starts_with("error: ") && report.contains(checks.refused) {
        Ok(())
    } else {
        Err((Stage::Revocation, 3))
    }
}

/// Leaves a request open at the service, which is then waiting on this client's next chunk, and
/// has `grant-control` revoke the grant. The service must serve that `REVOKE` during the wait, or
/// `grant-control` never finishes and this never wakes: a client mustn't be able to hold off its
/// own revocation this way. The request must then end `ACCESS`.
fn revoke_during_open_request(op: u16) -> StageResult<()> {
    if send_empty_chunk(op, FLAG_MORE)? != status::OK {
        return Err((Stage::Revocation, 1));
    }
    sys::signal(REVOKE_REQUEST_CPTR).map_err(|_| (Stage::Revocation, 2))?;
    sys::wait(REVOKE_DONE_CPTR).map_err(|_| (Stage::Revocation, 2))?;
    match send_empty_chunk(op, 0)? {
        status::ACCESS => Ok(()),
        status => Err((Stage::Revocation, 0x100 | status as usize)),
    }
}

/// One request chunk with no payload, by hand: `Channel::call` can't stop between chunks.
fn send_empty_chunk(op: u16, flags: u16) -> StageResult<u16> {
    let header = RequestHeader { op, flags, arg_len: 0, offset: 0 }.to_bytes();
    // SAFETY: the loader mapped the shared Frame read/write at FRAME_VADDR for this program's
    // whole life, and nothing else in this single-threaded program is using it right now.
    unsafe { core::ptr::copy_nonoverlapping(header.as_ptr(), FRAME_VADDR as *mut u8, header.len()) };
    let (_, tag) = sys::call_with_label(DEST_CPTR, op as u32, [0, 0, 0]).map_err(|_| (Stage::Revocation, 1))?;
    Ok(tag.label as u16)
}

/// The guest's report must start `ok: ` and contain every `required` marker; detail is
/// the index of the first one missing (`0` for the `ok: ` prefix itself).
fn check_report(report: &str, required: &[&str]) -> StageResult<()> {
    if !report.starts_with("ok: ") {
        return Err((Stage::Verdict, 0));
    }
    match required.iter().position(|marker| !report.contains(marker)) {
        Some(i) => Err((Stage::Verdict, i + 1)),
        None => Ok(()),
    }
}

/// `Signal` with a [`Stage`] in `a1` and `detail` in `a2`.
fn signal_with(notification: usize, stage: Stage, detail: usize) {
    let _ = sys::signal_with(notification, stage as usize, detail);
}
