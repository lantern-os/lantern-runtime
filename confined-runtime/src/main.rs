//! The confined `lantern-runtime` process — [RFC-0018](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0018-confined-execution-port.md)'s
//! integration proof. Everything RFC-0018 split into Parts 1–3, together in one real
//! U-mode program under the real kernel:
//!
//! - **Part 3**: Wasmtime `no_std` + Pulley, with Wasm linear memory and code backed by
//!   `FrameMega`s this program maps itself (`lantern_runtime::platform`, granted by
//!   `lantern-boot`'s `ArenaGrant`), and fuel metering on.
//! - **Part 2**: the guest's `lantern:host/keystore` grant is backed by
//!   [`IpcKeystore`] — RFC-0019 requests over a real shared `Frame` to a separately
//!   confined `keystore-service`, not an in-process `Keystore`.
//! - **Part 1**: that `keystore-service` is its own confined program; this process holds
//!   only the badged endpoint capability it was handed over IPC, scoped to SIGN on one key.
//!
//! The guest is `../confined-probe-guest` (real Rust, `wasm32-wasip2`, precompiled to
//! `pulley64` by this crate's own compiler role), embedded below. Its `probe` export signs
//! a message through the granted key and checks that an ungranted slot reads `none`.
//!
//! Steps, in order:
//!
//! 1. `Call` the keystore-service to be granted a badged endpoint (`keystore-client`'s
//!    convention; stands in for the launch-binder flow, RFC-0015/`lantern-shell`).
//! 2. **Attenuation check, host side**: an ENCRYPT over the same `IpcKeystore` must come
//!    back `ACCESS` — the badge is SIGN-only, and the keystore-service, not this process,
//!    is what enforces it.
//! 3. Deserialize, link (only `keystore`, from the [`GrantManifest`]), instantiate, and
//!    call the guest's `probe`; its report must start `ok: ` and show slot 1 as `none`.
//! 4. Signal `SUCCESS` or `FAILURE`.
//!
//! **Diagnostics**: every `Signal` this program sends also carries a [`Stage`] code in
//! `a1` and a detail word in `a2` (heap bytes used, on success). The kernel ignores both;
//! `lantern-boot`'s runtime-demo trap handler prints them. There is no console syscall,
//! and a confined program's only output channel is a capability it was granted.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;

use lantern_abi::sys;
use lantern_abi::wire::{syscall, MessageTag};
use lantern_crypto::{KeyId, KeystoreError};
use lantern_runtime::{
    build_linker, deserialize_trusted_component, runtime_engine, GrantManifest, HostCapability,
    IpcKeystore, KeystoreService, RuntimeState, DEFAULT_FUEL,
};

lantern_abi::entry!(run);

/// `confined-probe-guest`, precompiled for `pulley64` by `lantern-runtime`'s compiler role
/// (`cargo run --example precompile --features compiler`). Embedded: this process has no
/// filesystem, and the image is part of what the launcher loads and measures.
const PROBE_CWASM: &[u8] = include_bytes!("../../confined-probe-guest/assets/probe.pulley.cwasm");

/// The keystore-service's endpoint — matches `keystore-service`'s own `ENDPOINT_CPTR`.
const ENDPOINT_CPTR: usize = 1;
/// Where the keystore-service's granted, badged copy lands (the reply-leg slot).
const DEST_CPTR: usize = 2;
/// Proof notifications — matches `lantern-boot/src/runtime_demo/loader.rs`.
const SUCCESS_CPTR: usize = 3;
const FAILURE_CPTR: usize = 4;
// Slots 6.. hold the `ArenaGrant` (`lantern_runtime::platform`'s `SELF_VSPACE_CPTR`/
// `ARENA_FRAME_CPTR_BASE`); this file never names them itself.

/// Where the loader mapped this program's half of the shared `Frame` — must match
/// `keystore-service`'s own `FRAME_VADDR`.
const FRAME_VADDR: usize = 0x9000_0000;

/// Heap for `lantern-abi`'s bump allocator: Wasmtime's `Engine`/`Component`/`Store`
/// bookkeeping and Pulley's interpreter stack. Must equal `lantern_boot::launch::HEAP_VADDR`,
/// sized by the loader's `heap_megapages`. One `FrameMega`: measured under QEMU, a full run
/// of `confined-probe-guest` peaks at ~640 KiB (the bump allocator never frees, so that is
/// the whole run's total), reported back in the `SUCCESS` signal's detail word.
const HEAP_BASE: usize = 0x8620_0000;
const HEAP_LEN: usize = 0x20_0000;

/// What a `Signal`'s `a1` reports — see the module doc.
#[derive(Clone, Copy)]
#[repr(usize)]
enum Stage {
    Done = 0,
    Grant = 1,
    Attenuation = 2,
    Deserialize = 3,
    Link = 4,
    Instantiate = 5,
    Lookup = 6,
    Call = 7,
    Verdict = 8,
}

fn run(_arg0: usize) -> ! {
    // SAFETY: the loader mapped `HEAP_BASE..+HEAP_LEN` read/write into this program's own
    // VSpace before its first instruction ran (`ProgramSpec::heap_megapages`).
    unsafe { lantern_abi::rt::init_heap(HEAP_BASE, HEAP_LEN) };
    lantern_abi::rt::report_panics_via(FAILURE_CPTR);

    let (cptr, stage, detail) = match host_the_guest() {
        // `heap_stats().0` is the bump pointer (an address), not a byte count.
        Ok(()) => (SUCCESS_CPTR, Stage::Done, lantern_abi::rt::heap_stats().0 - HEAP_BASE),
        Err((stage, detail)) => (FAILURE_CPTR, stage, detail),
    };
    signal_with(cptr, stage, detail);

    loop {
        core::hint::spin_loop();
    }
}

fn host_the_guest() -> Result<(), (Stage, usize)> {
    // 1. Ask for access; the badged endpoint arrives in DEST_CPTR.
    sys::call_with_reply_slot(ENDPOINT_CPTR, DEST_CPTR, [0, 0]).map_err(|_| (Stage::Grant, 0))?;

    // SAFETY: the loader mapped the shared Frame read/write at FRAME_VADDR, in this
    // program's own VSpace only alongside the keystore-service's, for this program's life.
    let keystore = unsafe { IpcKeystore::new(DEST_CPTR, FRAME_VADDR as *mut u8) };
    // `IpcKeystore` routes by the kernel-delivered badge, never by these (see
    // `HostCapability::keystore_key`'s doc).
    let key = KeyId::from_raw(0);

    // 2. The service, not this process, enforces the SIGN-only scope.
    let mut buffer = *b"not granted";
    match keystore.encrypt(0, key, &[0u8; lantern_crypto::aead::NONCE_LEN], b"", &mut buffer) {
        Err(KeystoreError::RemoteDenied(lantern_crypto::wire::status::ACCESS)) => {}
        Err(KeystoreError::RemoteDenied(status)) => return Err((Stage::Attenuation, status as usize)),
        Err(_) => return Err((Stage::Attenuation, 0x100)),
        Ok(_) => return Err((Stage::Attenuation, 0x200)),
    }

    // 3. Host the guest. Slot 0 is the one grant; slot 1 is deliberately absent.
    let engine = runtime_engine();
    // SAFETY: `PROBE_CWASM` is a build-time constant produced by this repo's own trusted
    // compiler role, embedded in the image the launcher loaded — the "trusted bytes"
    // contract `Component::deserialize` requires. (A real deployment verifies a signed
    // `.lpkg` first, `load_verified_component`.)
    let component = unsafe { deserialize_trusted_component(&engine, PROBE_CWASM) }
        .map_err(|_| (Stage::Deserialize, 0))?;

    let manifest = GrantManifest {
        keystore_keys: vec![Some(HostCapability::keystore_key(0, key))],
        ..Default::default()
    };
    let mut linker = build_linker(&engine, &manifest).map_err(|_| (Stage::Link, 0))?;
    // `std` `wasm32-wasip2` startup imports (`wasi:cli/*`, `wasi:io/*`) the guest never
    // calls: trap stubs, not WASI. Same as the host-side test of this guest.
    linker.define_unknown_imports_as_traps(&component).map_err(|_| (Stage::Link, 1))?;

    let state = RuntimeState::new(manifest).with_keystore(Box::new(keystore));
    let mut store = wasmtime::Store::new(&engine, state);
    store.set_fuel(DEFAULT_FUEL).map_err(|_| (Stage::Instantiate, 0))?;
    let instance = linker.instantiate(&mut store, &component).map_err(|_| (Stage::Instantiate, 1))?;

    let probe = instance
        .get_typed_func::<(), (String,)>(&mut store, "probe")
        .map_err(|_| (Stage::Lookup, 0))?;
    let (report,) = probe.call(&mut store, ()).map_err(|_| (Stage::Call, 0))?;

    if !report.starts_with("ok: ") {
        return Err((Stage::Verdict, 0));
    }
    if !report.contains("keystore.open(1)=none") {
        return Err((Stage::Verdict, 1));
    }
    Ok(())
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
