//! `lantern-confined-runtime` — the **keystore** integration proof (see the crate doc in
//! `lib.rs` for what both binaries share). Hosts `../confined-probe-guest`, whose `probe`
//! export signs a message through `keystore` slot 0 and checks that slot 1 reads `none`.
//! The grant behind slot 0 is [`IpcKeystore`] over the shared `Frame` to a separately
//! confined `keystore-service`, scoped to SIGN on one key.
//!
//! Steps, in order:
//!
//! 1. Request the grant from the keystore-service.
//! 2. **Attenuation check, host side**: an ENCRYPT over the same `IpcKeystore` must come
//!    back `ACCESS` — the badge is SIGN-only, and the keystore-service, not this process,
//!    is what enforces it.
//! 3. Run the guest's `probe`; its report must start `ok: ` and show slot 1 as `none`.
//! 4. Signal `SUCCESS` or `FAILURE`.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;

use lantern_confined_runtime::{
    check_report, request_grant, run_and_report, run_probe, Stage, StageResult, DEST_CPTR, FRAME_VADDR,
};
use lantern_crypto::{KeyId, KeystoreError};
use lantern_runtime::{GrantManifest, HostCapability, IpcKeystore, KeystoreService, RuntimeState};

lantern_abi::entry!(run);

/// `confined-probe-guest`, precompiled for `pulley64` by `lantern-runtime`'s compiler role
/// (`cargo run --example precompile --features compiler`). Embedded: this process has no
/// filesystem, and the image is part of what the launcher loads and measures.
const PROBE_CWASM: &[u8] = include_bytes!("../../confined-probe-guest/assets/probe.pulley.cwasm");

fn run(_arg0: usize) -> ! {
    run_and_report(host_the_guest)
}

fn host_the_guest() -> StageResult<()> {
    request_grant()?;

    // SAFETY: the loader mapped the shared Frame read/write at FRAME_VADDR, in this
    // program's own VSpace only alongside the keystore-service's, for this program's life.
    let keystore = unsafe { IpcKeystore::new(DEST_CPTR, FRAME_VADDR as *mut u8) };
    // `IpcKeystore` routes by the kernel-delivered badge, never by these (see
    // `HostCapability::keystore_key`'s doc).
    let key = KeyId::from_raw(0);

    // The service, not this process, enforces the SIGN-only scope.
    let mut buffer = *b"not granted";
    match keystore.encrypt(0, key, &[0u8; lantern_crypto::aead::NONCE_LEN], b"", &mut buffer) {
        Err(KeystoreError::RemoteDenied(lantern_crypto::wire::status::ACCESS)) => {}
        Err(KeystoreError::RemoteDenied(status)) => return Err((Stage::Attenuation, status as usize)),
        Err(_) => return Err((Stage::Attenuation, 0x100)),
        Ok(_) => return Err((Stage::Attenuation, 0x200)),
    }

    // Slot 0 is the one grant; slot 1 is deliberately absent.
    let grants = || GrantManifest {
        keystore_keys: vec![Some(HostCapability::keystore_key(0, key))],
        ..Default::default()
    };
    let state = RuntimeState::new(grants()).with_keystore(Box::new(keystore));
    // SAFETY: `PROBE_CWASM` is this repo's own trusted compiler-role output.
    let report = unsafe { run_probe(PROBE_CWASM, &grants(), state) }?;
    check_report(&report, &["keystore.open(1)=none"])
}
