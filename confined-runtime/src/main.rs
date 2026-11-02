//! `lantern-confined-runtime` — one binary for both integration proofs (see the crate doc in
//! `lib.rs`). What it hosts, and how, comes from the guest's signed package:
//!
//! 1. Verify the guest's `.lpkg` the launcher mapped (see `lib.rs`).
//! 2. Read its manifest, and refuse any request this process can't wire.
//! 3. Request the one grant from the service at `ENDPOINT_CPTR`.
//! 4. Back the declared interface with that grant, at slot 0.
//! 5. Run the guest's `probe`; its report must start `ok: ` and pass that interface's checks.
//! 6. Signal `SUCCESS` or `FAILURE`.
//!
//! **`keystore`** (`confined-probe-guest`): [`IpcKeystore`] over the shared `Frame` to a
//! separately confined `keystore-service`. An ENCRYPT on that SIGN-only grant must come back
//! `ACCESS` however much the manifest asked for: the keystore-service, not this process and
//! not the manifest, decides.
//!
//! **`filesystem`** (`confined-fs-guest`): [`IpcFilesystem`] over the shared `Frame` to a
//! separately confined `store-service`, which encrypts every block through *its own* grant
//! on a third confined program, the `keystore-service`
//! (`lantern_filesystem::cipher::ChannelCipher`). So the guest's bytes are sealed at rest by
//! a key that neither this process nor the guest can name.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use lantern_confined_runtime::{
    check_report, request_grant, run_and_report, run_probe, verify_package, Stage, StageResult, VerifiedPackage,
    DEST_CPTR, FRAME_VADDR,
};
use lantern_crypto::{KeyId, KeystoreError};
use lantern_filesystem::FileId;
use lantern_runtime::{GrantManifest, HostCapability, HostFile, IpcFilesystem, IpcKeystore, KeystoreService, RuntimeState};
use lantern_sdk::plan::ResourceRequest;

lantern_abi::entry!(run);

/// `arg0`: the length of the guest's `.lpkg` the launcher mapped at `PACKAGE_VADDR`.
fn run(arg0: usize) -> ! {
    run_and_report(arg0, host_the_guest)
}

fn host_the_guest(package_len: usize) -> StageResult<()> {
    let package = verify_package(package_len)?;
    let plan = package.plan()?;

    // `run_probe` traps any import nothing linked, which would turn RFC-0015's "refused
    // link-scoped facility fails to instantiate" into a trap mid-run. Refuse it here.
    if plan.monotonic_clock.is_some() {
        return Err((Stage::Manifest, 4));
    }
    match (plan.keystore.as_slice(), plan.filesystem.as_slice()) {
        ([], []) => Err((Stage::Manifest, 2)),
        (keys, []) => host_keystore(package, keys),
        ([], files) => host_filesystem(package, files),
        _ => Err((Stage::Manifest, 3)),
    }
}

/// Positional with holes (RFC-0015): every declared role keeps its `open(slot)` index. This
/// process holds one grant, which backs slot 0. Later roles read `none`, as declined ones do.
fn slots<T>(declared: usize, grant: impl Fn() -> T) -> Vec<Option<T>> {
    (0..declared).map(|slot| (slot == 0).then(&grant)).collect()
}

fn host_keystore(package: VerifiedPackage, requests: &[ResourceRequest]) -> StageResult<()> {
    request_grant()?;

    // SAFETY: the loader mapped the shared Frame read/write at FRAME_VADDR, in this
    // program's own VSpace only alongside the keystore-service's, for this program's life.
    let keystore = unsafe { IpcKeystore::new(DEST_CPTR, FRAME_VADDR as *mut u8) };
    // `IpcKeystore` routes by the kernel-delivered badge, never by these (see
    // `HostCapability::keystore_key`'s doc).
    let key = KeyId::from_raw(0);

    let mut buffer = *b"not granted";
    match keystore.encrypt(0, key, &[0u8; lantern_crypto::aead::NONCE_LEN], b"", &mut buffer) {
        Err(KeystoreError::RemoteDenied(lantern_crypto::wire::status::ACCESS)) => {}
        Err(KeystoreError::RemoteDenied(status)) => return Err((Stage::Attenuation, status as usize)),
        Err(_) => return Err((Stage::Attenuation, 0x100)),
        Ok(_) => return Err((Stage::Attenuation, 0x200)),
    }

    let grants = || GrantManifest {
        keystore_keys: slots(requests.len(), || HostCapability::keystore_key(0, key)),
        ..Default::default()
    };
    let state = RuntimeState::new(grants()).with_keystore(Box::new(keystore));
    let report = run_probe(package, &grants(), state)?;
    check_report(&report, &["keystore.open(1)=none"])
}

fn host_filesystem(package: VerifiedPackage, requests: &[ResourceRequest]) -> StageResult<()> {
    request_grant()?;

    // SAFETY: the loader mapped the shared Frame read/write at FRAME_VADDR, in this
    // program's own VSpace only alongside the store-service's, for this program's life.
    let filesystem = unsafe { IpcFilesystem::new(DEST_CPTR, FRAME_VADDR as *mut u8) };
    // `IpcFilesystem` routes by the kernel-delivered badge, never by these (see
    // `FileId::from_raw`'s doc).
    let file = FileId::from_raw(0);

    let grants = || GrantManifest {
        filesystem_files: slots(requests.len(), || HostFile::filesystem_file(0, file)),
        ..Default::default()
    };
    let state = RuntimeState::new(grants()).with_filesystem(Box::new(filesystem));
    let report = run_probe(package, &grants(), state)?;
    check_report(&report, &["oversized write=invalid", "content intact", "filesystem.open(1)=none"])
}
