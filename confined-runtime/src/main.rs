//! `lantern-confined-runtime` — one binary for both integration proofs (see the crate doc in
//! `lib.rs`). What it hosts, and how, comes from the guest's signed package:
//!
//! 1. Verify the guest's `.lpkg` the launcher mapped (see `lib.rs`).
//! 2. Read its manifest, and refuse any request this process can't wire.
//! 3. Ask the launch binder for slot 0 of the declared interface.
//! 4. Back that slot with whatever came back: a grant, or a hole if declined.
//! 5. Run the guest's `probe`; its report must start `ok: ` and pass that interface's checks.
//! 6. Have the grant revoked with a request left open, and run `probe` again; it must report
//!    the refusal (RFC-0021).
//! 7. Signal `SUCCESS` or `FAILURE`.
//!
//! **`keystore`** (`confined-probe-guest`): [`IpcKeystore`] over the shared `Frame` to a
//! separately confined `keystore-service`. An ENCRYPT on that SIGN-only grant must come back
//! `ACCESS`: the keystore-service, not this process and not the manifest, decides.
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

use lantern_abi::grant::{self, INTERFACE_FILESYSTEM, INTERFACE_IDENTITY, INTERFACE_INFERENCE, INTERFACE_KEYSTORE};
use lantern_abi::launcher::{channel_vaddr, interface_bit, is_probe, Interfaces};
use lantern_confined_runtime::{
    check_clean, request_grant, run_and_report, run_app, run_probe, verify_package, ProbeChecks, Stage, StageResult,
    VerifiedPackage, APP_DEST_BASE, DEST_CPTR, ENDPOINT_CPTR, FRAME_VADDR,
};
use lantern_crypto::{KeyId, KeystoreError};
use lantern_filesystem::FileId;
use lantern_runtime::{
    GrantManifest, HostCapability, HostContext, HostFile, HostModel, IpcFilesystem, IpcIdentity, IpcInference, IpcKeystore,
    KeystoreService, RuntimeState,
};
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
    let mut interfaces: Interfaces = 0;
    for (requests, interface) in [
        (&plan.keystore, INTERFACE_KEYSTORE),
        (&plan.filesystem, INTERFACE_FILESYSTEM),
        (&plan.inference, INTERFACE_INFERENCE),
        (&plan.identity, INTERFACE_IDENTITY),
    ] {
        if !requests.is_empty() {
            interfaces |= interface_bit(interface);
        }
    }
    if interfaces == 0 {
        return Err((Stage::Manifest, 2));
    }
    // The launcher mapped a channel for each interface the manifest asks for, where `channel_vaddr` says: each must be
    // clean before it's used.
    for interface in [INTERFACE_KEYSTORE, INTERFACE_FILESYSTEM, INTERFACE_INFERENCE, INTERFACE_IDENTITY] {
        if interfaces & interface_bit(interface) != 0 {
            // SAFETY: the launcher mapped this interface's channel there, from the same verified manifest, and nothing
            // has used it yet.
            unsafe { check_clean(channel_vaddr(interfaces, interface)) }?;
        }
    }
    if !is_probe(interfaces) {
        return host_app(package, &plan, interfaces);
    }
    match (plan.keystore.as_slice(), plan.filesystem.as_slice()) {
        (keys, []) => host_keystore(package, keys),
        (_, files) => host_filesystem(package, files),
    }
}

/// [RFC-0034](../../../lantern-rfcs/rfcs/0034-local-inference-and-a-file-assistant.md): an app, not a probe. Every role it
/// declares is asked for in turn, each landing in its own slot from `APP_DEST_BASE`; a declined one reads `none`. Then its
/// `run` export runs once. The keystore isn't wired for apps yet, so an app asking for it is refused.
fn host_app(package: VerifiedPackage, plan: &lantern_sdk::GrantPlan, interfaces: Interfaces) -> StageResult<()> {
    if !plan.keystore.is_empty() {
        return Err((Stage::Manifest, 3));
    }
    let mut next = APP_DEST_BASE;
    let mut bind = |interface: usize, slot: usize| -> StageResult<Option<u64>> {
        let dest = next;
        next += 1;
        let granted = grant::bind(ENDPOINT_CPTR, dest, interface, slot).map_err(|_| (Stage::Grant, 1))?;
        Ok(granted.then_some(dest as u64))
    };
    // Routed by badge, which is the slot each badged endpoint landed in, never the file's own id.
    let mut files = Vec::new();
    for slot in 0..plan.filesystem.len() {
        files.push(bind(INTERFACE_FILESYSTEM, slot)?.map(|dest| HostFile::filesystem_file(dest, FileId::from_raw(0))));
    }
    let mut models = Vec::new();
    for slot in 0..plan.inference.len() {
        models.push(bind(INTERFACE_INFERENCE, slot)?.map(HostModel::inference_model));
    }
    let mut contexts = Vec::new();
    for slot in 0..plan.identity.len() {
        contexts.push(bind(INTERFACE_IDENTITY, slot)?.map(HostContext::identity_context));
    }
    let grants = || GrantManifest {
        filesystem_files: files.clone(),
        inference_models: models.clone(),
        identity_contexts: contexts.clone(),
        ..Default::default()
    };
    let mut state = RuntimeState::new(grants());
    if interfaces & interface_bit(INTERFACE_FILESYSTEM) != 0 {
        // SAFETY: the launcher mapped this app's channel to the store there, for its whole life, and every file handle's
        // badge is a slot `bind` filled with a badged endpoint to that store.
        let fs = unsafe { IpcFilesystem::routed(channel_vaddr(interfaces, INTERFACE_FILESYSTEM) as *mut u8) };
        state = state.with_filesystem(Box::new(fs));
    }
    if interfaces & interface_bit(INTERFACE_INFERENCE) != 0 {
        // SAFETY: as above, for the inference service's channel.
        let model = unsafe { IpcInference::new(channel_vaddr(interfaces, INTERFACE_INFERENCE) as *mut u8) };
        state = state.with_inference(Box::new(model));
    }
    if interfaces & interface_bit(INTERFACE_IDENTITY) != 0 {
        // SAFETY: as above, for the wallet's channel.
        let wallet = unsafe { IpcIdentity::new(channel_vaddr(interfaces, INTERFACE_IDENTITY) as *mut u8) };
        state = state.with_identity(Box::new(wallet));
    }
    run_app(package, &grants(), state)
}

/// Positional with holes (RFC-0015): every declared role keeps its `open(slot)` index. This
/// process holds at most one grant, which backs slot 0. Later roles read `none`, as declined
/// ones do.
fn slots<T>(declared: usize, granted: bool, grant: impl Fn() -> T) -> Vec<Option<T>> {
    (0..declared).map(|slot| (granted && slot == 0).then(&grant)).collect()
}

fn host_keystore(package: VerifiedPackage, requests: &[ResourceRequest]) -> StageResult<()> {
    let granted = request_grant(INTERFACE_KEYSTORE)?;

    // SAFETY: the loader mapped the shared Frame read/write at FRAME_VADDR, in this
    // program's own VSpace only alongside the keystore-service's, for this program's life.
    let keystore = unsafe { IpcKeystore::new(DEST_CPTR, FRAME_VADDR as *mut u8) };
    // `IpcKeystore` routes by the kernel-delivered badge, never by these (see
    // `HostCapability::keystore_key`'s doc).
    let key = KeyId::from_raw(0);

    if granted {
        let mut buffer = *b"not granted";
        match keystore.encrypt(0, key, &[0u8; lantern_crypto::aead::NONCE_LEN], b"", &mut buffer) {
            Err(KeystoreError::RemoteDenied(lantern_crypto::wire::status::ACCESS)) => {}
            Err(KeystoreError::RemoteDenied(status)) => return Err((Stage::Attenuation, status as usize)),
            Err(_) => return Err((Stage::Attenuation, 0x100)),
            Ok(_) => return Err((Stage::Attenuation, 0x200)),
        }
    }

    let grants = || GrantManifest {
        keystore_keys: slots(requests.len(), granted, || HostCapability::keystore_key(0, key)),
        ..Default::default()
    };
    let state = RuntimeState::new(grants()).with_keystore(Box::new(keystore));
    let checks = ProbeChecks {
        required: &["keystore.open(1)=none"],
        open_op: lantern_crypto::wire::OP_SIGN,
        refused: "keystore denied",
    };
    run_probe(package, &grants(), state, checks)
}

fn host_filesystem(package: VerifiedPackage, requests: &[ResourceRequest]) -> StageResult<()> {
    let granted = request_grant(INTERFACE_FILESYSTEM)?;

    // SAFETY: the loader mapped the shared Frame read/write at FRAME_VADDR, in this
    // program's own VSpace only alongside the store-service's, for this program's life.
    let filesystem = unsafe { IpcFilesystem::new(DEST_CPTR, FRAME_VADDR as *mut u8) };
    // `IpcFilesystem` routes by the kernel-delivered badge, never by these (see
    // `FileId::from_raw`'s doc).
    let file = FileId::from_raw(0);

    let grants = || GrantManifest {
        filesystem_files: slots(requests.len(), granted, || HostFile::filesystem_file(0, file)),
        ..Default::default()
    };
    let state = RuntimeState::new(grants()).with_filesystem(Box::new(filesystem));
    let checks = ProbeChecks {
        required: &["oversized write=invalid", "content intact", "filesystem.open(1)=none"],
        open_op: lantern_filesystem::wire::OP_READ,
        refused: "\"access\"",
    };
    run_probe(package, &grants(), state, checks)
}
