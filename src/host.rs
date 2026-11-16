//! The WIT-handle ⇄ capability mapping
//! ([RFC-0014](../https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0014-wit-handle-capability-mapping.md)/
//! [ADR-0018](../https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0018-wit-handle-capability-mapping.md)): how a Wasm
//! component's WIT-typed imports become LanternOS object capabilities.
//!
//! Two mapping shapes (`wit/host.wit`):
//!
//! - **Resource-scoped** — [`keystore`] (RFC-0014) and [`filesystem`]
//!   (RFC-0016/ADR-0019). Each handle is backed by one host record (a service badge + an
//!   object id — a [`HostCapability`] for a key, a [`HostFile`] for a file) held in a
//!   Wasmtime [`ResourceTable`]. Methods forward to the owning service, which re-checks
//!   the badge on every call; a denied/revoked/wrong-object badge surfaces as the
//!   interface's own `error-code::access`, relayed verbatim from the service's own
//!   deny-by-default check. This module never adds a capability check of its own.
//! - **Link-scoped** — [`monotonic_clock`]. No per-call object to scope (the functions
//!   take no arguments), so the grant is a single yes/no: [`build_linker`] either links
//!   the whole interface or leaves it unlinked, and a component that imports an unlinked
//!   interface fails to instantiate.
//!
//! **Handles are never manufactured in-guest.** Every [`ResourceTable`] entry exists
//! because the capability manifest ([`GrantManifest`] — the runtime-side contract
//! RFC-0014 fixes; the file format is `lantern-sdk`'s, not yet designed) named it before
//! the component started. `keystore.open(slot)` / `filesystem.open(slot)` only ever
//! return a handle for a slot the manifest filled — `slot` indexes an explicit grant
//! list, not an ambient namespace, and `filesystem` has no path or directory namespace
//! at all (ADR-0019).
//!
//! **Prototype boundary.** RFC-0014/RFC-0016 assume the crypto and store services are
//! IPC-reachable confined processes — they are now (`lantern-boot`'s `keystore-service`/
//! `store-service`), and [`IpcKeystore`]/[`IpcFilesystem`] reach them for real over
//! [`lantern_abi::frame::Channel`], RFC-0018 Part 2's actual transport, alongside the
//! in-process stand-ins ([`InProcessFilesystem`], and `lantern_crypto::Keystore`'s own
//! direct [`KeystoreService`] impl) every test in this crate still uses. This crate also
//! runs confined itself: its `no_std`/`riscv64` build (`Cargo.toml`'s `confined` feature,
//! [`crate::platform`]) is what `confined-runtime/` links, and that one binary runs
//! `IpcKeystore` against a real, separately confined `keystore-service`
//! (`lantern-boot-runtime-demo`) and `IpcFilesystem` against a real, separately confined
//! `store-service` (`lantern-boot-runtime-fs-demo`). The
//! mapping — badge lookup, per-call forwarding, error translation, link-or-refuse — is the
//! same in both builds.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec, vec::Vec};
#[cfg(not(feature = "std"))]
use alloc::string as alloc_string;
#[cfg(feature = "std")]
use std::string as alloc_string;

use wasmtime::component::{Linker, Resource, ResourceTable};
use wasmtime::Engine;

use lantern_crypto::aead::{NONCE_LEN, TAG_LEN};
use lantern_crypto::{KeyId, KeystoreError};
use lantern_filesystem::{FileId, StoreError, MAX_BLOCK_LEN};

wasmtime::component::bindgen!({
    path: "wit",
    world: "app",
    with: {
        // `pkg:ns/interface.resource` — each resource is backed host-side by our own
        // record type, not a bindgen-generated one.
        "lantern:host/keystore.key": HostCapability,
        "lantern:host/filesystem.file": HostFile,
        "lantern:host/inference.model": HostModel,
        "lantern:host/identity.context": HostContext,
    },
});

pub use self::lantern::host::{filesystem, identity, inference, keystore, monotonic_clock};

// -------------------------------------------------------------------------------------
// The host-side capability record (ADR-0018, "the host-side capability record")
// -------------------------------------------------------------------------------------

/// What one resource-scoped WIT handle is backed by, host-side. A guest never sees these
/// fields: Wasmtime's component-model ABI represents the handle as an opaque, per-instance,
/// type-checked index the guest cannot forge into another table entry. This type only
/// fixes what the host stores behind it.
#[derive(Clone, Copy, Debug)]
pub struct HostCapability {
    /// The badge this handle is scoped to — minted by the owning service's `Broker`
    /// ([RFC-0010](../https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0010-cross-process-capability-transfer-and-brokering.md)),
    /// never a raw kernel `CPtr`. A component only ever holds what a service already
    /// narrowed for it.
    badge: u64,
    /// The specific key `badge` names inside the crypto service.
    key: KeyId,
    /// Which service forwards calls on this handle — implicit from the resource type in
    /// practice, kept explicit for clarity and for the day it carries a real IPC endpoint.
    service: ServiceEndpoint,
}

/// The owning service a host record forwards to. A real IPC endpoint capability once the
/// owning services are confined processes (ADR-0018/ADR-0019).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceEndpoint {
    Keystore,
    Filesystem,
}

impl HostCapability {
    /// A capability to one key in the crypto service, scoped to whatever operation
    /// subset the manifest granted for `badge` (the crypto service enforces the subset;
    /// this record does not know it). For an [`IpcKeystore`] backend, `badge`/`key` are
    /// never actually consulted (see that type's own doc) — a caller with no real
    /// `lantern_crypto::Keystore` to mint a `KeyId` from (a confined runtime process holds
    /// a badged `Channel`, not a `Keystore`) can use `KeyId::from_raw` (always panic-safe,
    /// see its own doc) rather than needing one.
    pub fn keystore_key(badge: u64, key: KeyId) -> Self {
        Self { badge, key, service: ServiceEndpoint::Keystore }
    }
}

/// What one `filesystem::file` handle is backed by, host-side — the filesystem twin of
/// [`HostCapability`], a distinct type so a `file` handle can never be type-confused with
/// a `key` handle (R5, ADR-0019). Same shape: a service badge and the object id it names.
#[derive(Clone, Copy, Debug)]
pub struct HostFile {
    /// The badge this handle is scoped to — `Store`-minted, never a raw kernel `CPtr`.
    badge: u64,
    /// The specific file `badge` names inside the store.
    file: FileId,
    /// Which service forwards calls on this handle (always [`ServiceEndpoint::Filesystem`];
    /// kept for symmetry with [`HostCapability`] and the IPC-endpoint future).
    service: ServiceEndpoint,
}

impl HostFile {
    /// A capability to one file in the store, scoped to whatever `FileOps` subset the
    /// manifest granted for `badge` (the store enforces the subset).
    pub fn filesystem_file(badge: u64, file: FileId) -> Self {
        Self { badge, file, service: ServiceEndpoint::Filesystem }
    }
}

// -------------------------------------------------------------------------------------
// The owning crypto service, as the mapping sees it
// -------------------------------------------------------------------------------------

/// What one `inference` `model` handle is backed by (RFC-0034): the badge the binder granted on the inference service.
/// With an [`IpcInference`], the badge is the capability slot that badged endpoint landed in.
#[derive(Clone, Copy, Debug)]
pub struct HostModel {
    badge: u64,
}

impl HostModel {
    pub fn inference_model(badge: u64) -> Self {
        Self { badge }
    }
}

/// What one `identity` `context` handle is backed by (RFC-0035): the badge the binder granted on the wallet, which, with
/// [`IpcIdentity`], is the slot that badged endpoint landed in.
#[derive(Clone, Copy, Debug)]
pub struct HostContext {
    badge: u64,
}

impl HostContext {
    pub fn identity_context(badge: u64) -> Self {
        Self { badge }
    }
}

/// The wallet, as the runtime reaches it. Every call takes the badge, which the wallet re-checks; an error is its
/// RFC-0019 status, or [`lantern_abi::identity::REFUSED`].
pub trait IdentityService: Send + Sync {
    fn connect(&mut self, badge: u64) -> Result<(), u16>;
    fn send(&mut self, badge: u64, message: &[u8]) -> Result<(), u16>;
    fn recv(&mut self, badge: u64) -> Result<Vec<u8>, u16>;
}

/// Why a `generate` failed, as the service said.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InferenceError {
    /// An RFC-0019 status from the service.
    Remote(u16),
    /// The channel to it failed.
    Channel,
}

/// The inference service, as the runtime reaches it. Every call takes the badge, which the service re-checks.
pub trait InferenceService: Send + Sync {
    fn generate(&mut self, badge: u64, prompt: &[u8], max_tokens: usize) -> Result<Vec<u8>, InferenceError>;
}

/// The crypto service reached over (eventually) IPC. Implemented for
/// `lantern_crypto::Keystore` directly today because no confined crypto service exists
/// yet; a test double implements the same trait. Every method takes the badge and
/// re-checks it — the mapping forwards, it does not cache an "already allowed" decision.
pub trait KeystoreService: Send + Sync {
    fn encrypt(
        &self,
        badge: u64,
        key: KeyId,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], KeystoreError>;

    fn decrypt(
        &self,
        badge: u64,
        key: KeyId,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), KeystoreError>;

    fn sign(&self, badge: u64, key: KeyId, message: &[u8]) -> Result<Vec<u8>, KeystoreError>;
}

impl KeystoreService for lantern_crypto::Keystore {
    fn encrypt(
        &self,
        badge: u64,
        key: KeyId,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], KeystoreError> {
        lantern_crypto::Keystore::encrypt(self, badge, key, nonce, aad, buffer)
    }

    fn decrypt(
        &self,
        badge: u64,
        key: KeyId,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), KeystoreError> {
        lantern_crypto::Keystore::decrypt(self, badge, key, nonce, aad, buffer, tag)
    }

    fn sign(&self, badge: u64, key: KeyId, message: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        lantern_crypto::Keystore::sign(self, badge, key, message).map(|s| s.to_vec())
    }
}

/// A single-hart, non-reentrant interior-mutability cell (ADR-0010), used instead of
/// `std::sync::Mutex` so [`IpcKeystore`]/[`IpcFilesystem`] work identically in both this
/// crate's build roles (`std` host, `confined` `riscv64` — `Cargo.toml`'s features) without
/// a second, `std`-only implementation. `core::cell::RefCell` alone isn't `Sync`, which
/// `KeystoreService`/`FilesystemService`'s trait bound requires. Never actually
/// contended in either role: a host `Store<RuntimeState>` embedding is this project's own
/// single-threaded usage; a confined program is genuinely single-hart — the same
/// justification `lantern_abi::frame::Channel`'s own `unsafe impl Send` doc already gives.
struct SingleThreadCell<T>(core::cell::RefCell<T>);

// SAFETY: see the type's own doc.
unsafe impl<T> Sync for SingleThreadCell<T> {}

impl<T> SingleThreadCell<T> {
    fn new(value: T) -> Self {
        Self(core::cell::RefCell::new(value))
    }

    fn borrow_mut(&self) -> core::cell::RefMut<'_, T> {
        self.0.borrow_mut()
    }
}

/// Reaches a real, confined `keystore-service` over one [`lantern_abi::frame::Channel`] —
/// RFC-0018 Part 2's actual IPC transport, replacing the in-process
/// `lantern_crypto::Keystore` impl above once a component runs confined for real. The wire
/// codecs are `lantern_crypto::wire`'s own (already built and unit-tested there, the same
/// ones `lantern-boot`'s `keystore-client` demo uses directly) — this type is just the
/// `KeystoreService` glue around them, mirroring `lantern_filesystem::cipher::ChannelCipher`'s
/// identical shape one layer down.
///
/// [`SingleThreadCell`], not `&mut self`, because [`KeystoreService`]'s methods are `&self`
/// (matching `lantern_crypto::Keystore`'s own shape: one object serving every call) — see
/// that type's own doc for why not `std::sync::Mutex`.
///
/// **v0 scope**: one `IpcKeystore` wraps exactly one granted `(endpoint, Frame)`
/// relationship to one `keystore-service` — matching every real demo built so far
/// (`keystore-client` only ever holds one key). `encrypt`/`decrypt`/`sign`'s `badge`
/// parameter is accepted (the trait requires it) but not used to select between multiple
/// relationships: `RuntimeState` already validated the calling handle against a real
/// granted [`HostCapability`] before reaching here (`keystore_cap`), so forwarding through
/// this component's one `Channel` is correct as long as it was constructed for the one
/// relationship this component was actually granted. A component holding *multiple*
/// distinct keystore relationships (several badged endpoints to the same or different
/// services) needs a per-badge `Channel` lookup instead — not built here, no real grant
/// shape needs it yet.
pub struct IpcKeystore {
    channel: SingleThreadCell<lantern_abi::frame::Channel>,
}

impl IpcKeystore {
    /// # Safety
    /// As [`lantern_abi::frame::Channel::new`]'s: `frame` must point to a live, exclusively
    /// mapped shared `Frame` for as long as this `IpcKeystore` lives.
    pub unsafe fn new(endpoint: lantern_abi::wire::CPtr, frame: *mut u8) -> Self {
        // SAFETY: forwarded from this function's own contract.
        Self { channel: SingleThreadCell::new(unsafe { lantern_abi::frame::Channel::new(endpoint, frame) }) }
    }
}

impl KeystoreService for IpcKeystore {
    fn encrypt(
        &self,
        _badge: u64,
        _key: KeyId,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], KeystoreError> {
        let mut request = vec![0u8; 4 + NONCE_LEN + 4 + aad.len() + buffer.len()];
        let len = lantern_crypto::wire::encode_encrypt_request(nonce, aad, buffer, &mut request)
            .expect("request buffer sized exactly for nonce+aad+plaintext");
        let mut reply = vec![0u8; 4 + TAG_LEN + buffer.len()];
        let mut channel = self.channel.borrow_mut();
        let (status, reply_len) =
            channel.call(lantern_crypto::wire::OP_ENCRYPT, &request[..len], &mut reply).map_err(KeystoreError::Channel)?;
        if status != lantern_crypto::wire::status::OK {
            return Err(KeystoreError::RemoteDenied(status));
        }
        let (tag, ciphertext) = lantern_crypto::wire::decode_encrypt_reply(&reply[..reply_len])
            .ok_or(KeystoreError::Channel(lantern_abi::frame::ChannelError::Malformed))?;
        if ciphertext.len() != buffer.len() {
            return Err(KeystoreError::Channel(lantern_abi::frame::ChannelError::Malformed));
        }
        buffer.copy_from_slice(ciphertext);
        Ok(tag)
    }

    fn decrypt(
        &self,
        _badge: u64,
        _key: KeyId,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), KeystoreError> {
        let mut request = vec![0u8; 4 + NONCE_LEN + 4 + aad.len() + 4 + TAG_LEN + buffer.len()];
        let len = lantern_crypto::wire::encode_decrypt_request(nonce, aad, tag, buffer, &mut request)
            .expect("request buffer sized exactly for nonce+aad+tag+ciphertext");
        let mut reply = vec![0u8; buffer.len()];
        let mut channel = self.channel.borrow_mut();
        let (status, reply_len) =
            channel.call(lantern_crypto::wire::OP_DECRYPT, &request[..len], &mut reply).map_err(KeystoreError::Channel)?;
        if status != lantern_crypto::wire::status::OK {
            return Err(KeystoreError::RemoteDenied(status));
        }
        let plaintext = lantern_crypto::wire::decode_decrypt_reply(&reply[..reply_len]);
        if plaintext.len() != buffer.len() {
            return Err(KeystoreError::Channel(lantern_abi::frame::ChannelError::Malformed));
        }
        buffer.copy_from_slice(plaintext);
        Ok(())
    }

    fn sign(&self, _badge: u64, _key: KeyId, message: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        let request = lantern_crypto::wire::encode_sign_request(message);
        let mut reply = vec![0u8; lantern_crypto::signing::SIGNATURE_LEN];
        let mut channel = self.channel.borrow_mut();
        let (status, reply_len) =
            channel.call(lantern_crypto::wire::OP_SIGN, request, &mut reply).map_err(KeystoreError::Channel)?;
        if status != lantern_crypto::wire::status::OK {
            return Err(KeystoreError::RemoteDenied(status));
        }
        Ok(lantern_crypto::wire::decode_sign_reply(&reply[..reply_len]).to_vec())
    }
}

/// Maps the owning service's own error onto the WIT interface's `error-code`. Denied,
/// revoked, wrong-key, and missing-key all collapse to `access` — deny-by-default, and
/// no distinction is leaked about *why*. Everything else (malformed arguments, a
/// primitive-level authentication failure, a wrong-purpose key) is `invalid`.
/// `RemoteDenied` (an [`IpcKeystore`] call) carries the remote `keystore-service`'s own
/// already-collapsed `wire::status` and maps through the same way, rather than falling
/// into the generic `invalid` bucket every other unmatched variant (including a genuine
/// `Channel` transport failure) does — a denial is a denial regardless of which side of
/// the wire decided it.
fn to_error_code(err: KeystoreError) -> keystore::ErrorCode {
    use KeystoreError::*;
    match err {
        UnknownBadge | BadgeRevoked | OpNotGranted | WrongKey | NoSuchKey | KeyDestroyed => {
            keystore::ErrorCode::Access
        }
        RemoteDenied(status) if status == lantern_crypto::wire::status::ACCESS => keystore::ErrorCode::Access,
        _ => keystore::ErrorCode::Invalid,
    }
}

fn fixed_len<const N: usize>(bytes: &[u8]) -> Result<[u8; N], keystore::ErrorCode> {
    bytes.try_into().map_err(|_| keystore::ErrorCode::Invalid)
}

// -------------------------------------------------------------------------------------
// The owning store, as the mapping sees it (RFC-0016 / ADR-0019)
// -------------------------------------------------------------------------------------

/// The content-addressed store reached over (eventually) IPC. Implemented for
/// [`InProcessFilesystem`] today because no confined store service exists yet; a test
/// double implements the same trait. Every method takes the badge and re-checks it.
///
/// Note `write` takes `&mut self` where every [`KeystoreService`] method was `&self` —
/// the generated `filesystem::HostFile` methods are already `&mut self`, so this is free.
pub trait FilesystemService: Send + Sync {
    fn read(&self, badge: u64, file: FileId, buffer: &mut [u8]) -> Result<usize, StoreError>;
    fn write(&mut self, badge: u64, file: FileId, data: &[u8]) -> Result<(), StoreError>;
}

/// The in-process stand-in: a real `lantern_filesystem::Store` plus the
/// `lantern_crypto::Keystore` its store-wide AEAD key lives in, and the badge/key
/// `Store::read`/`write` need an
/// [`lantern_filesystem::cipher::InProcessCipher`] built from (constructed fresh each
/// call — `Store` itself carries no cipher state of its own, RFC-0018/ADR-0022) —
/// threaded internally so the [`FilesystemService`] signatures stay clean.
pub struct InProcessFilesystem {
    store: lantern_filesystem::Store,
    keystore: lantern_crypto::Keystore,
    aead_badge: u64,
    aead_key: lantern_crypto::KeyId,
}

impl InProcessFilesystem {
    pub fn new(
        store: lantern_filesystem::Store,
        keystore: lantern_crypto::Keystore,
        aead_badge: u64,
        aead_key: lantern_crypto::KeyId,
    ) -> Self {
        Self { store, keystore, aead_badge, aead_key }
    }
}

impl FilesystemService for InProcessFilesystem {
    fn read(&self, badge: u64, file: FileId, buffer: &mut [u8]) -> Result<usize, StoreError> {
        let mut cipher = lantern_filesystem::InProcessCipher::new(&self.keystore, self.aead_badge, self.aead_key);
        self.store.read(&mut cipher, badge, file, buffer)
    }

    fn write(&mut self, badge: u64, file: FileId, data: &[u8]) -> Result<(), StoreError> {
        let mut cipher = lantern_filesystem::InProcessCipher::new(&self.keystore, self.aead_badge, self.aead_key);
        self.store.write(&mut cipher, badge, file, data)
    }
}

/// Reaches a real, confined `store-service` over one [`lantern_abi::frame::Channel`] —
/// RFC-0018 Part 2's actual IPC transport, replacing [`InProcessFilesystem`] once a
/// component runs confined for real. Simpler than [`IpcKeystore`]: `lantern_filesystem::wire`
/// needs no request/reply codecs at all (READ's request is empty, its reply is the raw file
/// bytes; WRITE's request *is* the raw bytes, its reply is header-only — see that module's
/// own doc), so this type calls [`lantern_abi::frame::Channel::call`] directly with the
/// caller's own buffers — no scratch copy, and `Channel::call` chunks transparently past one
/// `Frame` regardless of size, so there is no fixed cap to size a buffer against either.
///
/// Same `SingleThreadCell`-for-`&self` reasoning and the same v0 single-relationship scope as
/// [`IpcKeystore`] — see its doc.
pub struct IpcFilesystem {
    channel: SingleThreadCell<lantern_abi::frame::Channel>,
    /// RFC-0034: with several file grants, each handle's badge is the slot its own badged endpoint landed in, and every
    /// call goes there, over the one channel this app shares with the store.
    frame: *mut u8,
    routed: bool,
}

// SAFETY: as `lantern_abi::frame::Channel`'s own `Send`: a confined program is single-hart, and `frame` is only ever
// used through a `Channel` built from it.
unsafe impl Send for IpcFilesystem {}
// SAFETY: as above; every use goes through `channel`'s `SingleThreadCell`.
unsafe impl Sync for IpcFilesystem {}

impl IpcFilesystem {
    /// # Safety
    /// As [`lantern_abi::frame::Channel::new`]'s.
    pub unsafe fn new(endpoint: lantern_abi::wire::CPtr, frame: *mut u8) -> Self {
        // SAFETY: forwarded from this function's own contract.
        Self { channel: SingleThreadCell::new(unsafe { lantern_abi::frame::Channel::new(endpoint, frame) }), frame, routed: false }
    }

    /// One relationship per file grant, all over the channel at `frame`: each call goes to the endpoint in the slot its
    /// handle's badge names.
    ///
    /// # Safety
    /// As [`new`](Self::new)'s, and every [`HostFile`] badge used with it must be a slot holding a badged endpoint to the
    /// store that serves `frame`.
    pub unsafe fn routed(frame: *mut u8) -> Self {
        // SAFETY: forwarded from this function's own contract; the endpoint is replaced on every call.
        Self { channel: SingleThreadCell::new(unsafe { lantern_abi::frame::Channel::new(0, frame) }), frame, routed: true }
    }

    fn route(&self, badge: u64) {
        if self.routed {
            // SAFETY: `frame` met `routed`'s contract when this was built, and nothing holds the old channel now.
            *self.channel.borrow_mut() = unsafe { lantern_abi::frame::Channel::new(badge as lantern_abi::wire::CPtr, self.frame) };
        }
    }
}

impl FilesystemService for IpcFilesystem {
    fn read(&self, badge: u64, _file: FileId, buffer: &mut [u8]) -> Result<usize, StoreError> {
        self.route(badge);
        let mut channel = self.channel.borrow_mut();
        let (status, len) = channel.call(lantern_filesystem::wire::OP_READ, &[], buffer).map_err(StoreError::Channel)?;
        if status != lantern_filesystem::wire::status::OK {
            return Err(StoreError::RemoteCryptoDenied(status));
        }
        Ok(len)
    }

    fn write(&mut self, badge: u64, _file: FileId, data: &[u8]) -> Result<(), StoreError> {
        self.route(badge);
        let mut channel = self.channel.borrow_mut();
        let (status, _len) = channel.call(lantern_filesystem::wire::OP_WRITE, data, &mut []).map_err(StoreError::Channel)?;
        if status != lantern_filesystem::wire::status::OK {
            return Err(StoreError::RemoteCryptoDenied(status));
        }
        Ok(())
    }
}

/// `StoreError` → the `filesystem` interface's `error-code`. Denied, revoked,
/// wrong-file, and missing-file all collapse to `access` — deny-by-default, no
/// distinction leaked. Malformed sizes and AEAD/kernel failures are `invalid`.
/// ([`StoreError::FileEmpty`] never reaches here — `read` maps it to an empty result.)
fn to_fs_error_code(err: StoreError) -> filesystem::ErrorCode {
    use StoreError::*;
    match err {
        UnknownBadge | BadgeRevoked | OpNotGranted | WrongFile | NoSuchFile | FileDestroyed => {
            filesystem::ErrorCode::Access
        }
        // An `IpcFilesystem` call's remote denial — see `to_error_code`'s identical
        // `RemoteDenied` reasoning, one layer up.
        RemoteCryptoDenied(status) if status == lantern_filesystem::wire::status::ACCESS => filesystem::ErrorCode::Access,
        _ => filesystem::ErrorCode::Invalid,
    }
}

/// Reaches the confined inference service (RFC-0034) over one [`lantern_abi::frame::Channel`]: each call goes to the
/// endpoint in the slot its handle's badge names, as [`IpcFilesystem::routed`] does.
pub struct IpcInference {
    frame: *mut u8,
}

// SAFETY: as `IpcFilesystem`'s.
unsafe impl Send for IpcInference {}
// SAFETY: as `IpcFilesystem`'s; it's only used through `&mut self`.
unsafe impl Sync for IpcInference {}

impl IpcInference {
    /// # Safety
    /// As [`IpcFilesystem::routed`]'s, for the inference service.
    pub unsafe fn new(frame: *mut u8) -> Self {
        Self { frame }
    }
}

impl InferenceService for IpcInference {
    fn generate(&mut self, badge: u64, prompt: &[u8], max_tokens: usize) -> Result<Vec<u8>, InferenceError> {
        // SAFETY: `frame` met `new`'s contract, and no other channel over it is alive.
        let mut channel = unsafe { lantern_abi::frame::Channel::new(badge as lantern_abi::wire::CPtr, self.frame) };
        let mut out = vec![0u8; lantern_abi::inference::MAX_REPLY];
        match lantern_abi::inference::generate(&mut channel, max_tokens, prompt, &mut out) {
            Ok(len) => {
                out.truncate(len);
                Ok(out)
            }
            Err(lantern_abi::inference::GenerateError::Status(status)) => Err(InferenceError::Remote(status)),
            Err(lantern_abi::inference::GenerateError::TooLong) => Err(InferenceError::Remote(lantern_abi::frame::status::INVALID)),
            Err(lantern_abi::inference::GenerateError::Channel(_)) => Err(InferenceError::Channel),
        }
    }
}

/// Reaches the wallet (RFC-0035) over one channel: each call goes to the endpoint in the slot its handle's badge names.
pub struct IpcIdentity {
    frame: *mut u8,
}

// SAFETY: as `IpcFilesystem`'s.
unsafe impl Send for IpcIdentity {}
// SAFETY: as `IpcFilesystem`'s; it's only used through `&mut self`.
unsafe impl Sync for IpcIdentity {}

impl IpcIdentity {
    /// # Safety
    /// As [`IpcFilesystem::routed`]'s, for the wallet.
    pub unsafe fn new(frame: *mut u8) -> Self {
        Self { frame }
    }

    fn channel(&self, badge: u64) -> lantern_abi::frame::Channel {
        // SAFETY: `frame` met `new`'s contract, and no other channel over it is alive.
        unsafe { lantern_abi::frame::Channel::new(badge as lantern_abi::wire::CPtr, self.frame) }
    }
}

fn identity_status(err: lantern_abi::identity::IdentityError) -> u16 {
    match err {
        lantern_abi::identity::IdentityError::Status(s) => s,
        lantern_abi::identity::IdentityError::Channel(_) => lantern_abi::identity::UNREACHABLE,
    }
}

impl IdentityService for IpcIdentity {
    fn connect(&mut self, badge: u64) -> Result<(), u16> {
        lantern_abi::identity::connect(&mut self.channel(badge)).map_err(identity_status)
    }

    fn send(&mut self, badge: u64, message: &[u8]) -> Result<(), u16> {
        lantern_abi::identity::send(&mut self.channel(badge), message).map_err(identity_status)
    }

    fn recv(&mut self, badge: u64) -> Result<Vec<u8>, u16> {
        let mut out = vec![0u8; lantern_abi::identity::MESSAGE_MAX];
        let n = lantern_abi::identity::recv(&mut self.channel(badge), &mut out).map_err(identity_status)?;
        out.truncate(n);
        Ok(out)
    }
}

fn to_identity_error_code(status: u16) -> identity::ErrorCode {
    use lantern_abi::frame::status as s;
    match status {
        s::ACCESS => identity::ErrorCode::Access,
        s::INVALID => identity::ErrorCode::Invalid,
        lantern_abi::identity::REFUSED => identity::ErrorCode::Refused,
        _ => identity::ErrorCode::Unreachable,
    }
}

fn to_inference_error_code(err: InferenceError) -> inference::ErrorCode {
    use lantern_abi::frame::status;
    match err {
        InferenceError::Remote(status::INVALID) => inference::ErrorCode::Invalid,
        InferenceError::Remote(status::FAILED) | InferenceError::Channel => inference::ErrorCode::Failed,
        InferenceError::Remote(_) => inference::ErrorCode::Access,
    }
}

// -------------------------------------------------------------------------------------
// The capability manifest (runtime-side contract only — RFC-0014)
// -------------------------------------------------------------------------------------

/// A link-scoped clock grant: a time source plus the resolution to report for it.
#[derive(Clone, Copy)]
pub struct MonotonicClock {
    /// Nanoseconds since an arbitrary monotonic epoch. Production wiring passes
    /// `<lantern_hal::Hardware as lantern_hal::Hal>::monotonic_time_ns`; the current
    /// host test target has no working HAL clock (the x86-64 impl is an `unimplemented!`
    /// stub), so a host shim stands in there — a `riscv64`-only follow-up.
    pub now_ns: fn() -> u64,
    /// The tick period of `now_ns`, reported by `resolution()`.
    pub resolution_ns: u64,
}

/// The host facilities one component instance was granted. The runtime-side half of the
/// contract RFC-0014 fixes: one [`HostCapability`] per resource-scoped grant, one
/// yes/no per link-scoped facility. The file format a developer authors is
/// `lantern-sdk`'s job, not fixed here.
#[derive(Default)]
pub struct GrantManifest {
    /// Resource-scoped keystore grants, **positional with holes** (RFC-0015/ADR-0020):
    /// slot `n` is `keystore.open(n)`, `None` is a declined-or-unbound role that reads as
    /// `none` just like an un-opened handle. An empty vec means the manifest did not
    /// declare `keystore` at all (the interface is left unlinked); a non-empty vec of all
    /// `None` means it declared roles that were all declined (linked, every `open`
    /// returns `none`).
    pub keystore_keys: Vec<Option<HostCapability>>,
    /// Resource-scoped filesystem grants — same positional-with-holes semantics.
    pub filesystem_files: Vec<Option<HostFile>>,
    /// Resource-scoped inference grants (RFC-0034) — same semantics.
    pub inference_models: Vec<Option<HostModel>>,
    /// Resource-scoped identity grants (RFC-0035) — same semantics.
    pub identity_contexts: Vec<Option<HostContext>>,
    /// Link-scoped: `Some` links `monotonic-clock`; `None` leaves it unlinked, so a
    /// component that imports it fails to instantiate.
    pub monotonic_clock: Option<MonotonicClock>,
}

impl GrantManifest {
    /// A manifest granting nothing — a component importing any host interface fails to
    /// instantiate against it.
    pub fn nothing() -> Self {
        Self::default()
    }
}

// -------------------------------------------------------------------------------------
// Store state + the generated host-trait impls
// -------------------------------------------------------------------------------------

/// The `T` in `Store<T>` for a confined component: the resource table plus the backing
/// objects the manifest's grants resolve to. Build with [`RuntimeState::new`] then the
/// `with_*` methods for whichever services the manifest's resource-scoped grants need.
pub struct RuntimeState {
    table: ResourceTable,
    keys: Vec<Option<HostCapability>>,
    files: Vec<Option<HostFile>>,
    models: Vec<Option<HostModel>>,
    contexts: Vec<Option<HostContext>>,
    keystore: Option<Box<dyn KeystoreService>>,
    filesystem: Option<Box<dyn FilesystemService>>,
    inference: Option<Box<dyn InferenceService>>,
    identity: Option<Box<dyn IdentityService>>,
    clock: Option<MonotonicClock>,
}

impl RuntimeState {
    /// The state for `manifest`, with no service backends attached yet.
    pub fn new(manifest: GrantManifest) -> Self {
        Self {
            table: ResourceTable::new(),
            keys: manifest.keystore_keys,
            files: manifest.filesystem_files,
            models: manifest.inference_models,
            contexts: manifest.identity_contexts,
            keystore: None,
            filesystem: None,
            inference: None,
            identity: None,
            clock: manifest.monotonic_clock,
        }
    }

    /// Attaches the service the resource-scoped `key` handles forward to — required iff
    /// the manifest granted any key. In a real deployment an IPC endpoint; today an
    /// in-process stand-in.
    pub fn with_keystore(mut self, keystore: Box<dyn KeystoreService>) -> Self {
        self.keystore = Some(keystore);
        self
    }

    /// Attaches the service the resource-scoped `file` handles forward to — required iff
    /// the manifest granted any file.
    pub fn with_filesystem(mut self, filesystem: Box<dyn FilesystemService>) -> Self {
        self.filesystem = Some(filesystem);
        self
    }

    /// Attaches the service the resource-scoped `model` handles forward to — required iff the manifest granted any.
    pub fn with_inference(mut self, inference: Box<dyn InferenceService>) -> Self {
        self.inference = Some(inference);
        self
    }

    /// Attaches the wallet the resource-scoped `context` handles forward to — required iff the manifest granted any.
    pub fn with_identity(mut self, identity: Box<dyn IdentityService>) -> Self {
        self.identity = Some(identity);
        self
    }

    fn context_service(&mut self, handle: &Resource<HostContext>) -> Result<(u64, &mut dyn IdentityService), identity::ErrorCode> {
        let cap = self.table.get(handle).copied().map_err(|_| identity::ErrorCode::Access)?;
        let service = self.identity.as_deref_mut().ok_or(identity::ErrorCode::Access)?;
        Ok((cap.badge, service))
    }

    fn keystore_cap(&self, handle: &Resource<HostCapability>) -> Result<HostCapability, keystore::ErrorCode> {
        // A type-mismatched or wrong-instance handle can't reach here (component-model
        // ABI guarantee); a stale handle after `drop` reads as `access`, deny-by-default.
        self.table.get(handle).copied().map_err(|_| keystore::ErrorCode::Access)
    }

    fn keystore(&self) -> Result<&dyn KeystoreService, keystore::ErrorCode> {
        self.keystore.as_deref().ok_or(keystore::ErrorCode::Access)
    }

    fn file_cap(&self, handle: &Resource<HostFile>) -> Result<HostFile, filesystem::ErrorCode> {
        self.table.get(handle).copied().map_err(|_| filesystem::ErrorCode::Access)
    }
}

impl keystore::HostKey for RuntimeState {
    fn encrypt(
        &mut self,
        handle: Resource<HostCapability>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), keystore::ErrorCode> {
        let cap = self.keystore_cap(&handle)?;
        let ServiceEndpoint::Keystore = cap.service else {
            return Err(keystore::ErrorCode::Access);
        };
        let nonce = fixed_len::<NONCE_LEN>(&nonce)?;
        let mut buffer = plaintext;
        let tag = self
            .keystore()?
            .encrypt(cap.badge, cap.key, &nonce, &aad, &mut buffer)
            .map_err(to_error_code)?;
        Ok((buffer, tag.to_vec()))
    }

    fn decrypt(
        &mut self,
        handle: Resource<HostCapability>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        ciphertext: Vec<u8>,
        tag: Vec<u8>,
    ) -> Result<Vec<u8>, keystore::ErrorCode> {
        let cap = self.keystore_cap(&handle)?;
        let ServiceEndpoint::Keystore = cap.service else {
            return Err(keystore::ErrorCode::Access);
        };
        let nonce = fixed_len::<NONCE_LEN>(&nonce)?;
        let tag = fixed_len::<TAG_LEN>(&tag)?;
        let mut buffer = ciphertext;
        self.keystore()?
            .decrypt(cap.badge, cap.key, &nonce, &aad, &mut buffer, &tag)
            .map_err(to_error_code)?;
        Ok(buffer)
    }

    fn sign(
        &mut self,
        handle: Resource<HostCapability>,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, keystore::ErrorCode> {
        let cap = self.keystore_cap(&handle)?;
        let ServiceEndpoint::Keystore = cap.service else {
            return Err(keystore::ErrorCode::Access);
        };
        self.keystore()?
            .sign(cap.badge, cap.key, &message)
            .map_err(to_error_code)
    }

    fn drop(&mut self, handle: Resource<HostCapability>) -> wasmtime::Result<()> {
        self.table.delete(handle)?;
        Ok(())
    }
}

impl keystore::Host for RuntimeState {
    fn open(&mut self, slot: u32) -> Option<Resource<HostCapability>> {
        let cap = self.keys.get(usize::try_from(slot).ok()?).copied().flatten()?;
        self.table.push(cap).ok()
    }
}

impl filesystem::HostFile for RuntimeState {
    fn read(&mut self, handle: Resource<HostFile>) -> Result<Vec<u8>, filesystem::ErrorCode> {
        let cap = self.file_cap(&handle)?;
        let ServiceEndpoint::Filesystem = cap.service else {
            return Err(filesystem::ErrorCode::Access);
        };
        let filesystem = self
            .filesystem
            .as_deref()
            .ok_or(filesystem::ErrorCode::Access)?;
        let mut buffer = vec![0u8; MAX_BLOCK_LEN];
        match filesystem.read(cap.badge, cap.file, &mut buffer) {
            Ok(n) => {
                buffer.truncate(n);
                Ok(buffer)
            }
            // An unwritten file is an empty file, not an error the guest can act on.
            Err(StoreError::FileEmpty) => Ok(Vec::new()),
            Err(e) => Err(to_fs_error_code(e)),
        }
    }

    fn write(
        &mut self,
        handle: Resource<HostFile>,
        bytes: Vec<u8>,
    ) -> Result<(), filesystem::ErrorCode> {
        let cap = self.file_cap(&handle)?;
        let ServiceEndpoint::Filesystem = cap.service else {
            return Err(filesystem::ErrorCode::Access);
        };
        // Pre-check the v0 block-size bound before the service is consulted (mirrors
        // keystore's nonce-length pre-check).
        if bytes.len() > MAX_BLOCK_LEN {
            return Err(filesystem::ErrorCode::Invalid);
        }
        let filesystem = self
            .filesystem
            .as_deref_mut()
            .ok_or(filesystem::ErrorCode::Access)?;
        filesystem
            .write(cap.badge, cap.file, &bytes)
            .map_err(to_fs_error_code)
    }

    fn drop(&mut self, handle: Resource<HostFile>) -> wasmtime::Result<()> {
        self.table.delete(handle)?;
        Ok(())
    }
}

impl filesystem::Host for RuntimeState {
    fn open(&mut self, slot: u32) -> Option<Resource<HostFile>> {
        let cap = self.files.get(usize::try_from(slot).ok()?).copied().flatten()?;
        self.table.push(cap).ok()
    }
}

impl inference::HostModel for RuntimeState {
    fn generate(
        &mut self,
        handle: Resource<HostModel>,
        prompt: alloc_string::String,
        max_tokens: u32,
    ) -> Result<alloc_string::String, inference::ErrorCode> {
        let cap = self.table.get(&handle).copied().map_err(|_| inference::ErrorCode::Access)?;
        let service = self.inference.as_deref_mut().ok_or(inference::ErrorCode::Access)?;
        let bytes = service.generate(cap.badge, prompt.as_bytes(), max_tokens as usize).map_err(to_inference_error_code)?;
        // A token can end mid-character; the guest gets text, with any such byte replaced.
        Ok(alloc_string::String::from_utf8_lossy(&bytes).into_owned())
    }

    fn drop(&mut self, handle: Resource<HostModel>) -> wasmtime::Result<()> {
        self.table.delete(handle)?;
        Ok(())
    }
}

impl inference::Host for RuntimeState {
    fn open(&mut self, slot: u32) -> Option<Resource<HostModel>> {
        let cap = self.models.get(usize::try_from(slot).ok()?).copied().flatten()?;
        self.table.push(cap).ok()
    }
}

impl identity::HostContext for RuntimeState {
    fn connect(&mut self, handle: Resource<HostContext>) -> Result<(), identity::ErrorCode> {
        let (badge, service) = self.context_service(&handle)?;
        service.connect(badge).map_err(to_identity_error_code)
    }

    fn send(&mut self, handle: Resource<HostContext>, message: Vec<u8>) -> Result<(), identity::ErrorCode> {
        if message.len() > lantern_abi::identity::MESSAGE_MAX {
            return Err(identity::ErrorCode::Invalid);
        }
        let (badge, service) = self.context_service(&handle)?;
        service.send(badge, &message).map_err(to_identity_error_code)
    }

    fn recv(&mut self, handle: Resource<HostContext>) -> Result<Vec<u8>, identity::ErrorCode> {
        let (badge, service) = self.context_service(&handle)?;
        service.recv(badge).map_err(to_identity_error_code)
    }

    fn drop(&mut self, handle: Resource<HostContext>) -> wasmtime::Result<()> {
        self.table.delete(handle)?;
        Ok(())
    }
}

impl identity::Host for RuntimeState {
    fn open(&mut self, slot: u32) -> Option<Resource<HostContext>> {
        let cap = self.contexts.get(usize::try_from(slot).ok()?).copied().flatten()?;
        self.table.push(cap).ok()
    }
}

impl monotonic_clock::Host for RuntimeState {
    fn now(&mut self) -> u64 {
        // `build_linker` only links this interface when `clock` is `Some`, so a linked
        // `now` always has a source.
        (self.clock.expect("monotonic-clock linked without a source").now_ns)()
    }

    fn resolution(&mut self) -> u64 {
        self.clock.expect("monotonic-clock linked without a source").resolution_ns
    }
}

// -------------------------------------------------------------------------------------
// Linker construction — the link-or-refuse decision point
// -------------------------------------------------------------------------------------

/// Builds the [`Linker`] for a component whose grants are `manifest`. A resource-scoped
/// interface is linked when the manifest **declared** it — i.e. its slot vec is non-empty
/// — even if every slot is a declined `None`, so `open` returns `none` rather than
/// trapping (RFC-0015/ADR-0020). A link-scoped interface is linked when the manifest
/// grants the facility. An imported interface that ends up unlinked makes the component
/// fail to instantiate — the single enforcement point the link-scoped shape admits.
pub fn build_linker(
    engine: &Engine,
    manifest: &GrantManifest,
) -> wasmtime::Result<Linker<RuntimeState>> {
    use wasmtime::component::HasSelf;

    let mut linker = Linker::new(engine);

    if manifest.monotonic_clock.is_some() {
        monotonic_clock::add_to_linker::<_, HasSelf<RuntimeState>>(&mut linker, |s| s)?;
    }
    if !manifest.keystore_keys.is_empty() {
        keystore::add_to_linker::<_, HasSelf<RuntimeState>>(&mut linker, |s| s)?;
    }
    if !manifest.filesystem_files.is_empty() {
        filesystem::add_to_linker::<_, HasSelf<RuntimeState>>(&mut linker, |s| s)?;
    }
    if !manifest.inference_models.is_empty() {
        inference::add_to_linker::<_, HasSelf<RuntimeState>>(&mut linker, |s| s)?;
    }
    if !manifest.identity_contexts.is_empty() {
        identity::add_to_linker::<_, HasSelf<RuntimeState>>(&mut linker, |s| s)?;
    }

    Ok(linker)
}

#[cfg(test)]
mod tests;
