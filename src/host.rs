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
//! direct [`KeystoreService`] impl) every test in this crate still uses. What's still
//! missing is *this crate itself* running confined: `lantern-runtime` only builds/runs on
//! a native `std` host target today (`STATUS.md`'s "carried forward" note) — folding a
//! `no_std`/`riscv64` build (`Cargo.toml`'s `confined` feature, folded in from
//! `lantern-runtime/riscv64-probe`'s own groundwork — [`crate::platform`]) is what lets
//! `IpcKeystore`/`IpcFilesystem` actually run inside a confined component process instead
//! of just compiling for one; a real confined binary and a new demo granting it a
//! `keystore-service`/`store-service` endpoint and shared `Frame` are still separate,
//! not-yet-built work. The mapping — badge lookup, per-call forwarding, error
//! translation, link-or-refuse — is real either way.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec, vec::Vec};

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
    },
});

pub use self::lantern::host::{filesystem, keystore, monotonic_clock};

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
    /// this record does not know it).
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
}

impl IpcFilesystem {
    /// # Safety
    /// As [`lantern_abi::frame::Channel::new`]'s.
    pub unsafe fn new(endpoint: lantern_abi::wire::CPtr, frame: *mut u8) -> Self {
        // SAFETY: forwarded from this function's own contract.
        Self { channel: SingleThreadCell::new(unsafe { lantern_abi::frame::Channel::new(endpoint, frame) }) }
    }
}

impl FilesystemService for IpcFilesystem {
    fn read(&self, _badge: u64, _file: FileId, buffer: &mut [u8]) -> Result<usize, StoreError> {
        let mut channel = self.channel.borrow_mut();
        let (status, len) = channel.call(lantern_filesystem::wire::OP_READ, &[], buffer).map_err(StoreError::Channel)?;
        if status != lantern_filesystem::wire::status::OK {
            return Err(StoreError::RemoteCryptoDenied(status));
        }
        Ok(len)
    }

    fn write(&mut self, _badge: u64, _file: FileId, data: &[u8]) -> Result<(), StoreError> {
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
    keystore: Option<Box<dyn KeystoreService>>,
    filesystem: Option<Box<dyn FilesystemService>>,
    clock: Option<MonotonicClock>,
}

impl RuntimeState {
    /// The state for `manifest`, with no service backends attached yet.
    pub fn new(manifest: GrantManifest) -> Self {
        Self {
            table: ResourceTable::new(),
            keys: manifest.keystore_keys,
            files: manifest.filesystem_files,
            keystore: None,
            filesystem: None,
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

    Ok(linker)
}

#[cfg(test)]
mod tests;
