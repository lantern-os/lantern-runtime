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
//! IPC-reachable confined processes; neither is one yet
//! (`lantern-crypto/STATUS.md`, `lantern-filesystem/STATUS.md`). So [`RuntimeState`]
//! holds live [`KeystoreService`] / [`FilesystemService`] stand-ins in-process, exactly
//! as the sibling crates do for the same gap. The mapping — badge lookup, per-call
//! forwarding, error translation, link-or-refuse — is real; the transport under it is
//! not yet.

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

/// Maps the owning service's own error onto the WIT interface's `error-code`. Denied,
/// revoked, wrong-key, and missing-key all collapse to `access` — deny-by-default, and
/// no distinction is leaked about *why*. Everything else (malformed arguments, a
/// primitive-level authentication failure, a wrong-purpose key) is `invalid`.
fn to_error_code(err: KeystoreError) -> keystore::ErrorCode {
    use KeystoreError::*;
    match err {
        UnknownBadge | BadgeRevoked | OpNotGranted | WrongKey | NoSuchKey | KeyDestroyed => {
            keystore::ErrorCode::Access
        }
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
/// `lantern_crypto::Keystore` its store-wide AEAD key lives in (`Store::read`/`write`
/// both need it), threaded internally so the [`FilesystemService`] signatures stay clean.
pub struct InProcessFilesystem {
    store: lantern_filesystem::Store,
    keystore: lantern_crypto::Keystore,
}

impl InProcessFilesystem {
    pub fn new(store: lantern_filesystem::Store, keystore: lantern_crypto::Keystore) -> Self {
        Self { store, keystore }
    }
}

impl FilesystemService for InProcessFilesystem {
    fn read(&self, badge: u64, file: FileId, buffer: &mut [u8]) -> Result<usize, StoreError> {
        self.store.read(&self.keystore, badge, file, buffer)
    }

    fn write(&mut self, badge: u64, file: FileId, data: &[u8]) -> Result<(), StoreError> {
        self.store.write(&self.keystore, badge, file, data)
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
    /// Resource-scoped keystore grants, in slot order. `keystore.open(n)` returns a
    /// handle iff `n < keystore_keys.len()`.
    pub keystore_keys: Vec<HostCapability>,
    /// Resource-scoped filesystem grants, in slot order. `filesystem.open(n)` returns a
    /// handle iff `n < filesystem_files.len()`.
    pub filesystem_files: Vec<HostFile>,
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
    keys: Vec<HostCapability>,
    files: Vec<HostFile>,
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
        let cap = *self.keys.get(usize::try_from(slot).ok()?)?;
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
        let cap = *self.files.get(usize::try_from(slot).ok()?)?;
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

/// Builds the [`Linker`] for a component whose grants are `manifest`. Resource-scoped
/// interfaces are linked when the manifest grants at least one object for them;
/// link-scoped interfaces are linked when the manifest grants the facility. An imported
/// interface that ends up unlinked makes the component fail to instantiate — the single
/// enforcement point the link-scoped shape admits, applied uniformly.
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
