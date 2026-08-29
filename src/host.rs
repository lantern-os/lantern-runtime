//! The WIT-handle ⇄ capability mapping
//! ([RFC-0014](../https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0014-wit-handle-capability-mapping.md)/
//! [ADR-0018](../https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0018-wit-handle-capability-mapping.md)): how a Wasm
//! component's WIT-typed imports become LanternOS object capabilities.
//!
//! Two mapping shapes, one worked interface each (`wit/host.wit`):
//!
//! - **Resource-scoped** — [`keystore`]. Each `key` handle is backed by one
//!   [`HostCapability`] (a service badge + a key id) held in a Wasmtime
//!   [`ResourceTable`]. `encrypt`/`decrypt`/`sign` forward to the owning crypto service,
//!   which re-checks the badge on every call; a denied/revoked/wrong-key badge surfaces
//!   as [`keystore::ErrorCode::Access`], relayed verbatim from the service's own
//!   deny-by-default check. This module never adds a capability check of its own.
//! - **Link-scoped** — [`monotonic_clock`]. No per-call object to scope (the functions
//!   take no arguments), so the grant is a single yes/no: [`build_linker`] either links
//!   the whole interface or leaves it unlinked, and a component that imports an unlinked
//!   interface fails to instantiate.
//!
//! **Handles are never manufactured in-guest.** Every [`ResourceTable`] entry exists
//! because the capability manifest ([`GrantManifest`] — the runtime-side contract
//! RFC-0014 fixes; the file format is `lantern-sdk`'s, not yet designed) named it before
//! the component started. `keystore.open(slot)` only ever returns a handle for a slot the
//! manifest filled — `slot` indexes an explicit grant list, not an ambient namespace.
//!
//! **Prototype boundary.** RFC-0014 assumes the crypto service is an IPC-reachable
//! confined process; it is not one yet (`lantern-crypto/STATUS.md`). So [`RuntimeState`]
//! holds a live [`KeystoreService`] in-process, exactly the stand-in the sibling crates
//! use for the same gap. The mapping — badge lookup, per-call forwarding, error
//! translation, link-or-refuse — is real; the transport under it is not yet.

use wasmtime::component::{Linker, Resource, ResourceTable};
use wasmtime::Engine;

use lantern_crypto::aead::{NONCE_LEN, TAG_LEN};
use lantern_crypto::{KeyId, KeystoreError};

wasmtime::component::bindgen!({
    path: "wit",
    world: "app",
    with: {
        "lantern:host/keystore/key": HostCapability,
    },
});

pub use self::lantern::host::{keystore, monotonic_clock};

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

/// The owning service a [`HostCapability`] forwards to. One variant today; a real IPC
/// endpoint capability once the owning services are confined processes (ADR-0018).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceEndpoint {
    Keystore,
}

impl HostCapability {
    /// A capability to one key in the crypto service, scoped to whatever operation
    /// subset the manifest granted for `badge` (the crypto service enforces the subset;
    /// this record does not know it).
    pub fn keystore_key(badge: u64, key: KeyId) -> Self {
        Self { badge, key, service: ServiceEndpoint::Keystore }
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
/// objects the manifest's grants resolve to.
pub struct RuntimeState {
    table: ResourceTable,
    keys: Vec<HostCapability>,
    keystore: Option<Box<dyn KeystoreService>>,
    clock: Option<MonotonicClock>,
}

impl RuntimeState {
    /// Builds the state for `manifest`. `keystore` is the service the resource-scoped
    /// `key` handles forward to — required iff `manifest` granted any key. In a real
    /// deployment this is an IPC endpoint; today it is an in-process stand-in.
    pub fn new(manifest: GrantManifest, keystore: Option<Box<dyn KeystoreService>>) -> Self {
        Self {
            table: ResourceTable::new(),
            keys: manifest.keystore_keys,
            keystore,
            clock: manifest.monotonic_clock,
        }
    }

    fn capability(&self, handle: &Resource<HostCapability>) -> Result<HostCapability, keystore::ErrorCode> {
        // A type-mismatched or wrong-instance handle can't reach here (component-model
        // ABI guarantee); a stale handle after `drop` reads as `access`, deny-by-default.
        self.table.get(handle).copied().map_err(|_| keystore::ErrorCode::Access)
    }

    fn keystore(&self) -> Result<&dyn KeystoreService, keystore::ErrorCode> {
        self.keystore.as_deref().ok_or(keystore::ErrorCode::Access)
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
        let cap = self.capability(&handle)?;
        let ServiceEndpoint::Keystore = cap.service;
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
        let cap = self.capability(&handle)?;
        let ServiceEndpoint::Keystore = cap.service;
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
        let cap = self.capability(&handle)?;
        let ServiceEndpoint::Keystore = cap.service;
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
    let mut linker = Linker::new(engine);

    if manifest.monotonic_clock.is_some() {
        monotonic_clock::add_to_linker(&mut linker, |s: &mut RuntimeState| s)?;
    }
    if !manifest.keystore_keys.is_empty() {
        keystore::add_to_linker(&mut linker, |s: &mut RuntimeState| s)?;
    }

    Ok(linker)
}

#[cfg(test)]
mod tests;
