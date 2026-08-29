//! RFC-0014 / ADR-0018 (keystore) and RFC-0016 / ADR-0019 (filesystem) host-binding tests.
//!
//! - The resource-scoped mappings are driven against real `lantern-crypto` `Keystore` /
//!   `lantern-filesystem` `Store` with real `Broker`-minted badges — deny-by-default
//!   surface included — plus a fault-injecting keystore double for the
//!   argument-validation and error-translation edges.
//! - The link-scoped clock is driven end to end through Wasmtime instantiation (behind
//!   `--features compiler`, which brings in `wat`): a granted manifest links a real time
//!   source a component reads; a denied manifest makes that same component fail to
//!   instantiate.

use std::sync::{Arc, Mutex};

use super::*;
use keystore::{ErrorCode, Host, HostKey};

use lantern_crypto::aead::{NONCE_LEN, TAG_LEN};
use lantern_crypto::{KeyId, KeyOps, Keystore, KeystoreError};

// ---------------------------------------------------------------------------------
// KeystoreService doubles
// ---------------------------------------------------------------------------------

struct AlwaysErr(KeystoreError);

impl KeystoreService for AlwaysErr {
    fn encrypt(&self, _: u64, _: KeyId, _: &[u8; NONCE_LEN], _: &[u8], _: &mut [u8]) -> Result<[u8; TAG_LEN], KeystoreError> {
        Err(self.0)
    }
    fn decrypt(&self, _: u64, _: KeyId, _: &[u8; NONCE_LEN], _: &[u8], _: &mut [u8], _: &[u8; TAG_LEN]) -> Result<(), KeystoreError> {
        Err(self.0)
    }
    fn sign(&self, _: u64, _: KeyId, _: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        Err(self.0)
    }
}

/// Records what badge/key each call forwarded, then succeeds.
#[derive(Clone, Default)]
struct Spy(Arc<Mutex<Vec<(u64, KeyId)>>>);

impl KeystoreService for Spy {
    fn encrypt(&self, badge: u64, key: KeyId, _: &[u8; NONCE_LEN], _: &[u8], buffer: &mut [u8]) -> Result<[u8; TAG_LEN], KeystoreError> {
        self.0.lock().unwrap().push((badge, key));
        buffer.iter_mut().for_each(|b| *b ^= 0xFF);
        Ok([7u8; TAG_LEN])
    }
    fn decrypt(&self, badge: u64, key: KeyId, _: &[u8; NONCE_LEN], _: &[u8], buffer: &mut [u8], _: &[u8; TAG_LEN]) -> Result<(), KeystoreError> {
        self.0.lock().unwrap().push((badge, key));
        buffer.iter_mut().for_each(|b| *b ^= 0xFF);
        Ok(())
    }
    fn sign(&self, badge: u64, key: KeyId, message: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        self.0.lock().unwrap().push((badge, key));
        Ok(message.to_vec())
    }
}

fn state_with(service: impl KeystoreService + 'static, caps: Vec<HostCapability>) -> RuntimeState {
    RuntimeState::new(GrantManifest { keystore_keys: caps, ..Default::default() })
        .with_keystore(Box::new(service))
}

// ---------------------------------------------------------------------------------
// Resource-scoped: handle acquisition
// ---------------------------------------------------------------------------------

#[test]
fn open_returns_a_handle_only_for_a_granted_slot() {
    let cap = HostCapability::keystore_key(0xAB, fabricate_key_id());
    let mut state = state_with(Spy::default(), vec![cap]);

    assert!(state.open(0).is_some(), "slot 0 was granted");
    assert!(state.open(1).is_none(), "slot 1 was never granted — nothing to forge");
    assert!(state.open(u32::MAX).is_none());
}

#[test]
fn a_dropped_handle_no_longer_resolves() {
    let cap = HostCapability::keystore_key(0xAB, fabricate_key_id());
    let mut state = state_with(Spy::default(), vec![cap]);

    let handle = state.open(0).unwrap();
    let stale = wasmtime::component::Resource::<HostCapability>::new_own(handle.rep());
    HostKey::drop(&mut state, handle).unwrap();

    assert_eq!(state.sign(stale, b"x".to_vec()), Err(ErrorCode::Access));
}

// ---------------------------------------------------------------------------------
// Resource-scoped: forwarding + error translation
// ---------------------------------------------------------------------------------

#[test]
fn the_denied_family_of_service_errors_maps_to_access() {
    for err in [
        KeystoreError::UnknownBadge,
        KeystoreError::BadgeRevoked,
        KeystoreError::OpNotGranted,
        KeystoreError::WrongKey,
        KeystoreError::NoSuchKey,
        KeystoreError::KeyDestroyed,
    ] {
        let cap = HostCapability::keystore_key(1, fabricate_key_id());
        let mut state = state_with(AlwaysErr(err), vec![cap]);
        let handle = state.open(0).unwrap();
        assert_eq!(state.sign(handle, b"m".to_vec()), Err(ErrorCode::Access), "{err:?}");
    }
}

#[test]
fn a_primitive_level_failure_maps_to_invalid_not_access() {
    let cap = HostCapability::keystore_key(1, fabricate_key_id());
    let mut state = state_with(AlwaysErr(KeystoreError::CryptoFailure), vec![cap]);
    let handle = state.open(0).unwrap();
    assert_eq!(
        state.decrypt(handle, vec![0; NONCE_LEN], vec![], vec![1, 2, 3], vec![0; TAG_LEN]),
        Err(ErrorCode::Invalid),
    );
}

#[test]
fn a_wrong_length_nonce_is_rejected_before_the_service_is_consulted() {
    let cap = HostCapability::keystore_key(1, fabricate_key_id());
    let mut state = state_with(AlwaysErr(KeystoreError::OpNotGranted), vec![cap]);
    let handle = state.open(0).unwrap();
    assert_eq!(
        state.encrypt(handle, vec![0; NONCE_LEN - 1], vec![], vec![1, 2, 3]),
        Err(ErrorCode::Invalid),
    );
}

#[test]
fn the_badge_behind_the_handle_is_what_gets_forwarded() {
    let key = fabricate_key_id();
    let spy = Spy::default();
    let log = spy.0.clone();
    let cap = HostCapability::keystore_key(0x5151, key);
    let mut state = state_with(spy, vec![cap]);

    let handle = state.open(0).unwrap();
    state.sign(handle, b"hello".to_vec()).unwrap();

    assert_eq!(*log.lock().unwrap(), vec![(0x5151, key)]);
}

// ---------------------------------------------------------------------------------
// Resource-scoped: against a real Keystore + real Broker-minted badge
// ---------------------------------------------------------------------------------

#[test]
fn real_keystore_encrypt_decrypt_round_trip_through_the_mapping() {
    let mut rc = real_crypto();
    let key = rc.keystore.generate_aead_key([7u8; 32]).unwrap();
    let badge = rc.grant(key, KeyOps::ENCRYPT.union(KeyOps::DECRYPT));

    let cap = HostCapability::keystore_key(badge, key);
    let mut state = state_with(rc.into_keystore(), vec![cap]);

    let handle = state.open(0).unwrap();
    let (ciphertext, tag) = state
        .encrypt(handle, vec![9u8; NONCE_LEN], b"aad".to_vec(), b"secret".to_vec())
        .unwrap();
    assert_ne!(ciphertext, b"secret");

    let handle = state.open(0).unwrap();
    let plaintext = state
        .decrypt(handle, vec![9u8; NONCE_LEN], b"aad".to_vec(), ciphertext, tag)
        .unwrap();
    assert_eq!(plaintext, b"secret");
}

#[test]
fn real_keystore_relays_its_own_deny_by_default_checks() {
    let mut rc = real_crypto();
    let key = rc.keystore.generate_aead_key([7u8; 32]).unwrap();
    let badge = rc.grant(key, KeyOps::ENCRYPT); // ENCRYPT only — not DECRYPT

    let cap = HostCapability::keystore_key(badge, key);
    let mut state = state_with(rc.into_keystore(), vec![cap]);

    let handle = state.open(0).unwrap();
    let (ciphertext, tag) = state
        .encrypt(handle, vec![9u8; NONCE_LEN], b"".to_vec(), b"x".to_vec())
        .unwrap();

    let handle = state.open(0).unwrap();
    assert_eq!(
        state.decrypt(handle, vec![9u8; NONCE_LEN], b"".to_vec(), ciphertext, tag),
        Err(ErrorCode::Access),
    );
}

#[test]
fn real_keystore_revocation_is_relayed() {
    let mut rc = real_crypto();
    let key = rc.keystore.generate_signing_key([3u8; 32]).unwrap();
    let badge = rc.grant(key, KeyOps::SIGN);
    rc.keystore.revoke_access(badge).unwrap();

    let cap = HostCapability::keystore_key(badge, key);
    let mut state = state_with(rc.into_keystore(), vec![cap]);
    let handle = state.open(0).unwrap();
    assert_eq!(state.sign(handle, b"m".to_vec()), Err(ErrorCode::Access));
}

#[test]
fn real_keystore_sign_returns_a_64_byte_signature() {
    let mut rc = real_crypto();
    let key = rc.keystore.generate_signing_key([3u8; 32]).unwrap();
    let badge = rc.grant(key, KeyOps::SIGN);

    let cap = HostCapability::keystore_key(badge, key);
    let mut state = state_with(rc.into_keystore(), vec![cap]);
    let handle = state.open(0).unwrap();
    let sig = state.sign(handle, b"message".to_vec()).unwrap();
    assert_eq!(sig.len(), lantern_crypto::signing::SIGNATURE_LEN);
}

// ---------------------------------------------------------------------------------
// Link-or-refuse
// ---------------------------------------------------------------------------------

#[cfg(feature = "compiler")]
mod through_wasmtime {
    use super::*;
    use crate::verified::runtime_engine;

    const EMPTY_WAT: &str = "(component)";

    /// Imports the link-scoped clock and returns `now()`.
    const CLOCK_READER_WAT: &str = r#"
        (component
          (import "lantern:host/monotonic-clock@0.1.0" (instance $clock
            (export "now" (func (result u64)))))
          (core func $now (canon lower (func $clock "now")))
          (core module $m
            (import "clock" "now" (func $now (result i64)))
            (func (export "run") (result i64) call $now))
          (core instance $ci (instantiate $m
            (with "clock" (instance (export "now" (func $now))))))
          (func (export "run") (result u64) (canon lift (core func $ci "run"))))
    "#;

    #[test]
    fn a_component_with_no_imports_instantiates_against_an_empty_linker() {
        let engine = runtime_engine();
        let component = wasmtime::component::Component::new(&engine, EMPTY_WAT).unwrap();
        let linker = build_linker(&engine, &GrantManifest::nothing()).unwrap();
        let mut store = wasmtime::Store::new(&engine, RuntimeState::new(GrantManifest::nothing()));
        assert!(linker.instantiate(&mut store, &component).is_ok());
    }

    #[test]
    fn a_granted_clock_is_linked_and_readable() {
        let engine = runtime_engine();
        let component = wasmtime::component::Component::new(&engine, CLOCK_READER_WAT).unwrap();

        let manifest = GrantManifest {
            monotonic_clock: Some(MonotonicClock { now_ns: || 1_234_567, resolution_ns: 100 }),
            ..Default::default()
        };
        let linker = build_linker(&engine, &manifest).unwrap();
        let mut store = wasmtime::Store::new(&engine, RuntimeState::new(manifest));
        let instance = linker.instantiate(&mut store, &component).unwrap();
        let run = instance.get_typed_func::<(), (u64,)>(&mut store, "run").unwrap();
        assert_eq!(run.call(&mut store, ()).unwrap().0, 1_234_567);
    }

    #[test]
    fn a_denied_clock_makes_the_importing_component_fail_to_instantiate() {
        let engine = runtime_engine();
        let component = wasmtime::component::Component::new(&engine, CLOCK_READER_WAT).unwrap();

        let manifest = GrantManifest::nothing();
        let linker = build_linker(&engine, &manifest).unwrap();
        let mut store = wasmtime::Store::new(&engine, RuntimeState::new(manifest));
        assert!(
            linker.instantiate(&mut store, &component).is_err(),
            "an unlinked import must refuse instantiation",
        );
    }
}

// ---------------------------------------------------------------------------------
// Resource-scoped: filesystem, against a real Store + real Store-minted badge
// ---------------------------------------------------------------------------------

mod fs {
    use super::*;
    use crate::host::filesystem::{self, ErrorCode as FsErr};
    use lantern_filesystem::{FileOps, MAX_BLOCK_LEN};
    use wasmtime::component::Resource;

    fn fs_state(service: InProcessFilesystem, files: Vec<HostFile>) -> RuntimeState {
        RuntimeState::new(GrantManifest { filesystem_files: files, ..Default::default() })
            .with_filesystem(Box::new(service))
    }

    // `keystore::Host` and `filesystem::Host` both have `open` (and both are in scope via
    // `super::*`), so route the filesystem calls through fully-qualified trait syntax.
    fn open(state: &mut RuntimeState, slot: u32) -> Option<Resource<HostFile>> {
        <RuntimeState as filesystem::Host>::open(state, slot)
    }
    fn read(state: &mut RuntimeState, h: Resource<HostFile>) -> Result<Vec<u8>, FsErr> {
        <RuntimeState as filesystem::HostFile>::read(state, h)
    }
    fn write(state: &mut RuntimeState, h: Resource<HostFile>, b: Vec<u8>) -> Result<(), FsErr> {
        <RuntimeState as filesystem::HostFile>::write(state, h, b)
    }

    #[test]
    fn open_returns_a_file_handle_only_for_a_granted_slot() {
        let mut fs = real_fs(None);
        let badge = fs.grant(FileOps::READ, 7);
        let cap = HostFile::filesystem_file(badge, fs.file);
        let mut state = fs_state(fs.into_service(), vec![cap]);

        assert!(open(&mut state, 0).is_some(), "slot 0 was granted");
        assert!(open(&mut state, 1).is_none(), "slot 1 was never granted — no path to guess");
        assert!(open(&mut state, u32::MAX).is_none());
    }

    #[test]
    fn read_returns_the_granted_file_content() {
        let mut fs = real_fs(Some(b"confidential config"));
        let badge = fs.grant(FileOps::READ, 7);
        let cap = HostFile::filesystem_file(badge, fs.file);
        let mut state = fs_state(fs.into_service(), vec![cap]);

        let handle = open(&mut state, 0).unwrap();
        assert_eq!(read(&mut state, handle).unwrap(), b"confidential config");
    }

    #[test]
    fn write_then_read_round_trips_through_the_mapping() {
        let mut fs = real_fs(None);
        let badge = fs.grant(FileOps::ALL, 7);
        let cap = HostFile::filesystem_file(badge, fs.file);
        let mut state = fs_state(fs.into_service(), vec![cap]);

        let handle = open(&mut state, 0).unwrap();
        write(&mut state, handle, b"written by the guest".to_vec()).unwrap();
        let handle = open(&mut state, 0).unwrap();
        assert_eq!(read(&mut state, handle).unwrap(), b"written by the guest");
    }

    #[test]
    fn an_unwritten_file_reads_as_empty_not_an_error() {
        let mut fs = real_fs(None);
        let badge = fs.grant(FileOps::READ, 7);
        let cap = HostFile::filesystem_file(badge, fs.file);
        let mut state = fs_state(fs.into_service(), vec![cap]);

        let handle = open(&mut state, 0).unwrap();
        assert_eq!(read(&mut state, handle).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn read_is_denied_when_the_badge_lacks_read() {
        let mut fs = real_fs(Some(b"secret"));
        let badge = fs.grant(FileOps::WRITE, 7); // WRITE only
        let cap = HostFile::filesystem_file(badge, fs.file);
        let mut state = fs_state(fs.into_service(), vec![cap]);

        let handle = open(&mut state, 0).unwrap();
        assert_eq!(read(&mut state, handle), Err(FsErr::Access));
    }

    #[test]
    fn write_is_denied_when_the_badge_lacks_write() {
        let mut fs = real_fs(None);
        let badge = fs.grant(FileOps::READ, 7); // READ only
        let cap = HostFile::filesystem_file(badge, fs.file);
        let mut state = fs_state(fs.into_service(), vec![cap]);

        let handle = open(&mut state, 0).unwrap();
        assert_eq!(write(&mut state, handle, b"nope".to_vec()), Err(FsErr::Access));
    }

    #[test]
    fn a_badge_for_a_different_file_is_rejected() {
        // A handle whose badge was minted for file A but whose record names file B:
        // `Store::check_access` rejects the mismatch as `WrongFile` → `access` before it
        // ever touches content. There is no namespace to walk from one file to another.
        let mut fs = real_fs(None);
        let badge_for_a = fs.grant(FileOps::READ, 7);
        let file_b = fs.store.create().unwrap();
        let mut state = fs_state(
            fs.into_service(),
            vec![HostFile::filesystem_file(badge_for_a, file_b)],
        );

        let handle = open(&mut state, 0).unwrap();
        assert_eq!(read(&mut state, handle), Err(FsErr::Access));
    }

    #[test]
    fn an_oversized_write_is_invalid_before_the_store_is_consulted() {
        let mut fs = real_fs(None);
        let badge = fs.grant(FileOps::WRITE, 7);
        let cap = HostFile::filesystem_file(badge, fs.file);
        let mut state = fs_state(fs.into_service(), vec![cap]);

        let handle = open(&mut state, 0).unwrap();
        assert_eq!(
            write(&mut state, handle, vec![0u8; MAX_BLOCK_LEN + 1]),
            Err(FsErr::Invalid),
        );
    }

    #[test]
    fn a_dropped_file_handle_no_longer_resolves() {
        let mut fs = real_fs(Some(b"x"));
        let badge = fs.grant(FileOps::READ, 7);
        let cap = HostFile::filesystem_file(badge, fs.file);
        let mut state = fs_state(fs.into_service(), vec![cap]);

        let handle = open(&mut state, 0).unwrap();
        let stale = wasmtime::component::Resource::<HostFile>::new_own(handle.rep());
        crate::host::filesystem::HostFile::drop(&mut state, handle).unwrap();
        assert_eq!(read(&mut state, stale), Err(FsErr::Access));
    }

    #[test]
    fn build_linker_links_filesystem_iff_a_file_is_granted() {
        let engine = crate::verified::runtime_engine();
        // no files → no filesystem interface
        assert!(build_linker(&engine, &GrantManifest::nothing()).is_ok());
        let mut fs = real_fs(None);
        let badge = fs.grant(FileOps::READ, 7);
        let manifest = GrantManifest {
            filesystem_files: vec![HostFile::filesystem_file(badge, fs.file)],
            ..Default::default()
        };
        assert!(build_linker(&engine, &manifest).is_ok());
    }
}

// ---------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------

/// `KeyId` is opaque; the double-backed tests never touch the key, so route through a
/// real generate call on a throwaway keystore just to obtain a value.
fn fabricate_key_id() -> KeyId {
    real_crypto().keystore.generate_aead_key([0u8; 32]).unwrap()
}

use lantern_hal::{MessageTag, TrapFrame};
use lantern_kernel::cap::{CNode, CNodeId, Capability, CPtr, EndpointId, NotificationId, Rights, TcbId};
use lantern_kernel::ipc;
use lantern_kernel::object::{Endpoint, Notification, Tcb};
use lantern_kernel::state::KernelState;

/// The same two-party service/client shape `lantern-crypto`'s own test suite uses.
struct RealCrypto {
    state: KernelState,
    keystore: Keystore,
    keystore_tcb: TcbId,
    client_tcb: TcbId,
    ep_cptr: CPtr,
}

const SOURCE_SLOT: CPtr = 5;
const SCRATCH_SLOT: CPtr = 6;
const CLIENT_DEST_SLOT: usize = 9;

fn real_crypto() -> RealCrypto {
    let mut state = KernelState::new();

    let ks_cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
    let keystore_tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
    state.tcbs.get_mut(keystore_tcb.0 as usize).unwrap().cspace = Some(ks_cnode);
    *state.cnodes.get_mut(ks_cnode.0 as usize).unwrap().slot_mut(0).unwrap() = Capability::CNode(ks_cnode);

    let ep_idx = state.endpoints.alloc(Endpoint::new()).unwrap();
    let ep = Capability::Endpoint { id: EndpointId(ep_idx as u16), badge: 0, rights: Rights::ALL };
    *state.cnodes.get_mut(ks_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = ep;

    let notif_idx = state.notifications.alloc(Notification::new()).unwrap();
    let source = Capability::Notification {
        id: NotificationId(notif_idx as u16),
        badge: 0,
        rights: Rights::READ.union(Rights::GRANT),
    };
    *state.cnodes.get_mut(ks_cnode.0 as usize).unwrap().slot_mut(SOURCE_SLOT).unwrap() = source;

    let client_cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
    let client_tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
    state.tcbs.get_mut(client_tcb.0 as usize).unwrap().cspace = Some(client_cnode);
    *state.cnodes.get_mut(client_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = ep;

    let keystore = Keystore::new(keystore_tcb, 0);
    RealCrypto { state, keystore, keystore_tcb, client_tcb, ep_cptr: 1 }
}

impl RealCrypto {
    fn grant(&mut self, key: KeyId, ops: KeyOps) -> u64 {
        self.state.make_ready(self.keystore_tcb);
        self.state.scheduler.current = Some(self.client_tcb);
        let mut recv_frame = TrapFrame::zeroed();
        recv_frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 1, flags: 0 });
        recv_frame.set_mr(1, CLIENT_DEST_SLOT);
        ipc::recv(&mut self.state, self.client_tcb, self.ep_cptr, &mut recv_frame).unwrap();
        assert_eq!(self.state.scheduler.current, Some(self.keystore_tcb));

        let badge = self
            .keystore
            .request_key_access(&mut self.state, key, ops, SOURCE_SLOT, SCRATCH_SLOT)
            .unwrap();
        self.keystore.deliver_grant(&mut self.state, self.ep_cptr, SCRATCH_SLOT, (0, 0)).unwrap();
        badge
    }

    fn into_keystore(self) -> Keystore {
        let _ = (self.state, self.client_tcb, self.ep_cptr);
        self.keystore
    }
}

/// The three-party (crypto service / store service / client) fixture
/// `lantern-filesystem`'s own test suite uses, trimmed for these tests. A real `Store`
/// with its store-wide AEAD key held in a real `Keystore`, plus file-access grants.
struct RealFs {
    state: KernelState,
    keystore: Keystore,
    store: lantern_filesystem::Store,
    store_tcb: TcbId,
    store_ep_cptr: CPtr,
    store_ep: Capability,
    file: lantern_filesystem::FileId,
}

fn new_cnode_tcb(state: &mut KernelState) -> (CNodeId, TcbId) {
    let cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
    let tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
    state.tcbs.get_mut(tcb.0 as usize).unwrap().cspace = Some(cnode);
    *state.cnodes.get_mut(cnode.0 as usize).unwrap().slot_mut(0).unwrap() = Capability::CNode(cnode);
    (cnode, tcb)
}

fn source_notif(state: &mut KernelState, cnode: CNodeId) {
    let idx = state.notifications.alloc(Notification::new()).unwrap();
    *state.cnodes.get_mut(cnode.0 as usize).unwrap().slot_mut(SOURCE_SLOT).unwrap() =
        Capability::Notification {
            id: NotificationId(idx as u16),
            badge: 0,
            rights: Rights::READ.union(Rights::GRANT),
        };
}

/// A store with one file, optionally seeded with `content` (which needs a transient
/// WRITE grant on scratch slot 6 — file-access grants for the tests then use 7, 8, …).
fn real_fs(content: Option<&[u8]>) -> RealFs {
    use lantern_filesystem::FileOps;

    let mut state = KernelState::new();

    let (ks_cnode, ks_tcb) = new_cnode_tcb(&mut state);
    source_notif(&mut state, ks_cnode);
    let mut keystore = Keystore::new(ks_tcb, 0);
    let aead_key = keystore.generate_aead_key([3u8; 32]).unwrap();
    state.scheduler.current = Some(ks_tcb);
    let aead_badge = keystore
        .request_key_access(
            &mut state,
            aead_key,
            KeyOps::ENCRYPT.union(KeyOps::DECRYPT),
            SOURCE_SLOT,
            SCRATCH_SLOT,
        )
        .unwrap();

    let (store_cnode, store_tcb) = new_cnode_tcb(&mut state);
    source_notif(&mut state, store_cnode);
    let ep_idx = state.endpoints.alloc(Endpoint::new()).unwrap();
    let store_ep = Capability::Endpoint { id: EndpointId(ep_idx as u16), badge: 0, rights: Rights::ALL };
    *state.cnodes.get_mut(store_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = store_ep;

    let mut store = lantern_filesystem::Store::new(store_tcb, 0, aead_badge, aead_key);
    let file = store.create().unwrap();

    let mut fs = RealFs { state, keystore, store, store_tcb, store_ep_cptr: 1, store_ep, file };

    if let Some(bytes) = content {
        let write_badge = fs.grant(FileOps::WRITE, 6);
        fs.store.write(&fs.keystore, write_badge, file, bytes).unwrap();
    }
    fs
}

impl RealFs {
    /// Mints and delivers a file-access badge scoped to `self.file` and `ops`, over a
    /// fresh client thread. `scratch_slot` must be distinct across calls in one fixture.
    fn grant(&mut self, ops: lantern_filesystem::FileOps, scratch_slot: CPtr) -> u64 {
        self.grant_for(self.file, ops, scratch_slot)
    }

    fn grant_for(&mut self, file: lantern_filesystem::FileId, ops: lantern_filesystem::FileOps, scratch_slot: CPtr) -> u64 {
        let (client_cnode, client_tcb) = new_cnode_tcb(&mut self.state);
        *self.state.cnodes.get_mut(client_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = self.store_ep;

        self.state.make_ready(self.store_tcb);
        self.state.scheduler.current = Some(client_tcb);
        let mut recv_frame = TrapFrame::zeroed();
        recv_frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 1, flags: 0 });
        recv_frame.set_mr(1, CLIENT_DEST_SLOT);
        ipc::recv(&mut self.state, client_tcb, self.store_ep_cptr, &mut recv_frame).unwrap();

        let badge = self
            .store
            .request_file_access(&mut self.state, file, ops, SOURCE_SLOT, scratch_slot)
            .unwrap();
        self.store
            .deliver_grant(&mut self.state, self.store_ep_cptr, scratch_slot, (0, 0))
            .unwrap();
        badge
    }

    fn into_service(self) -> InProcessFilesystem {
        let _ = (self.state, self.store_tcb, self.store_ep_cptr, self.store_ep);
        InProcessFilesystem::new(self.store, self.keystore)
    }
}
