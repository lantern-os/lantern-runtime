//! The runtime role ([RFC-0013](../https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0013-wasm-engine-selection-and-aot-strategy.md)/
//! [ADR-0017](../https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0017-wasm-engine-selection-and-aot-strategy.md)):
//! verify, then deserialize — nothing else. No Cranelift/Winch is linked into this crate
//! without the `compiler` feature, so `Component::new`/`Engine::precompile_component`
//! aren't reachable from this module even by mistake — this file physically cannot compile
//! a component from source, only load one already compiled and signed elsewhere.

use lantern_crypto::signing;
use wasmtime::component::Component;
use wasmtime::{Config, Engine};

#[derive(Debug)]
pub enum LoadError {
    /// The artifact's signature didn't verify against the given public key — tampered,
    /// corrupted, or signed under a different key. [`Component::deserialize`] is never
    /// reached in this case; see [`load_verified_component`]'s ordering requirement.
    BadSignature,
    /// The signature checked out, but Wasmtime itself rejected the artifact (wrong
    /// Wasmtime version/target, or not actually a `.cwasm` at all).
    Deserialize(wasmtime::Error),
}

/// Builds the runtime-role [`Engine`]: Component Model on, no compiler configured —
/// none is linked into this build at all when the `compiler` feature is off (see this
/// crate's top-level doc). Every runtime-role component is expected to share one engine,
/// matching Wasmtime's own guidance on how `Engine`s are meant to be reused.
pub fn runtime_engine() -> Engine {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Engine::new(&config).expect("a component-model-only Config is always valid")
}

/// Verifies `cwasm`'s Ed25519 signature under `public_key` (RFC-0007's ratified primitive,
/// via [`lantern_crypto::signing::verify`]) and only then deserializes it. Verification
/// needs only a public key — like `signing::verify` itself, this isn't gated behind a
/// capability badge, since there's no secret asset to protect here, only an integrity
/// check on an artifact this process is about to trust.
///
/// # Ordering
/// The signature check runs unconditionally before `Component::deserialize` is ever
/// called. Wasmtime documents `deserialize` as unsound on untrusted bytes; verifying first
/// is what makes calling it here sound at all, not an incidental nicety — the same
/// signed-artifact trust chain `lantern-boot` uses for its own kernel-image verification.
pub fn load_verified_component(
    engine: &Engine,
    cwasm: &[u8],
    public_key: &[u8; signing::PUBLIC_KEY_LEN],
    signature: &[u8; signing::SIGNATURE_LEN],
) -> Result<Component, LoadError> {
    signing::verify(public_key, cwasm, signature).map_err(|_| LoadError::BadSignature)?;
    // SAFETY: the signature just verified above is over exactly these bytes, under a
    // public key the caller supplied out of band.
    unsafe { deserialize_trusted_component(engine, cwasm) }
}

/// Deserializes a `.cwasm` whose integrity the caller has **already** verified out of band.
/// The counterpart to [`load_verified_component`] for the RFC-0015 `.lpkg` package flow,
/// where the Ed25519 signature is over the `BLAKE3(manifest) ‖ BLAKE3(cwasm)` digest (see
/// `lantern_sdk::package`), not the bare `.cwasm` — so there is no standalone `.cwasm`
/// signature for [`load_verified_component`] to check.
///
/// # Safety
/// `cwasm` must be bytes this process trusts: verified against a signature under a key it
/// trusts (e.g. `lantern_sdk::package::verify_package` returned `Ok`). `Component::deserialize`
/// is documented as unsound on untrusted input.
pub unsafe fn deserialize_trusted_component(
    engine: &Engine,
    cwasm: &[u8],
) -> Result<Component, LoadError> {
    unsafe { Component::deserialize(engine, cwasm) }.map_err(LoadError::Deserialize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_crypto::signing::{SigningKey, SEED_LEN};

    #[test]
    fn rejects_a_tampered_artifact() {
        let key = SigningKey::from_random_bytes([7u8; SEED_LEN]);
        let cwasm = b"not really a cwasm".to_vec();
        let sig = key.sign(&cwasm);
        let mut tampered = cwasm.clone();
        tampered.push(0);

        let engine = runtime_engine();
        match load_verified_component(&engine, &tampered, &key.verifying_key(), &sig) {
            Err(LoadError::BadSignature) => {}
            Err(other) => panic!("expected BadSignature, got {other:?}"),
            Ok(_) => panic!("expected an error, got a loaded component"),
        }
    }

    #[test]
    fn a_valid_signature_does_not_bypass_wasmtime_s_own_validation() {
        // The signature can check out and deserialize can still fail — two separate
        // checks, not one; a signed non-artifact must not be treated as trusted bytes.
        let key = SigningKey::from_random_bytes([7u8; SEED_LEN]);
        let cwasm = b"not really a cwasm".to_vec();
        let sig = key.sign(&cwasm);

        let engine = runtime_engine();
        match load_verified_component(&engine, &cwasm, &key.verifying_key(), &sig) {
            Err(LoadError::Deserialize(_)) => {}
            Err(other) => panic!("expected Deserialize, got {other:?}"),
            Ok(_) => panic!("expected an error, got a loaded component"),
        }
    }
}
