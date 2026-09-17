//! RFC-0018's first real (non-trivial) confined guest component. Compiles to a
//! WebAssembly **component** whose entire import surface is
//! `lantern:host/keystore` (RFC-0014) — see `wit/probe.wit`'s own doc for why this
//! is deliberately narrower than `lantern-example-signer`'s own `signer` world.
//! Imports no `wasi:*` interface it can call and has no ambient authority: if the
//! host does not grant a capability, `keystore::open` returns `none` and every
//! method call the guest *could* still attempt returns `error-code::access` — this
//! guest's `probe` function exercises exactly that adversarial shape, borrowed from
//! (and simplified down from) `lantern-example-signer/app/src/lib.rs`'s own
//! `attest`/`probe`.

wit_bindgen::generate!({
    world: "probe",
    path: "wit",
    generate_all,
});

use crate::lantern::host::keystore;

/// A fixed message, so a real `sign` call has something deterministic to sign.
const MESSAGE: &[u8] = b"lantern-runtime confined-probe-guest v0";

struct Probe;

impl Guest for Probe {
    fn probe() -> String {
        // The granted case: keystore slot 0 is expected to hold a real key scoped to
        // at least SIGN (the launcher's own job to have arranged that grant).
        let Some(key) = keystore::open(0) else {
            return String::from("error: the manifest granted no key at keystore slot 0");
        };
        let signature = match key.sign(MESSAGE) {
            Ok(sig) => sig,
            Err(keystore::ErrorCode::Access) => {
                return String::from("error: keystore denied `sign` (badge not scoped to that op)")
            }
            Err(keystore::ErrorCode::Invalid) => {
                return String::from("error: keystore rejected the sign request as invalid")
            }
        };

        // The adversarial case, same shape as lantern-example-signer's own `probe`: an
        // ungranted slot must read back `none`, never a leaked handle.
        let ungranted = if keystore::open(1).is_none() { "none" } else { "LEAKED" };

        let mut sig_prefix = String::new();
        for byte in signature.iter().take(6) {
            sig_prefix.push_str(&format!("{byte:02x}"));
        }

        format!(
            "ok: signed {} bytes with the granted key — ed25519 sig = {sig_prefix}… ({} bytes); \
             keystore.open(1)={ungranted}",
            MESSAGE.len(),
            signature.len(),
        )
    }
}

export!(Probe);
