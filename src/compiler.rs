//! The offline compiler role ([RFC-0013](../https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0013-wasm-engine-selection-and-aot-strategy.md)/
//! [ADR-0017](../https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0017-wasm-engine-selection-and-aot-strategy.md)):
//! compile ahead-of-time via Cranelift, then sign. Only ever built with the `compiler`
//! Cargo feature — never part of the confined runtime-role build (see this crate's
//! top-level doc and `Cargo.toml`). Where this actually runs (SDK build tooling vs. an
//! on-device install-time service) is `lantern-sdk`/packaging's decision, not this
//! module's — this file fixes only that it is never the running per-component process.

use lantern_crypto::signing::{SigningKey, SIGNATURE_LEN};
use wasmtime::{Config, Engine};

#[derive(Debug)]
pub enum CompileError {
    Wasmtime(wasmtime::Error),
}

/// A compiler-role [`Engine`] — Component Model + Cranelift. Distinct from
/// [`crate::verified::runtime_engine`] on purpose: the two roles never share a `Config`
/// any more than they share a build.
pub fn compiler_engine() -> Engine {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Engine::new(&config).expect("a component-model Config is always valid")
}

/// Compiles a `.wasm`/`.wat` component ahead-of-time and signs the resulting `.cwasm`
/// artifact under `signing_key`, ready for a runtime-role
/// [`crate::verified::load_verified_component`] call elsewhere (a different process,
/// typically — see this module's top-level doc).
pub fn precompile_and_sign(
    engine: &Engine,
    wasm_or_wat: &[u8],
    signing_key: &SigningKey,
) -> Result<(Vec<u8>, [u8; SIGNATURE_LEN]), CompileError> {
    let cwasm = engine.precompile_component(wasm_or_wat).map_err(CompileError::Wasmtime)?;
    let signature = signing_key.sign(&cwasm);
    Ok((cwasm, signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verified::{load_verified_component, runtime_engine};
    use lantern_crypto::signing::{SigningKey, SEED_LEN};

    const WAT: &str = r#"
        (component
          (core module $m
            (func (export "run") (result i32) i32.const 42))
          (core instance $i (instantiate $m))
          (func (export "run") (result s32) (canon lift (core func $i "run"))))
    "#;

    /// The mechanism RFC-0013 fixes, end to end: compile, sign, hand the bytes to a
    /// *fresh* runtime-role engine (a different process in a real deployment), verify,
    /// deserialize, instantiate, and call — proving the split is real, not just a
    /// paper distinction, since the runtime role here never touches the compiler.
    #[test]
    fn round_trips_through_compile_sign_verify_deserialize_run() {
        let key = SigningKey::from_random_bytes([3u8; SEED_LEN]);
        let compiler = compiler_engine();
        let (cwasm, sig) = precompile_and_sign(&compiler, WAT.as_bytes(), &key).unwrap();

        let runtime = runtime_engine();
        let component = load_verified_component(&runtime, &cwasm, &key.verifying_key(), &sig).unwrap();

        let mut store = wasmtime::Store::new(&runtime, ());
        let linker = wasmtime::component::Linker::new(&runtime);
        let instance = linker.instantiate(&mut store, &component).unwrap();
        let func = instance.get_typed_func::<(), (i32,)>(&mut store, "run").unwrap();
        let (result,) = func.call(&mut store, ()).unwrap();
        assert_eq!(result, 42);
    }
}
