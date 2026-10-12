//! Regenerates a checked-in Pulley `.cwasm` fixture (e.g.
//! `confined-probe-guest/assets/probe.pulley.cwasm`) from a `wasm32-wasip2` component, via
//! this crate's own compiler role — so the fixture always matches
//! [`lantern_runtime::runtime_engine`]'s `Config` (target, fuel, memory reservation), which
//! Wasmtime checks on every deserialize.
//!
//! ```text
//! cargo run --example precompile --features compiler -- <in.wasm> <out.cwasm>
//! ```

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, input, output] = args.as_slice() else {
        eprintln!("usage: precompile <in.wasm> <out.cwasm>");
        std::process::exit(2);
    };
    let wasm = std::fs::read(input).expect("read input component");
    let cwasm = lantern_runtime::compiler::compiler_engine()
        .precompile_component(&wasm)
        .expect("precompile for pulley64");
    std::fs::write(output, &cwasm).expect("write output .cwasm");
    println!("{input} -> {output} ({} bytes)", cwasm.len());
}
