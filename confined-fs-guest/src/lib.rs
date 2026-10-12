//! RFC-0018's filesystem-path confined guest component. Compiles to a WebAssembly
//! **component** whose entire import surface is `lantern:host/filesystem`
//! (RFC-0016/ADR-0019) — the filesystem twin of `../confined-probe-guest`. Imports no
//! `wasi:*` interface it can call and has no ambient authority: no paths, no
//! directories, no way to create or name a file. It reaches a file only through a
//! manifest slot the host granted.

wit_bindgen::generate!({
    world: "fs-probe",
    path: "wit",
    generate_all,
});

use crate::lantern::host::filesystem;

/// What this guest writes. Must fit `lantern-filesystem`'s `MAX_BLOCK_LEN` (256).
const CONTENT: &[u8] = b"lantern-runtime confined-fs-guest v0: written by a confined Wasm guest";

/// One byte past `MAX_BLOCK_LEN`: v0 `Store` holds one block per file, and the WIT
/// contract says an oversized write is `invalid`, never a partial write.
const OVERSIZED_LEN: usize = 257;

struct Probe;

impl Guest for Probe {
    fn probe() -> String {
        // The granted case: slot 0 is expected to hold a real file scoped to at least
        // READ|WRITE (the launcher's own job to have arranged that grant).
        let Some(file) = filesystem::open(0) else {
            return String::from("error: the manifest granted no file at filesystem slot 0");
        };

        // A fresh file reads back empty, not an error (WIT: "an unwritten file reads as
        // empty").
        match file.read() {
            Ok(bytes) if bytes.is_empty() => {}
            Ok(bytes) => return format!("error: a fresh file read back {} bytes, not 0", bytes.len()),
            Err(e) => return format!("error: reading the fresh file failed: {e:?}"),
        }

        if let Err(e) = file.write(CONTENT) {
            return format!("error: write failed: {e:?}");
        }
        match file.read() {
            Ok(bytes) if bytes == CONTENT => {}
            Ok(bytes) => return format!("error: read back {} bytes that don't match what was written", bytes.len()),
            Err(e) => return format!("error: read-back failed: {e:?}"),
        }

        // Adversarial: an oversized write must be refused outright, and must not
        // clobber what's already there.
        let oversized = match file.write(&[0xAA; OVERSIZED_LEN]) {
            Err(filesystem::ErrorCode::Invalid) => "invalid",
            Err(filesystem::ErrorCode::Access) => return String::from("error: oversized write denied as access, not invalid"),
            Ok(()) => return String::from("error: an oversized write was accepted"),
        };
        match file.read() {
            Ok(bytes) if bytes == CONTENT => {}
            Ok(_) => return String::from("error: a refused oversized write still changed the file"),
            Err(e) => return format!("error: read after the refused write failed: {e:?}"),
        }

        // Adversarial, same shape as confined-probe-guest: an ungranted slot must read
        // back `none`, never a leaked handle.
        let ungranted = if filesystem::open(1).is_none() { "none" } else { "LEAKED" };

        format!(
            "ok: wrote and read back {} bytes; oversized write={oversized}, content intact; \
             filesystem.open(1)={ungranted}",
            CONTENT.len(),
        )
    }
}

export!(Probe);
