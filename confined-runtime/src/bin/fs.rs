//! `lantern-confined-runtime-fs` — the **filesystem** integration proof (see the crate
//! doc in `lib.rs` for what both binaries share). Hosts `../confined-fs-guest`, whose
//! `probe` export checks a fresh file reads empty, writes and reads it back, checks an
//! oversized write is refused without changing the content, and checks that slot 1
//! reads `none`.
//!
//! The grant behind slot 0 is [`IpcFilesystem`] over the shared `Frame` to a separately
//! confined `store-service`, scoped READ|WRITE to one file. The store-service in turn
//! encrypts every block through *its own* grant on a third confined program, the
//! `keystore-service` (`lantern_filesystem::cipher::ChannelCipher`). So the guest's
//! bytes are sealed at rest by a key that neither this process nor the guest can name.
//!
//! Steps: request the grant from the store-service; run the guest's `probe`; its report
//! must start `ok: ` and confirm the refused write and the `none` slot; signal.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;

use lantern_confined_runtime::{check_report, request_grant, run_and_report, run_probe, StageResult, DEST_CPTR, FRAME_VADDR};
use lantern_filesystem::FileId;
use lantern_runtime::{GrantManifest, HostFile, IpcFilesystem, RuntimeState};

lantern_abi::entry!(run);

/// `confined-fs-guest`, precompiled for `pulley64` by `lantern-runtime`'s compiler role
/// (`cargo run --example precompile --features compiler`).
const FS_PROBE_CWASM: &[u8] = include_bytes!("../../../confined-fs-guest/assets/fs-probe.pulley.cwasm");

fn run(_arg0: usize) -> ! {
    run_and_report(host_the_guest)
}

fn host_the_guest() -> StageResult<()> {
    request_grant()?;

    // SAFETY: the loader mapped the shared Frame read/write at FRAME_VADDR, in this
    // program's own VSpace only alongside the store-service's, for this program's life.
    let filesystem = unsafe { IpcFilesystem::new(DEST_CPTR, FRAME_VADDR as *mut u8) };
    // `IpcFilesystem` routes by the kernel-delivered badge, never by these (see
    // `FileId::from_raw`'s doc).
    let file = FileId::from_raw(0);

    // Slot 0 is the one grant; slot 1 is deliberately absent.
    let grants = || GrantManifest {
        filesystem_files: vec![Some(HostFile::filesystem_file(0, file))],
        ..Default::default()
    };
    let state = RuntimeState::new(grants()).with_filesystem(Box::new(filesystem));
    // SAFETY: `FS_PROBE_CWASM` is this repo's own trusted compiler-role output.
    let report = unsafe { run_probe(FS_PROBE_CWASM, &grants(), state) }?;
    check_report(&report, &["oversized write=invalid", "content intact", "filesystem.open(1)=none"])
}
