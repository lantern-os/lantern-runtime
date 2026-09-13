//! Wasmtime 48's `sys/custom` C API
//! (`wasmtime/src/runtime/vm/sys/custom/capi.rs`), implemented for a
//! single-threaded, bare-metal LanternOS confined program
//! ([ADR-0023](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0023-wasmtime-no-std-pulley-hosting.md)).
//!
//! **First cut.** Virtual memory is a fixed bump arena in `.bss`, not real
//! `FrameInvoke::Map` yet — enough to prove the whole stack builds, links, and
//! runs a Pulley component. TLS is one static pointer; the sync primitives are
//! uncontended no-ops (single hart, non-reentrant — [ADR-0010](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0010-kernel-concurrency-model.md)).
//! `wasmtime_memory_image_*` reports "unsupported" so Wasmtime zero-fills
//! instead.
//!
//! The symbol set here matches wasmtime 48 with features `runtime`,
//! `component-model`, `pulley`, `custom-virtual-memory`,
//! `custom-sync-primitives` and **not** `custom-native-signals` /
//! `component-model-async`: no `wasmtime_init_traps`, no `wasmtime_fiber_*`.
//! A Wasmtime bump re-checks this list against its `capi.rs`.

use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

// --- page size -----------------------------------------------------------

/// LanternOS uses 4 KiB pages (`lantern_hal::RISCV64_PAGE_SIZE`).
#[no_mangle]
pub extern "C" fn wasmtime_page_size() -> usize {
    4096
}

// --- virtual memory: a fixed .bss bump arena ---------------------------

/// Address space for Wasm linear memories and Wasmtime's own mappings. A
/// `static` so it needs no allocator and no syscalls; `align(4096)` makes every
/// hand-out page-aligned. **256 KiB** — empirically the smallest round number
/// above what this probe's trivial component actually needs (found by
/// bisecting down from an initial 64 MiB guess: `cargo test` first fails
/// somewhere between 64 KiB and 128 KiB, so this keeps ~2x margin) — small
/// enough to fit in a single `lantern-kernel` `FrameMega` (2 MiB), unlike the
/// original 64 MiB guess, which alone would have needed ~32 of the kernel's
/// only 16 total `MAX_FRAMES` (`lantern-kernel/src/limits.rs`) — categorically
/// unloadable, not just large. A real (non-trivial) guest component's own
/// working set is a separate, later question; the real version retypes
/// `Untyped` → `Frame` and maps on demand via `lantern-abi` instead of a fixed
/// arena regardless of size.
const ARENA_BYTES: usize = 256 * 1024;

#[repr(C, align(4096))]
struct Arena([u8; ARENA_BYTES]);

static mut ARENA: Arena = Arena([0; ARENA_BYTES]);
static ARENA_NEXT: AtomicUsize = AtomicUsize::new(0);

fn arena_base() -> usize {
    core::ptr::addr_of!(ARENA) as usize
}

/// Bump `size` bytes (rounded up to a page) off the arena. Returns 0 on
/// exhaustion. Never reclaims — matches Phase 1's `Untyped` bump discipline.
fn arena_alloc(size: usize) -> usize {
    let size = (size + 4095) & !4095;
    let mut off = ARENA_NEXT.load(Ordering::Relaxed);
    loop {
        let new = match off.checked_add(size) {
            Some(v) if v <= ARENA_BYTES => v,
            _ => return 0,
        };
        match ARENA_NEXT.compare_exchange_weak(off, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return arena_base() + off,
            Err(cur) => off = cur,
        }
    }
}

#[no_mangle]
pub extern "C" fn wasmtime_mmap_new(size: usize, _prot_flags: u32, ret: &mut *mut u8) -> c_int {
    match arena_alloc(size) {
        0 => 1,
        p => {
            *ret = p as *mut u8;
            0
        }
    }
}

/// # Safety
/// `addr..addr+size` must be a region previously returned by
/// [`wasmtime_mmap_new`] that Wasmtime owns for the duration of this call — the
/// contract of Wasmtime's own `wasmtime_mmap_remap` declaration.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_mmap_remap(addr: *mut u8, size: usize, _prot_flags: u32) -> c_int {
    // "Replace with a fresh blank mapping." The arena stays mapped RW and never
    // reuses an address, so zeroing the range in place is equivalent.
    // SAFETY: forwarded from this function's own contract.
    unsafe { core::ptr::write_bytes(addr, 0, size) };
    0
}

#[no_mangle]
pub extern "C" fn wasmtime_munmap(_ptr: *mut u8, _size: usize) -> c_int {
    0 // bump arena: no reclaim
}

#[no_mangle]
pub extern "C" fn wasmtime_mprotect(_ptr: *mut u8, _size: usize, _prot_flags: u32) -> c_int {
    // Pulley does explicit bounds checks — there are no guard pages to arm and
    // no executable mappings to grant. Every arena page is already RW.
    0
}

// --- memory images: unsupported (Wasmtime falls back to zero-fill) -----

#[no_mangle]
pub extern "C" fn wasmtime_memory_image_new(
    _ptr: *const u8,
    _len: usize,
    ret: &mut *mut c_void,
) -> c_int {
    *ret = core::ptr::null_mut(); // NULL + rc 0 = "no image, but not an error"
    0
}

#[no_mangle]
pub extern "C" fn wasmtime_memory_image_map_at(
    _image: *mut c_void,
    _addr: *mut u8,
    _len: usize,
) -> c_int {
    1 // never called — `_new` always yields NULL
}

#[no_mangle]
pub extern "C" fn wasmtime_memory_image_free(_image: *mut c_void) {}

// --- TLS: one static pointer (single-threaded) ------------------------

static TLS: AtomicUsize = AtomicUsize::new(0);

#[no_mangle]
pub extern "C" fn wasmtime_tls_get(_slot: usize) -> *mut u8 {
    // `component-model-async` is off, so `slot` is always 0.
    TLS.load(Ordering::Relaxed) as *mut u8
}

#[no_mangle]
pub extern "C" fn wasmtime_tls_set(_slot: usize, ptr: *mut u8) {
    TLS.store(ptr as usize, Ordering::Relaxed);
}

// --- sync: uncontended no-ops (single hart, non-reentrant) ------------

#[no_mangle]
pub extern "C" fn wasmtime_sync_lock_free(_lock: *mut usize) {}
#[no_mangle]
pub extern "C" fn wasmtime_sync_lock_acquire(_lock: *mut usize) {}
#[no_mangle]
pub extern "C" fn wasmtime_sync_lock_release(_lock: *mut usize) {}
#[no_mangle]
pub extern "C" fn wasmtime_sync_rwlock_read(_lock: *mut usize) {}
#[no_mangle]
pub extern "C" fn wasmtime_sync_rwlock_read_release(_lock: *mut usize) {}
#[no_mangle]
pub extern "C" fn wasmtime_sync_rwlock_write(_lock: *mut usize) {}
#[no_mangle]
pub extern "C" fn wasmtime_sync_rwlock_write_release(_lock: *mut usize) {}
#[no_mangle]
pub extern "C" fn wasmtime_sync_rwlock_free(_lock: *mut usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arena_hands_out_page_aligned_distinct_regions_then_exhausts() {
        let mut a = core::ptr::null_mut();
        assert_eq!(wasmtime_mmap_new(4096, 0, &mut a), 0);
        assert_eq!(a as usize % 4096, 0);

        let mut b = core::ptr::null_mut();
        assert_eq!(wasmtime_mmap_new(1, 0, &mut b), 0); // rounds to a page
        assert_eq!(b as usize, a as usize + 4096);

        // Way past the arena -> non-zero rc, no panic.
        let mut c = core::ptr::null_mut();
        assert_ne!(wasmtime_mmap_new(ARENA_BYTES * 2, 0, &mut c), 0);
    }

    #[test]
    fn tls_slot_roundtrips() {
        let p = 0xdead_beef_usize as *mut u8;
        wasmtime_tls_set(0, p);
        assert_eq!(wasmtime_tls_get(0), p);
        wasmtime_tls_set(0, core::ptr::null_mut());
    }
}
