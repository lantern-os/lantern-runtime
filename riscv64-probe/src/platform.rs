//! Wasmtime 48's `sys/custom` C API
//! (`wasmtime/src/runtime/vm/sys/custom/capi.rs`), implemented for a
//! single-threaded, bare-metal LanternOS confined program
//! ([ADR-0023](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0023-wasmtime-no-std-pulley-hosting.md)).
//!
//! **Virtual memory is real `Frame`-backed on `riscv64`** (feature `bin`):
//! `lantern-boot`'s launcher grants this program a bounded pool of
//! *unmapped* `FrameMega` capabilities plus a capability to its own VSpace
//! (`ProgramSpec::arena`/`launch::ArenaGrant`,
//! [RFC-0018](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0018-confined-execution-port.md) Part
//! 3's "retype `Untyped` → `Frame`, `FrameInvoke::Map`/`Unmap` into the
//! runtime's VSpace at a reserved virtual range"), and `backing` maps/unmaps
//! them itself, on demand, as Wasmtime's `wasmtime_mmap_new`/`wasmtime_munmap`
//! are called — real syscalls, not a `.bss` bump array. Getting this working
//! end to end found a real, previously-unexercised `lantern-kernel` bug (a
//! confined program's own `FrameInvoke::Map`, after its own paging is
//! active, couldn't dereference its own VSpace's root table) — fixed by
//! `lantern-kernel`'s `KernelPageTables` (see that type's doc). A host
//! `cargo test` build (no `lantern-abi`, no real kernel to `ecall` into)
//! keeps the original static-arena behaviour instead, so the execution test
//! this crate's own `cargo test` runs still exercises every other platform
//! symbol without needing real hardware.
//!
//! TLS is one static pointer; the sync primitives are uncontended no-ops
//! (single hart, non-reentrant — [ADR-0010](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0010-kernel-concurrency-model.md)).
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

// --- virtual memory backing store -----------------------------------------

/// The real `riscv64` backing: a bounded pool of granted, initially-unmapped
/// `FrameMega` capabilities, mapped/unmapped into this program's own VSpace
/// on demand via `lantern-abi`'s `FrameInvoke` wrappers. Only compiled for
/// the actual bare-metal binary (`feature = "bin"` is what pulls in
/// `lantern-abi` at all — see `Cargo.toml`); a plain `cargo check --target
/// riscv64gc-unknown-none-elf` without it falls back to the other `mod
/// backing` below instead of failing to resolve the crate.
#[cfg(all(target_arch = "riscv64", feature = "bin"))]
mod backing {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use lantern_abi::sys::frame as frame_sys;
    use lantern_abi::wire::MapPerms;

    /// Must match `lantern-boot/src/wasm_probe_demo/loader.rs`'s own
    /// `PROBE_ARENA_FRAME_CPTR_BASE`/`PROBE_SELF_VSPACE_CPTR`/
    /// `PROBE_ARENA_MEGAPAGES`, and `lantern-boot/src/launch.rs`'s
    /// `ARENA_VADDR` — the same "duplicated shared constant" convention
    /// `../main.rs`'s `HEAP_BASE`/`HEAP_LEN` already established (this
    /// crate has no dependency on `lantern-boot`).
    const ARENA_VADDR: usize = 0x8820_0000;
    /// `FrameMega` (2 MiB) only, never `FrameSmall` — this project's loader
    /// uses 2 MiB pages exclusively, a documented QEMU 3-level-Sv39-walk
    /// workaround (`lantern-hal/STATUS.md`); `FrameSmall` is correct and
    /// host-tested but not exercised on that path, so this arena doesn't
    /// risk an unrelated, unexercised code path to get finer granularity.
    const MEGAPAGE_BYTES: usize = 2 * 1024 * 1024;
    /// How many (initially unmapped) `FrameMega`s the loader grants, at
    /// consecutive `ARENA_FRAME_CPTR_BASE..` slots in this program's own
    /// CSpace. Must match `PROBE_ARENA_MEGAPAGES`.
    const REGIONS: usize = 2;
    const ARENA_FRAME_CPTR_BASE: usize = 7;
    /// This program's own VSpace capability, granted by the loader
    /// (`ArenaGrant::self_vspace_dest`) so it can name itself as
    /// `FrameInvoke::Map`/`Unmap`'s target.
    const SELF_VSPACE_CPTR: usize = 6;

    /// Parallel arrays, one slot per in-flight `wasmtime_mmap_new` grant:
    /// `ALLOC_COUNT[i] == 0` means the slot is free. `ALLOC_VADDR[i]` is
    /// always nonzero for an occupied slot ([`ARENA_VADDR`] is never zero),
    /// so `count == 0` alone is an unambiguous "empty" test. Plain fixed-size
    /// arrays rather than `Option<_>` — no dependency on an array-repeat
    /// `const` block, and matches this project's fixed-capacity-pool style
    /// (`lantern-kernel/src/limits.rs`).
    static mut ALLOC_VADDR: [usize; REGIONS] = [0; REGIONS];
    static mut ALLOC_COUNT: [usize; REGIONS] = [0; REGIONS];
    /// Bump index into the granted region pool. Never rewound on `dealloc`
    /// (only the mapping itself is really `Unmap`ped) — matches every other
    /// bump-allocation discipline this project uses (`Untyped`, `BumpAlloc`,
    /// the `fallback` arena this module replaces).
    static NEXT_REGION: AtomicUsize = AtomicUsize::new(0);

    fn slots() -> (&'static mut [usize; REGIONS], &'static mut [usize; REGIONS]) {
        // SAFETY: single hart, non-reentrant confined program (ADR-0010) —
        // same discipline this crate's `BumpAlloc`/the fallback arena's own
        // `static mut` already rely on.
        unsafe { (&mut *core::ptr::addr_of_mut!(ALLOC_VADDR), &mut *core::ptr::addr_of_mut!(ALLOC_COUNT)) }
    }

    fn vaddr_of(region: usize) -> usize {
        ARENA_VADDR + region * MEGAPAGE_BYTES
    }

    /// Claim `ceil(size / MEGAPAGE_BYTES)` (at least one) not-yet-claimed
    /// `FrameMega`s from the granted pool and `FrameInvoke::Map` each into
    /// this program's own VSpace, contiguously. Returns the first region's
    /// base vaddr, or `None` on exhaustion.
    pub(crate) fn alloc(size: usize) -> Option<usize> {
        let count = size.div_ceil(MEGAPAGE_BYTES).max(1);
        let start = NEXT_REGION.load(Ordering::Relaxed);
        let end = start.checked_add(count)?;
        if end > REGIONS {
            return None;
        }
        NEXT_REGION.store(end, Ordering::Relaxed);

        let perms = MapPerms::READ.union(MapPerms::WRITE).union(MapPerms::USER);
        for region in start..end {
            let frame_cptr = ARENA_FRAME_CPTR_BASE + region;
            frame_sys::map(frame_cptr, SELF_VSPACE_CPTR, vaddr_of(region), perms)
                .expect("a granted arena Frame must map into this program's own VSpace");
        }

        let vaddr_base = vaddr_of(start);
        let (vaddrs, counts) = slots();
        let slot = counts.iter().position(|&c| c == 0)?;
        vaddrs[slot] = vaddr_base;
        counts[slot] = count;
        Some(vaddr_base)
    }

    /// `FrameInvoke::Unmap` every region a matching earlier [`alloc`] claimed.
    /// A `ptr` this module never handed out (or a stale double-`dealloc`) is
    /// a harmless no-op, matching `wasmtime_munmap`'s documented contract
    /// for a caller that never actually granted this region.
    pub(crate) fn dealloc(ptr: usize) {
        let (vaddrs, counts) = slots();
        let Some(slot) = (0..REGIONS).find(|&i| counts[i] != 0 && vaddrs[i] == ptr) else {
            return;
        };
        let count = counts[slot];
        let start = (ptr - ARENA_VADDR) / MEGAPAGE_BYTES;
        for region in start..start + count {
            let frame_cptr = ARENA_FRAME_CPTR_BASE + region;
            let _ = frame_sys::unmap(frame_cptr, SELF_VSPACE_CPTR);
        }
        vaddrs[slot] = 0;
        counts[slot] = 0;
    }
}

/// The `.bss` bump-arena fallback: host `cargo test` (no real kernel to
/// `ecall` into — `lantern-abi`'s own `raw()` is `unimplemented!()` off
/// `riscv64`), and any `riscv64` build without `feature = "bin"`. Identical
/// behaviour to this module's original "first cut" implementation.
#[cfg(not(all(target_arch = "riscv64", feature = "bin")))]
mod backing {
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// **256 KiB** — empirically the smallest round number above what this
    /// probe's trivial component actually needs (found by bisecting down
    /// from an initial 64 MiB guess: `cargo test` first fails somewhere
    /// between 64 KiB and 128 KiB, so this keeps ~2x margin).
    pub(crate) const ARENA_BYTES: usize = 256 * 1024;

    #[repr(C, align(4096))]
    struct Arena([u8; ARENA_BYTES]);

    static mut ARENA: Arena = Arena([0; ARENA_BYTES]);
    static ARENA_NEXT: AtomicUsize = AtomicUsize::new(0);

    fn arena_base() -> usize {
        core::ptr::addr_of!(ARENA) as usize
    }

    /// Bump `size` bytes (rounded up to a page) off the arena. Never
    /// reclaims — matches Phase 1's `Untyped` bump discipline.
    pub(crate) fn alloc(size: usize) -> Option<usize> {
        let size = (size + 4095) & !4095;
        let mut off = ARENA_NEXT.load(Ordering::Relaxed);
        loop {
            let new = off.checked_add(size).filter(|&v| v <= ARENA_BYTES)?;
            match ARENA_NEXT.compare_exchange_weak(off, new, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Some(arena_base() + off),
                Err(cur) => off = cur,
            }
        }
    }

    pub(crate) fn dealloc(_ptr: usize) {
        // bump arena: no reclaim
    }
}

#[no_mangle]
pub extern "C" fn wasmtime_mmap_new(size: usize, _prot_flags: u32, ret: &mut *mut u8) -> c_int {
    match backing::alloc(size) {
        None => 1,
        Some(p) => {
            *ret = p as *mut u8;
            0
        }
    }
}

/// # Safety
/// `addr..addr+size` must be a region previously returned by
/// [`wasmtime_mmap_new`] that Wasmtime owns for the duration of this call — the
/// contract of Wasmtime's own `wasmtime_mmap_remap` declaration. Holds
/// regardless of backing store: `addr` is always a live, writable mapping by
/// the time this is called.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_mmap_remap(addr: *mut u8, size: usize, _prot_flags: u32) -> c_int {
    // "Replace with a fresh blank mapping." Every backing page is already
    // its own distinct region (no address is ever reused while live), so
    // zeroing the range in place is equivalent.
    // SAFETY: forwarded from this function's own contract.
    unsafe { core::ptr::write_bytes(addr, 0, size) };
    0
}

#[no_mangle]
pub extern "C" fn wasmtime_munmap(ptr: *mut u8, _size: usize) -> c_int {
    backing::dealloc(ptr as usize);
    0
}

#[no_mangle]
pub extern "C" fn wasmtime_mprotect(_ptr: *mut u8, _size: usize, _prot_flags: u32) -> c_int {
    // Pulley does explicit bounds checks — there are no guard pages to arm and
    // no executable mappings to grant. Every backing page is already RW.
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
        assert_ne!(wasmtime_mmap_new(backing::ARENA_BYTES * 2, 0, &mut c), 0);
    }

    #[test]
    fn tls_slot_roundtrips() {
        let p = 0xdead_beef_usize as *mut u8;
        wasmtime_tls_set(0, p);
        assert_eq!(wasmtime_tls_get(0), p);
        wasmtime_tls_set(0, core::ptr::null_mut());
    }
}
