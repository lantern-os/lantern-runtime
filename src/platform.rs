//! Wasmtime 48's `sys/custom` C API
//! (`wasmtime/src/runtime/vm/sys/custom/capi.rs`), implemented for a
//! single-threaded, bare-metal LanternOS confined program
//! ([ADR-0023](../https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0023-wasmtime-no-std-pulley-hosting.md)).
//! **Folded in from `lantern-runtime/riscv64-probe`'s own groundwork** — that
//! crate proved the whole stack (Wasmtime `no_std` + Pulley + this platform
//! shim) builds, links, and runs a component under the real kernel; this is
//! the same logic living in this crate's own `no_std`/`confined` build
//! instead of a separate standalone proof-of-concept crate, so
//! [`crate::host`]'s real `IpcKeystore`/`IpcFilesystem` can eventually run
//! inside an actual confined `lantern-runtime` process. Only compiled for
//! `target_arch = "riscv64"` + `feature = "confined"` (`lib.rs`'s `pub mod
//! platform` declaration) — this crate's `std` (host) build never sees it,
//! Wasmtime's own native platform handles memory there.
//!
//! **Virtual memory is real `Frame`-backed**: a confined `lantern-runtime`
//! process needs a bounded pool of *unmapped* `FrameMega` capabilities plus a
//! capability to its own VSpace, granted by whatever launches it
//! (`lantern-boot`'s `ProgramSpec::arena`/`launch::ArenaGrant`,
//! [RFC-0018](../https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0018-confined-execution-port.md) Part
//! 3's "retype `Untyped` → `Frame`, `FrameInvoke::Map`/`Unmap` into the
//! runtime's VSpace at a reserved virtual range") — [`backing`] maps/unmaps
//! them itself, on demand, as Wasmtime's `wasmtime_mmap_new`/`wasmtime_munmap`
//! are called — real syscalls, not a `.bss` bump array. Getting this working
//! for `riscv64-probe` found a real, previously-unexercised `lantern-kernel`
//! bug (a confined program's own `FrameInvoke::Map`, after its own paging is
//! active, couldn't dereference its own VSpace's root table) — fixed by
//! `lantern-kernel`'s `KernelPageTables` (see that type's doc).
//!
//! **The exact `ArenaGrant` slot numbers below are `riscv64-probe`'s own
//! convention, copied verbatim as a starting point — no `lantern-boot` loader
//! grants *this* crate anything yet.** Whatever eventually loads a real
//! confined `lantern-runtime` binary (a new demo, not built here) must grant
//! an `ArenaGrant` whose `self_vspace_dest`/`frame_dest_base`/`megapages`
//! match [`SELF_VSPACE_CPTR`]/[`ARENA_FRAME_CPTR_BASE`]/[`REGIONS`] below (or
//! this module's constants get updated to match whatever that loader picks —
//! the two sides just need to agree, the same "duplicated shared constant"
//! convention every `lantern-boot` demo/program pair already uses).
//!
//! TLS is one static pointer; the sync primitives are uncontended no-ops
//! (single hart, non-reentrant — [ADR-0010](../https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0010-kernel-concurrency-model.md)).
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

// --- virtual memory: a bounded pool of granted, initially-unmapped Frames ---

mod backing {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use lantern_abi::sys::frame as frame_sys;
    use lantern_abi::wire::MapPerms;

    /// See the module doc's "no loader grants this yet" note — copied from
    /// `riscv64-probe/src/platform.rs`'s own identical constant as a
    /// starting point, not yet validated against a real loader for this crate.
    const ARENA_VADDR: usize = 0x8820_0000;
    /// `FrameMega` (2 MiB) only, never `FrameSmall` — this project's loader
    /// uses 2 MiB pages exclusively, a documented QEMU 3-level-Sv39-walk
    /// workaround (`lantern-hal/STATUS.md`); `FrameSmall` is correct and
    /// host-tested but not exercised on that path, so this arena doesn't
    /// risk an unrelated, unexercised code path to get finer granularity.
    const MEGAPAGE_BYTES: usize = 2 * 1024 * 1024;
    /// How many (initially unmapped) `FrameMega`s a loader is expected to
    /// grant, at consecutive `ARENA_FRAME_CPTR_BASE..` slots. A real
    /// (non-trivial) guest component's actual working set is what should
    /// drive this once one exists — copied from `riscv64-probe`'s own
    /// trivial-component sizing for now.
    const REGIONS: usize = 2;
    const ARENA_FRAME_CPTR_BASE: usize = 7;
    /// This program's own VSpace capability, expected at
    /// `ArenaGrant::self_vspace_dest`, so it can name itself as
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
    /// `lantern-kernel`'s `KernelPageTables`).
    static NEXT_REGION: AtomicUsize = AtomicUsize::new(0);

    fn slots() -> (&'static mut [usize; REGIONS], &'static mut [usize; REGIONS]) {
        // SAFETY: single hart, non-reentrant confined program (ADR-0010) —
        // same discipline this project's other confined-program statics rely on.
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
    /// a harmless no-op, matching `wasmtime_munmap`'s documented contract for
    /// a caller that never actually granted this region.
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
/// contract of Wasmtime's own `wasmtime_mmap_remap` declaration.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_mmap_remap(addr: *mut u8, size: usize, _prot_flags: u32) -> c_int {
    // "Replace with a fresh blank mapping." Every backing page is already its
    // own distinct region (no address is ever reused while live), so zeroing
    // the range in place is equivalent.
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
