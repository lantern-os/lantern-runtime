# lantern-runtime — Status

**Phase:** 2 (Capability runtime & first services) — open per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md). Still substantively blocked — see "Blocked on".

## Done
- Service framework + WASM runtime split documented and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Capability-backed WASI approach fixed ([ADR-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0003-wasm-as-portable-app-abi.md)).
- Threat model drafted and reviewed.

## Next
- Select a Wasm engine and AOT strategy.
- Specify the WIT-handle ⇄ capability mapping.
- Phase 2: host a confined Wasm app that reaches a file only via a granted capability.

## Blocked on
- ~~Kernel IPC/endpoints ([`lantern-kernel`](https://github.com/lantern-os/lantern-kernel)).~~
  Resolved — RFC-0009/ADR-0014.
- Capability brokering API ([`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities))
  — still open; `lantern-capabilities` is itself only just unblocked (RFC-0009/ADR-0014)
  and has no brokering prototype code yet.
