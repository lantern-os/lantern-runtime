# lantern-runtime — Status

**Phase:** 0 (Foundations) — design only.

## Done
- Service framework + WASM runtime split documented and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Capability-backed WASI approach fixed ([ADR-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0003-wasm-as-portable-app-abi.md)).
- Threat model drafted and reviewed.

## Next
- Select a Wasm engine and AOT strategy.
- Specify the WIT-handle ⇄ capability mapping.
- Phase 2: host a confined Wasm app that reaches a file only via a granted capability.

## Blocked on
- Capability brokering API ([`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)).
- Kernel IPC/endpoints ([`lantern-kernel`](https://github.com/lantern-os/lantern-kernel)).
