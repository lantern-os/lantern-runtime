# lantern-runtime — Architecture

Companion to [wiki/Runtime](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Runtime.md). Bound by
[ADR-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0003-wasm-as-portable-app-abi.md).

## Service framework
- **Endpoints** over kernel IPC with **badges** so a service safely multiplexes mutually
  distrusting clients.
- **Capability brokering**: mint/grant/revoke surface from [`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities).
- **Narrowing-waterfall startup**: each service receives exactly the caps it needs from the
  root task and no more ([Architecture](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Architecture.md)).

## WASM runtime
- **Component Model + WASI Preview 2** as the app ABI; **WIT** interfaces are the typed
  contract surface the [SDK](https://github.com/lantern-os/lantern-sdk) binds against.
- **Capability-backed WASI (the key twist):** every host/WASI interface is backed by a
  LanternOS object capability. No preopened directories, no ambient sockets, minimised
  clock/RNG/env (a fingerprinting concern). A component does exactly what its caps permit.
- **Execution:** AOT-compiled and validated before running; no JIT in sensitive contexts.
- **Confinement:** the engine itself is a confined user-space service — an engine bug is
  bounded by *its* capabilities, not the kernel's.

## Native vs. Wasm
TCB and performance-critical services are native Rust; the untrusted, portable app/agent tier
is Wasm. AI agents run here ([`lantern-ai-runtime`](https://github.com/lantern-os/lantern-ai-runtime) builds on this).

## Open questions
- Which Wasm engine to adopt/build on; the AOT pipeline shape.
- Pinning/versioning the WASI/Component-Model surface as a governed public ABI.
- WIT-handle ⇄ LanternOS capability mapping.
- Per-component resource accounting tied to scheduling contexts.
