# lantern-runtime

The **user-space runtime**: the service framework that system services are built on, and the
**WASM runtime** that hosts portable, sandboxed applications and agents.

- **Layer:** runtime (confined user space).
- **Decision of record:** [ADR-0003 — WebAssembly as the portable application ABI](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0003-wasm-as-portable-app-abi.md).
- **System context:** [wiki/Runtime](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Runtime.md).

> ⚠️ **Phase 0.** Design only; no code. See [`STATUS.md`](./STATUS.md).

## Two parts
- **Service framework** — endpoints over kernel IPC, badged multiplexing, capability
  brokering (with [`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)), the narrowing-waterfall
  startup.
- **WASM runtime** — WebAssembly Component Model + WASI Preview 2, but with **capability-backed
  WASI** (no ambient host access). AOT-compiled, validated, confined.

## In this repo
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`STATUS.md`](./STATUS.md).
