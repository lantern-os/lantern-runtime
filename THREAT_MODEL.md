# lantern-runtime — Threat Model

Inherits the [system threat model](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Threat-Model.md). The runtime hosts
**untrusted code** (apps and AI agents), so its confinement guarantees are central
(system threat T4).

## Assets
- Isolation of each hosted component from the others and from the host.
- Integrity of the capability-backed WASI boundary (no ambient leakage).
- Correctness of Wasm validation/AOT compilation.

## Threats and mitigations
| # | Threat | Mitigation |
| --- | --- | --- |
| R1 | A Wasm component gains ambient host access | Capability-backed WASI only; no preopens; host functions gate on held caps. |
| R2 | Sandbox escape via engine bug | Engine is confined user space; memory-safe Rust; validate before execute; engine bug ≠ kernel compromise. |
| R3 | Fingerprinting via clock/RNG/env | Minimise and mediate these host interfaces. |
| R4 | Resource exhaustion / DoS by a component | Per-component CPU/memory budgets via scheduling contexts. |
| R5 | Malicious WIT interface confusion | Typed, versioned interfaces; governed ABI; capability checks on host calls. |
| R6 | Compromised service abuses brokered caps | Brokers confined; least privilege; revocation. |

## Non-goals
- Defending the kernel from the runtime — that is the kernel's job (the runtime is untrusted
  by the kernel like any component).
- Microarchitectural side channels between components (system non-goal at Phase 0).
