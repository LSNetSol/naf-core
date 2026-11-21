# naf-core

**Status: pre-alpha. Not for production use.**

`naf-core` is the open core of a closed-loop network assurance framework for operators of critical communications networks, maintained by LS Network Solutions LLC. It is organized exactly as in the published *Architecture - HLD & LLD* (high-level and low-level design):

1. **Verify** every configuration change before it reaches production (M1).
2. **Detect** routing incidents (BGP route leaks and hijacks), DDoS and configuration drift from streaming telemetry (M2).
3. **Remediate** only through pre-approved, auditable, reversible runbooks under Zero Trust controls, starting in observe-only mode (M3, M4).

Standards used: gNMI/OpenConfig, BMP (RFC 7854), RPKI origin validation (RFC 6811, RFC 8210), NETCONF (RFC 6241), RESTCONF (RFC 8040), YANG (RFC 7950), Zero Trust (NIST SP 800-207).

## Map from the design to the code

| Design layer | Module | File | v0.2 status |
|---|---|---|---|
| 1. Collect: BMP | BMP parsers (RFC 7854) | `src/naf/collect/bmp.py` | Headers parsed and tested; live session planned v0.5 |
| 1. Collect: RPKI | RTR IPv4 PDU parser (RFC 8210) | `src/naf/collect/rtr.py` | Parser tested; live session planned v0.5 |
| 1. Collect: syslog / IPFIX | RFC 5424 parser; IPFIX interface | `src/naf/collect/syslog_ipfix.py` | Syslog parsed; IPFIX planned v0.5 |
| 1. Collect: gNMI | Notification parser; subscribe interface | `src/naf/collect/gnmi.py` | Parser tested; live subscribe planned v0.5 |
| 2. Stream and store | Normalized event schema | `src/naf/normalize.py` | Schema and validation; message bus and store planned v0.5 |
| 3. Decide: M1 Verify | Pre-change rules | `src/naf/verify.py` | Rules implemented and tested; Batfish and lab integration planned v0.5 |
| 3. Decide: M2 Detect | RFC 6811 validation; valley-free leak check; detectors | `src/naf/rpki.py`, `leak.py`, `detectors.py` | Implemented and tested on synthetic data |
| 3. Decide: policy gate | Signed runbooks, scope, cap, autonomy, approval | `src/naf/policy.py` | Implemented and tested (demo HMAC signature) |
| 3. Act: M3 Remediate | Snapshot, apply, verify, rollback executor | `src/naf/remediate.py` | Executor and fake driver tested; NETCONF/gNMI drivers planned v1.0 |
| M4 Guardrails | Short-lived scoped tokens; dual approval | `src/naf/guardrails.py` | Implemented and tested (demo HMAC) |
| 4. Operate and report | Hash-chained evidence log; incident record export | `src/naf/evidence.py`, `report.py` | Implemented and tested |

Everything runs on synthetic data from documentation ranges (RFC 5737 prefixes, RFC 5398 AS numbers); no real network is touched.

## Quick start

```bash
python3 -m unittest discover -s tests -v      # no third-party dependencies
python3 examples/demo.py                      # replays a synthetic route leak end to end
```

## Safety principles

* **When uncertain, observe.** Stale, missing or contradictory data produces an alert, not an action.
* **Graduated autonomy.** Level 0 observe, Level 1 act with human approval, Level 2 act within pre-approved limits, Level 3 broader automation after a track record. Each operator chooses.
* **Every action is reversible and recorded.** No change without a snapshot and a rollback path.
* **No offensive capability.** The framework contains no exploit code and acts only with credentials the operator provides.

## Roadmap

| Version | Scope |
|---|---|
| v0.2 | Code for every layer of the design: parsers, schema, M1 rules, M2 detectors, policy gate, M3 executor, M4 guardrails, evidence and reporting |
| v0.5 | Live gNMI and BMP collectors, containerlab test scenarios, evaluation report with precision and recall |
| v1.0 | Real device drivers, asymmetric signing, independent security review |

## Contributing and security

See `CONTRIBUTING.md` and `SECURITY.md`. Licensed under the Apache License 2.0 (see `LICENSE` and `NOTICE`).
The names and marks of the project are not licensed for use with modified versions that could be mistaken for the original.
