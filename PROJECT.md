# IPv6 Core RFC Conformance Test Suite

## 1. Project Purpose

Build a practical, reproducible IPv6 Core RFC conformance test suite for a specifically configured DUT.

The initial conformance scope is:

- RFC 8200 — Internet Protocol, Version 6 (IPv6) Specification
- RFC 8201 — Path MTU Discovery for IP version 6
- RFC 4861 — Neighbor Discovery for IP version 6
- RFC 4862 — IPv6 Stateless Address Autoconfiguration
- RFC 4443 — Internet Control Message Protocol for the Internet Protocol Version 6 (ICMPv6)

The operator-facing model is deliberately simple:

```text
uv run RFC-8200-conformance.py
uv run RFC-8201-conformance.py
uv run RFC-4861-conformance.py
uv run RFC-4862-conformance.py
uv run RFC-4443-conformance.py
```

Each RFC is represented by one independently executable, monolithic Python test program.

The suite is a conformance harness, not a packet-fuzzing framework. Tests must be bounded, deterministic, traceable to explicit requirements, and capable of producing evidence sufficient to support PASS, FAIL, INCONCLUSIVE, or NOT_APPLICABLE.

---

## 2. Source of Truth and Requirements

The supplied ER annexure is the authoritative source for explicit conformance requirements.

Do not silently:

- rewrite an ER clause;
- replace an ER clause with a newer RFC requirement;
- omit an inconvenient portion of a clause;
- change an expected result because Linux or another implementation behaves differently;
- declare a test compliant merely because a newer RFC contains related language.

Where interpretation is necessary, record the interpretation separately from the requirement.

### RFC 2460 / RFC 8200 distinction

If the supplied ER annexure identifies a requirement as RFC 2460, preserve that identity in the test matrix and test identifiers.

If RFC 8200 is used as implementation/reference context, record the distinction explicitly:

```text
ER requirement: RFC 2460
Implementation/reference: RFC 8200
```

Do not silently rename an ER test group.

---

## 3. Design Goals

The implementation should satisfy these goals:

1. **One-command RFC execution**
   - An operator should be able to run one RFC suite without learning an internal framework.

2. **Monolithic RFC units**
   - Each RFC gets one primary Python file.
   - The file contains its test definitions, execution flow, CLI, packet-generation adapters, observation logic, and result reporting.
   - Small shared helper modules are permitted only where they materially reduce duplication without obscuring the RFC test logic.

3. **Tool diversity**
   - Use THC-IPv6 / `thc-ipv6` where its existing primitives map directly to a requirement.
   - Use Fernando Gont's SI6 tools where they provide an appropriate stimulus or diagnostic.
   - Use Scapy to construct, mutate, parse, and inspect packets where the other tools do not provide sufficient control.
   - Do not make any one external tool the conformance oracle.

4. **Deterministic packet construction**
   - Fields relevant to a requirement must be explicitly controllable.
   - Scapy is the fallback for exact packet construction and packet parsing.

5. **Evidence-driven verdicts**
   - A tool exit code is not by itself a conformance verdict.
   - Packet captures and parsed observations should be preferred over human-readable command output where exact packet fields matter.

6. **No false PASS**
   - When evidence cannot establish the expected result, use `INCONCLUSIVE`.

7. **Safe live testing**
   - Tests target only explicitly configured test equipment.
   - No public Internet probing, uncontrolled scanning, flooding, or address exhaustion.

8. **Dry-run support**
   - Every packet-generation test should expose its intended stimulus without transmitting.

9. **Unit/live separation**
   - Ordinary unit tests must not transmit packets.
   - Live transmission requires an explicit integration/live execution path.

---

## 4. Target Repository Layout

Preferred layout:

```text
.
├── PROJECT.md
├── constraints.md
├── RFC-8200-conformance.py
├── RFC-8201-conformance.py
├── RFC-4861-conformance.py
├── RFC-4862-conformance.py
├── RFC-4443-conformance.py
├── tests/
│   ├── unit/
│   └── integration/
├── tools/
│   └── ...
└── results/
    └── <run timestamp>/
```

The five RFC programs are the primary operator-facing artifacts.

Do not turn the project into a mandatory heavyweight test framework merely for abstraction's sake.

---

## 5. RFC Test Program Contract

Every RFC program should support a common minimum CLI.

Example:

```text
usage: RFC-8200-conformance.py [options]

Required:
  --interface IFACE
  --source IPV6
  --target IPV6

Optional:
  --tests TEST,...
  --dry-run
  --timeout SECONDS
  --observation-timeout SECONDS
  --output DIR
  --pcap
  --verbose
```

The exact option names may be refined during implementation, but the behavior must remain consistent across the five RFC programs.

### Configuration

At minimum, the harness must allow explicit configuration of:

- test interface;
- source IPv6 address;
- destination IPv6 address;
- observation/capture interface;
- execution timeout;
- observation timeout;
- packet count;
- output/evidence directory;
- selected tests;
- dry-run mode.

Do not default to:

- public Internet destinations;
- arbitrary discovered IPv6 addresses;
- DNS-derived addresses;
- production interfaces.

---

## 6. Common Test Record

Each test should have enough metadata to make the result independently understandable.

Recommended structure:

```text
Test ID
RFC
RFC section
ER requirement
Description
Role
Preconditions
Stimulus
Expected behavior
Observation method
Evidence requirements
Verdict
```

Example:

```text
Test ID: 8200-EXT-001
RFC: RFC 8200
Section: <exact section>
ER requirement: <exact supplied requirement>

Role:
  HOST

Preconditions:
  IPv6 connectivity established

Stimulus:
  <precisely constructed IPv6 packet>

Expected:
  <observable expected behavior>

Observation:
  <packet/capture/state evidence>

Verdict:
  PASS / FAIL / INCONCLUSIVE / NOT_APPLICABLE
```

Do not invent RFC sections or ER requirements when the supplied annexure does not provide them. Populate the matrix from the authoritative requirements source.

---

## 7. Tooling Strategy

### 7.1 THC-IPv6

Use THC-IPv6 when an existing tool provides the exact or sufficiently precise stimulus required by a conformance test.

Invoke external tools through controlled subprocess execution.

Requirements:

- bounded execution time;
- explicit arguments;
- captured stdout/stderr;
- captured exit status;
- no uncontrolled retry loops;
- no interpretation of exit status as the sole conformance verdict.

### 7.2 SI6 Tools

Use Fernando Gont's SI6 tools for IPv6/Neighbor Discovery/extension-header/ICMPv6 stimuli where the tool directly matches the requirement.

The suite should document:

- exact executable used;
- exact command line;
- relevant tool version;
- exit status;
- stdout/stderr;
- associated PCAP where applicable.

### 7.3 Scapy

Use Scapy when precise packet construction or inspection is required.

Scapy should be preferred for:

- unusual extension-header chains;
- exact option types and action bits;
- malformed/reserved fields;
- controlled ICMPv6 Type/Code combinations;
- Routing Header fields;
- Fragment Header construction;
- exact Hop Limit manipulation;
- exact MTU values;
- ND reserved fields and options;
- packet parsing and evidence verification.

The existing `new.py` is the initial packet-generation reference. It demonstrates direct Scapy construction, explicit IPv6 addresses, an extension-header chain, ICMPv6 Echo handling, capture-before-send, bounded transmission, and response matching.

Do not copy its one-off execution model verbatim; convert the useful mechanisms into reusable patterns inside the RFC programs.

---

## 8. Packet Generation Requirements

Packet generation must provide deterministic control over fields relevant to each requirement.

At minimum, the architecture must be capable of controlling:

- IPv6 source;
- IPv6 destination;
- Hop Limit;
- Next Header;
- extension-header ordering;
- extension-header repetition;
- Routing Header fields;
- Routing Header Segments Left;
- IPv6 option type;
- option action bits;
- option data;
- ICMPv6 Type;
- ICMPv6 Code;
- ICMPv6 MTU;
- Neighbor Discovery reserved fields;
- Neighbor Discovery options.

Where possible, construct packets directly with Scapy rather than relying on command-line tools whose packet formats cannot be controlled precisely.

---

## 9. Capture and Observation

Capture must begin before the stimulus is transmitted.

A live test should preserve enough information to establish:

- that the stimulus was transmitted;
- exact stimulus fields;
- that the stimulus reached the relevant observation point where required;
- DUT response;
- exact response fields;
- absence of prohibited responses where absence is observable.

Prefer PCAP as primary packet evidence.

Do not rely exclusively on human-readable `tcpdump` output when exact packet fields can be parsed from PCAP.

### Observation categories

The harness should distinguish:

```text
DIRECTLY_OBSERVED
INFERRED
UNKNOWN
```

Example:

```text
Directly observed:
  ICMPv6 Parameter Problem Code 2 received.

Inferred:
  No packet was observed beyond the DUT.

Unknown:
  DUT internal PMTU cache cannot be inspected.
```

Never convert an inference into a directly observed fact.

---

## 10. Verdict Model

Use the following minimum verdicts:

```text
PASS
FAIL
INCONCLUSIVE
NOT_APPLICABLE
ERROR
```

### PASS

Use only when the available evidence establishes the expected behavior.

### FAIL

Use when the test stimulus and preconditions were established and the observed DUT behavior contradicts the requirement.

Record the deviation.

### INCONCLUSIVE

Use when the test cannot establish the required observation.

Typical example:

```text
No expected response observed
+
No evidence that the stimulus reached the DUT
=
INCONCLUSIVE
```

Do not report this as PASS.

### NOT_APPLICABLE

Use when a requirement legitimately does not apply because its explicit preconditions cannot or should not exist for the DUT/test role.

### ERROR

Use for harness/tool execution failures that prevent the test from being meaningfully evaluated.

Examples:

- requested external executable missing;
- packet could not be constructed;
- capture failed to start;
- required interface unavailable.

Do not silently transform a harness error into a DUT FAIL.

---

## 11. Negative Tests

A negative requirement such as:

```text
MUST silently discard
```

cannot be established merely by seeing no response.

The test must first establish that the stimulus reached the relevant observation point.

Use a control case where practical:

```text
control stimulus
    |
    +--> expected valid response/error

negative stimulus
    |
    +--> prohibited response suppressed
```

This is particularly important for ICMPv6 error suppression tests.

---

## 12. Timing

Tests involving:

- DAD;
- Router Solicitation;
- Router Advertisement;
- Neighbor Discovery;
- PMTU state;

are stateful and timing-sensitive.

Do not assume immediate responses.

Timing values must be configurable.

Record relevant timing observations when they materially affect the verdict.

---

## 13. DUT Preconditions

Every test must identify required preconditions, including where applicable:

- router behavior;
- host behavior;
- forwarding;
- advertising interface;
- IPv6 unicast address;
- IPv6 multicast address;
- anycast address;
- DAD active;
- known PMTU;
- specific interface MTU.

If a required precondition cannot be established:

```text
INCONCLUSIVE
```

or:

```text
NOT_APPLICABLE
```

must be used as appropriate.

Do not silently modify persistent DUT configuration to manufacture a PASS.

---

## 14. RFC 8200 Scope

`RFC-8200-conformance.py` covers the IPv6 base specification requirements assigned by the supplied ER annexure.

Expected test areas include, as applicable to the supplied requirements:

- IPv6 base header fields;
- payload length;
- Next Header;
- Hop Limit;
- Traffic Class;
- Flow Label;
- extension-header processing;
- extension-header ordering;
- repeated extension headers where prohibited;
- destination options;
- unknown option action bits;
- Routing Header handling;
- Fragment Header handling;
- malformed/invalid IPv6 packet handling;
- required ICMPv6 error generation or suppression.

Do not expand the test matrix merely because a related RFC contains additional requirements. The supplied ER remains authoritative.

---

## 15. RFC 8201 Scope

`RFC-8201-conformance.py` covers IPv6 Path MTU Discovery requirements assigned by the supplied ER annexure.

Particular attention must be paid to Packet Too Big processing.

Do not reduce a PMTU test to:

```text
send oversized packet
```

Where the requirement concerns incoming Packet Too Big processing, the test must explicitly establish:

- injected PTB;
- PTB MTU;
- relevant IPv6 packet information;
- initial PMTU state where observable;
- resulting PMTU behavior;
- whether PMTU is reduced below 1280 when that is the requirement.

The test must not claim visibility into internal PMTU state when the DUT does not expose it.

---

## 16. RFC 4861 Scope

`RFC-4861-conformance.py` covers Neighbor Discovery requirements assigned by the supplied ER annexure.

Expected test areas include, as applicable:

- Router Solicitation;
- Router Advertisement;
- Neighbor Solicitation;
- Neighbor Advertisement;
- address resolution;
- neighbor cache behavior;
- reachability;
- override/solicited/router flags;
- Neighbor Discovery option validation;
- reserved fields;
- ICMPv6 Hop Limit requirements;
- invalid NS/NA handling;
- redirects where required.

Tests must explicitly distinguish host and router roles.

---

## 17. RFC 4862 Scope

`RFC-4862-conformance.py` covers IPv6 Stateless Address Autoconfiguration requirements assigned by the supplied ER annexure.

Expected test areas include, as applicable:

- Router Solicitation/Advertisement interaction;
- prefix processing;
- address configuration;
- address lifetimes;
- preferred/valid lifetime behavior;
- Duplicate Address Detection;
- address state transitions;
- autoconfiguration behavior;
- anycast-related requirements.

Anycast cannot be inferred merely from an IPv6 address string.

The test must have an explicit mechanism for establishing that the address is configured/treated as anycast.

If the precondition cannot be proven, do not fabricate the test condition.

---

## 18. RFC 4443 Scope

`RFC-4443-conformance.py` covers ICMPv6 requirements assigned by the supplied ER annexure.

Expected test areas include, as applicable:

- Destination Unreachable;
- Packet Too Big;
- Time Exceeded;
- Parameter Problem;
- Echo Request;
- Echo Reply;
- Type and Code validation;
- error-message construction;
- quoted invoking packet;
- ICMPv6 error suppression;
- multicast/error suppression requirements;
- source-address restrictions;
- malformed ICMPv6 handling.

For suppression tests, use a valid control stimulus where practical before testing the negative condition.

---

## 19. Duplicate Requirements

Some requirements overlap across RFCs.

Do not merge overlapping requirements into one result.

For example, if a requirement appears independently in RFC 4861 and RFC 4862, maintain separate test identifiers and separate verdicts even if one packet exchange supplies evidence for both.

Example naming:

```text
ND-04
RFC 4861 §7.1.1

SLAAC-03
RFC 4862 §7.1.1
```

A shared trace may be referenced by both results, but the requirement identity and verdict remain independent.

---

## 20. Dry Run

Every packet-generation test must support dry-run operation.

Dry-run output should expose the important packet fields without transmitting.

Example:

```text
Test: 8200-OPT-001
Option Type: 0xC1
Action bits: 11
IPv6 Source: 2001:db8:100::2
IPv6 Destination: 2001:db8:100::1
Expected: discard + ICMPv6 Parameter Problem Code 2
Transmission: SKIPPED
```

`--dry-run` must not invoke a live packet transmitter.

External packet-generation tools should not be invoked in a mode that causes network transmission during dry-run.

---

## 21. Unit Tests and Live Tests

Ordinary unit tests must never transmit packets.

Unit tests should operate on:

- Scapy packet objects;
- serialized bytes;
- parser input;
- synthetic observations;
- captured PCAP fixtures;
- synthetic tool output.

Live transmission must require an explicit integration/live execution path.

For example:

```bash
pytest
```

must not transmit.

A live suite may be invoked through:

```bash
uv run RFC-8200-conformance.py
```

or an explicit integration marker/command.

---

## 22. Reproducibility

A live test result must be reproducible from its saved configuration.

Record at minimum:

- test ID;
- RFC;
- test configuration;
- packet parameters;
- timestamp;
- software version;
- Python version;
- Scapy version;
- external tool versions where used;
- interface information;
- capture file;
- verdict.

Avoid uncontrolled randomness.

If randomness is required, record the random seed.

The initial `new.py` uses random ICMP identifiers. Future conformance tests should either derive identifiers deterministically from the test/run context or record the generated values in evidence.

---

## 23. Evidence Directory

Do not overwrite evidence from previous runs by default.

Preferred structure:

```text
results/
└── 2026-09-23T21-30-12/
    ├── summary.json
    ├── summary.md
    ├── RFC-8200-001.json
    ├── RFC-8200-001.pcap
    ├── RFC-8200-002.json
    ├── RFC-8200-002.pcap
    └── ...
```

Each individual test result should identify its evidence files.

---

## 24. Test Output

The terminal output should be useful to an operator without opening the evidence files.

Example:

```text
IPv6 RFC Conformance
====================

RFC: 8200
DUT: 2001:db8:100::1
Interface: eth0

Tests:
  8200-BASE-001   PASS
  8200-BASE-002   PASS
  8200-EXT-001    FAIL
  8200-EXT-002    INCONCLUSIVE
  8200-OPT-001    PASS

Summary:
  PASS           3
  FAIL           1
  INCONCLUSIVE   1
  NOT_APPLICABLE 0
  ERROR          0

Evidence:
  results/2026-09-23T21-30-12/
```

Do not hide inconclusive or error conditions.

---

## 25. No Silent Test Mutation

The harness must not automatically modify:

- packet fields;
- destination address;
- source address;
- interface;
- Hop Limit;
- MTU;
- extension-header order;
- option type;
- test stimulus;

because a particular DUT rejects the intended stimulus.

If the packet cannot be transmitted, report an error.

If a DUT precondition is missing, report the appropriate precondition status.

Do not mutate the test until it passes.

---

## 26. Network Safety

Tests must run only against an explicitly configured test target.

Do not introduce:

- flooding;
- packet-rate attacks;
- address exhaustion;
- uncontrolled multicast traffic;
- large-scale scanning;

unless a future requirement explicitly requires the behavior and provides its own safety controls.

Every live test should have:

- bounded packet count;
- execution timeout;
- observation timeout.

---

## 27. Shared-Kernel Environment

The current intended test-generator environment may use:

```text
TREX host
    |
    +-- systemd-nspawn br33
            |
            +-- Python / Scapy
            +-- thc-ipv6
            +-- SI6 tools
            +-- tcpdump
            +-- iproute2
            |
            +-- test network
```

The `systemd-nspawn` environment is a convenient test-generator environment, not a separate IPv6 implementation.

It shares the host kernel.

Do not claim that the container provides kernel-level IPv6 implementation isolation.

The harness must remain portable to another Linux host/container with equivalent packet-generation capabilities.

---

## 28. Implementation Order

Implement incrementally.

### Phase 1 — RFC 8200 foundation

Start with:

```text
RFC-8200-conformance.py
```

Use the existing `new.py` as the starting reference for:

- Scapy packet construction;
- extension-header construction;
- interface/MAC handling;
- capture-before-send;
- bounded transmission;
- response matching;
- packet display/hexdump.

First establish:

- CLI;
- configuration;
- test metadata;
- dry-run;
- capture;
- evidence;
- verdict handling;
- external-tool adapter pattern.

Then implement the first RFC 8200 tests.

### Phase 2 — RFC 4443

Build ICMPv6 parsing and error-verification patterns needed by RFC 8200 tests.

### Phase 3 — RFC 4861

Implement Neighbor Discovery stateful exchanges and timing.

### Phase 4 — RFC 4862

Implement SLAAC and DAD tests.

### Phase 5 — RFC 8201

Implement PTB/PMTU tests with explicit PMTU-state observability limitations.

---

## 29. Definition of Done

A test is complete only when:

1. It has a stable test ID.
2. Its RFC/section and supplied requirement are traceable.
3. Its preconditions are explicit.
4. Its stimulus is deterministic.
5. The packet-generation mechanism is identified.
6. Dry-run works.
7. Live execution is bounded.
8. Capture starts before transmission.
9. The expected observation is explicit.
10. PASS is supported by evidence.
11. FAIL records the observed deviation.
12. Missing observability produces INCONCLUSIVE rather than a false PASS.
13. Evidence is saved without overwriting previous runs.
14. Unit tests can exercise the relevant parser/builder/verdict logic without transmitting.
15. The test does not silently modify its intended stimulus.

---

## 30. Non-Goals

The initial project is not intended to be:

- a general IPv6 vulnerability scanner;
- a high-rate packet generator;
- a production network scanner;
- a replacement for a full network emulator;
- an implementation of the IPv6 stack;
- a generic fuzzing framework;
- a claim that every sentence of the RFCs is automatically testable.

The project tests explicit, observable conformance requirements.

Where a requirement cannot be established from available observations, the correct result is an explicit limitation or `INCONCLUSIVE`, not an inferred PASS.

---

## 31. Acceptance Criteria for the Initial Implementation

The initial implementation milestone is successful when:

```bash
uv run RFC-8200-conformance.py --help
```

works without requiring live network access;

```bash
uv run RFC-8200-conformance.py --dry-run ...
```

constructs and displays intended test stimuli without transmission;

```bash
pytest
```

runs without transmitting packets;

and a configured live run:

```bash
uv run RFC-8200-conformance.py ...
```

produces:

- bounded execution;
- packet captures;
- per-test verdicts;
- machine-readable JSON;
- human-readable summary;
- sufficient evidence to reproduce and audit the result.

The remaining four RFC programs should follow the same operator-facing contract while retaining RFC-specific test logic.
