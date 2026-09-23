# Constraints --- IPv6 RFC Conformance Test Harness

## 1. Purpose

This document defines the constraints under which the IPv6 RFC
conformance harness must be designed and operated.

`project.md` defines **what must be tested**.

`constraints.md` defines **what the implementation must and must not
assume or do**.

The supplied ER annexure remains the source of truth for the explicit
conformance requirements.

------------------------------------------------------------------------

## 2. Source Fidelity

### 2.1 Do not alter the supplied requirements

The ER annexure contains the exact requirements being evaluated.

The implementation must not:

-   silently rewrite an ER clause;
-   replace an ER clause with a newer RFC requirement;
-   omit inconvenient portions of a clause;
-   change an expected result because Linux behaves differently;
-   declare a test compliant merely because a newer RFC contains related
    language.

If an implementation requires interpretation, record the interpretation
separately.

### 2.2 RFC 2460 versus RFC 8200

The supplied Table-3 is explicitly labelled:

``` text
Table-3: IPV6 as per RFC 2460
```

Do not rename the test group to RFC 8200.

If RFC 8200 is used as implementation/reference context, record:

``` text
ER requirement: RFC 2460
Implementation/reference: RFC 8200
```

The annexure itself requires Helpdesk confirmation where an IP test is
implemented through an RFC different from the RFC named in the ER.

------------------------------------------------------------------------

## 3. Platform Agnosticism

The harness must not depend on:

-   a specific NGFW vendor;
-   a specific Linux distribution on the DUT;
-   a particular NIC vendor;
-   a particular switch;
-   a particular firewall implementation;
-   a particular hardware accelerator;
-   a particular kernel version.

The current Debian `systemd-nspawn` `br33` environment is the
**test-generator environment**, not a requirement imposed on the DUT.

The harness should remain usable from another Linux host/container with
equivalent packet-generation capabilities.

------------------------------------------------------------------------

## 4. Network Isolation

Tests must run only against an explicitly configured test target.

The harness must not default to:

-   public Internet destinations;
-   arbitrary discovered IPv6 addresses;
-   addresses taken from DNS without explicit configuration;
-   production interfaces.

The target interface, source address, destination address, and capture
interface should be explicitly configurable.

------------------------------------------------------------------------

## 5. Packet Generation

Packet generation must provide deterministic control over the fields
relevant to the requirement.

At minimum this includes:

-   IPv6 source;
-   IPv6 destination;
-   Hop Limit;
-   Next Header;
-   extension-header ordering;
-   extension-header repetition;
-   Routing Header fields;
-   Routing Header `Segments Left`;
-   IPv6 option type;
-   option action bits;
-   option data;
-   ICMPv6 Type;
-   ICMPv6 Code;
-   ICMPv6 MTU;
-   Neighbor Discovery reserved fields;
-   Neighbor Discovery options.

Where possible, construct packets directly with Scapy rather than
depending on command-line tools whose packet formats cannot be
controlled precisely.

------------------------------------------------------------------------

## 6. No Unbounded Traffic

The harness must default to bounded traffic.

Do not introduce:

-   flooding;
-   packet-rate attacks;
-   address exhaustion;
-   uncontrolled multicast traffic;
-   large-scale scanning;

as part of the conformance tests unless a specific future test
explicitly requires it and provides its own safety controls.

A test should have:

-   a packet count;
-   an execution timeout;
-   an observation timeout.

------------------------------------------------------------------------

## 7. Negative-Test Evidence

A negative requirement such as:

``` text
MUST silently discard
```

cannot be established merely by observing that no response was seen.

The harness must first establish that the stimulus reached the relevant
observation point.

Therefore:

``` text
packet never reached DUT
```

must not be treated as:

``` text
DUT silently discarded packet
```

If the harness cannot distinguish these conditions, the verdict must be:

``` text
INCONCLUSIVE
```

rather than `PASS`.

------------------------------------------------------------------------

## 8. Capture Requirements

Capture must begin before the stimulus is transmitted.

The harness should retain sufficient packet data to establish:

-   stimulus transmission;
-   stimulus fields;
-   DUT response;
-   response fields;
-   absence of prohibited responses where observable.

PCAP evidence should be retained for live tests.

Do not rely exclusively on human-readable tcpdump output when exact
packet fields can be parsed from the PCAP.

------------------------------------------------------------------------

## 9. Timing

Tests involving:

-   DAD;
-   Router Solicitation;
-   Router Advertisement;
-   Neighbor Discovery;
-   PMTU state;

are stateful and timing-sensitive.

The implementation must not assume that a response occurs immediately.

Timing values must be configurable.

The test result should record relevant timing information where it
materially affects the verdict.

------------------------------------------------------------------------

## 10. Shared-Kernel Constraint

The `systemd-nspawn` container shares the host kernel.

Therefore the harness must distinguish:

``` text
userspace isolation
```

from:

``` text
kernel isolation
```

Installing tools in the `br33` container is isolated from the host
filesystem/package database, but packet processing still uses the host
kernel.

The project must not claim that nspawn provides a separate IPv6
implementation.

------------------------------------------------------------------------

## 11. DUT State

The harness must avoid changing persistent DUT configuration unless the
test explicitly requires it.

For tests involving:

-   advertising interfaces;
-   SLAAC;
-   anycast;
-   DAD;
-   PMTU;

the required DUT configuration should be treated as an explicit test
precondition.

Record the precondition in the result.

Do not silently modify configuration to manufacture a PASS result.

------------------------------------------------------------------------

## 12. Test Preconditions

Every test should identify whether it requires:

-   router behavior;
-   host behavior;
-   forwarding;
-   an advertising interface;
-   an IPv6 unicast address;
-   an IPv6 multicast address;
-   an anycast address;
-   DAD to be active;
-   a known PMTU;
-   a specific interface MTU.

If a required precondition cannot be established, return:

``` text
INCONCLUSIVE
```

or:

``` text
NOT_APPLICABLE
```

as appropriate.

------------------------------------------------------------------------

## 13. Observability

The harness should distinguish three things:

### Directly observed

Example:

``` text
ICMPv6 Parameter Problem Code 2 received.
```

### Inferred

Example:

``` text
No packet was observed beyond the DUT.
```

### Unknown

Example:

``` text
The DUT's internal PMTU cache cannot be inspected.
```

Do not present inference as direct observation.

------------------------------------------------------------------------

## 14. ICMPv6 Error Tests

When testing requirements concerning suppression of ICMPv6 errors,
construct a stimulus that would otherwise produce an error under the
corresponding valid/unicast condition.

The harness should ideally run a control case first:

``` text
control stimulus
    |
    +--> expected ICMPv6 error

negative stimulus
    |
    +--> error must be suppressed
```

This makes the negative result substantially more defensible.

------------------------------------------------------------------------

## 15. Duplicate Requirements

Some requirements intentionally overlap across RFCs.

For example, invalid Neighbor Solicitation/Advertisement Hop Limit
behavior appears in both RFC 4861 and RFC 4862.

Do not merge these into a single result.

Maintain separate identifiers:

``` text
ND-04     RFC 4861 §7.1.1
SLAAC-03  RFC 4862 §7.1.1
```

One packet exchange may provide evidence for both, but each ER
requirement must retain its own verdict and traceability.

------------------------------------------------------------------------

## 16. RFC 8201 PMTU Test

The explicit supplied requirement concerns receipt of a Packet Too Big
message reporting an MTU below the IPv6 minimum link MTU.

Do not reduce this test to:

``` text
send oversized packet
```

The actual requirement concerns processing of an incoming PTB and the
resulting PMTU estimate.

The test must therefore record:

-   injected PTB MTU;
-   initial PMTU state where observable;
-   resulting PMTU behavior;
-   whether PMTU is reduced below 1280.

------------------------------------------------------------------------

## 17. RFC 4862 Anycast Test

Anycast cannot be inferred merely from an IPv6 address string.

The test must have an explicit mechanism for establishing that the
address is configured/treated as anycast.

If the DUT cannot expose sufficient information to prove the
precondition, the harness must not fabricate an anycast test condition.

Use:

``` text
INCONCLUSIVE
```

where the requirement cannot be established.

------------------------------------------------------------------------

## 18. Unit-Test Safety

Ordinary unit tests must never transmit packets.

Packet-builder tests should operate on:

-   Scapy packet objects;
-   serialized bytes;
-   parser input;
-   synthetic observations.

Live transmission must require an explicit integration/live-test
command.

For example:

``` bash
pytest
```

must not transmit network traffic.

A separate command/marker should be required:

``` bash
pytest -m integration
```

or:

``` bash
ipv6-conf run ...
```

------------------------------------------------------------------------

## 19. Dry-Run Requirement

Every packet-generation test should support dry-run behavior.

Dry-run output should expose the important packet fields without
transmitting.

Example:

``` text
Test: IP-02
Option Type: 0xC1
Action bits: 11
IPv6 Source: 2001:db8:100::2
IPv6 Destination: 2001:db8:100::1
Expected: discard + ICMPv6 Parameter Problem Code 2
Transmission: SKIPPED
```

------------------------------------------------------------------------

## 20. Reproducibility

A live test result must be reproducible from its saved configuration.

Record:

-   test ID;
-   configuration;
-   packet parameters;
-   timestamp;
-   software version;
-   Python version;
-   Scapy version;
-   relevant interface information;
-   capture file;
-   verdict.

Avoid uncontrolled randomness.

If randomness is required, record the random seed.

------------------------------------------------------------------------

## 21. Evidence Preservation

Do not overwrite evidence from a previous run by default.

Use run directories such as:

``` text
results/
└── 2026-09-07T16-30-00/
    ├── summary.json
    ├── summary.md
    ├── IP-01.json
    ├── IP-01.pcap
    └── ...
```

A rerun should produce a new evidence set.

------------------------------------------------------------------------

## 22. No False PASS

The harness must prefer:

``` text
INCONCLUSIVE
```

over an unsupported:

``` text
PASS
```

A PASS must be supported by evidence sufficient to establish the
expected behavior.

A FAIL must identify the observed deviation where possible.

------------------------------------------------------------------------

## 23. No Silent Test Mutation

The harness must not automatically modify:

-   packet fields;
-   destination addresses;
-   interface;
-   Hop Limit;
-   MTU;
-   extension-header order;
-   option type;

because a particular DUT rejects the intended stimulus.

If a packet cannot be transmitted, report an error.

If a DUT precondition is missing, report the appropriate precondition
status.

Do not mutate the test until it passes.

------------------------------------------------------------------------

## 24. Operational Constraint

The current intended workflow is:

``` text
TREX host
    |
    +-- systemd-nspawn br33
            |
            +-- Python / Scapy
            +-- thc-ipv6
            +-- tcpdump
            +-- iproute2
            |
            +-- test network
```

The container is a convenient isolated test environment. The test
definitions themselves must remain portable.

------------------------------------------------------------------------

## 25. Deliverable Constraint

The final project should produce three distinct artifacts:

### `project.md`

Defines:

-   requirements;
-   test matrix;
-   implementation architecture;
-   test definitions;
-   evidence model;
-   acceptance criteria;
-   supplied annexure.

### `constraints.md`

Defines:

-   operational restrictions;
-   source-fidelity requirements;
-   safety boundaries;
-   observability rules;
-   reproducibility requirements;
-   PASS/FAIL/INCONCLUSIVE semantics.

### Test results

Generated separately under a run-specific output directory.

Do not mix generated results into the requirements documents.

------------------------------------------------------------------------

## 26. Priority of Requirements

When requirements conflict, use this priority:

1.  Explicit supplied ER annexure requirement.
2.  Explicit test precondition.
3.  Test safety constraint.
4.  RFC implementation/reference context.
5.  Implementation convenience.

Implementation convenience must never override the supplied ER
requirement.


------------------------------------------------------------------------

## 27. Minimum Required Observability

The harness must use the **minimum level of DUT observability necessary to establish the verdict for each individual test**.

Observability must be determined on a **per-test basis**, rather than imposed globally on the test suite.

The preferred observability levels are:

```text
Level 1: Network-observable / black-box
Level 2: External test-interface / protocol observation
Level 3: DUT white-box observation
```

A test must begin at the lowest observability level that can establish the required conformance result.

### 27.1 Black-Box First

Where the requirement can be established from externally observable network behavior, the test must remain black-box.

The harness may use Scapy or equivalent packet-generation/capture mechanisms to:

* construct the required stimulus;
* transmit a bounded number of packets;
* capture traffic;
* correlate responses;
* inspect response fields;
* establish timing-dependent behavior where externally observable.

The Scapy pattern demonstrated in the supplied implementation is an example of this approach: capture is started before transmission, the stimulus is sent in a bounded manner, and responses are correlated using relevant IPv6 and ICMPv6 fields.

### 27.2 Escalate Only When Necessary

If black-box observation cannot establish the required verdict, the test may escalate to the next observability level.

Escalation must be:

* explicit;
* justified by the individual test requirement;
* limited to the minimum additional DUT state required;
* recorded as part of the test configuration/result.

The harness must not require white-box access merely because some other tests require it.

For example:

```text
Test A
  Network response is sufficient
  -> Black-box

Test B
  Requirement concerns an externally observable ICMPv6 response
  -> Black-box

Test C
  Requirement depends on internal PMTU state that cannot be established
  from network behavior
  -> Escalate to white-box

Test D
  Requirement concerns an internal configuration/state precondition
  -> Escalate only to the observation needed to establish that precondition
```

### 27.3 Test-Specific Observability Declaration

Every test definition should declare its minimum required observability.

For example:

```text
observability:
    minimum: blackbox
```

or:

```text
observability:
    minimum: whitebox
    reason: "Required result depends on DUT-internal PMTU state."
```

Where escalation is permitted, the reason must identify the specific evidence that cannot be established at the lower level.

### 27.4 No Premature White-Box Dependence

A test must not be classified as requiring white-box access simply because white-box access makes the test easier to implement.

The fact that a DUT exposes an internal state does not, by itself, justify requiring that state.

The test should first determine whether the same requirement can be established through:

* transmitted stimulus;
* observed response;
* packet fields;
* timing;
* externally observable state transitions; or
* a defined control/negative comparison.

### 27.5 Negative Tests

For negative requirements, absence of a response must not automatically be interpreted as successful behavior.

If black-box observation cannot establish that the stimulus reached the relevant DUT processing point, the test may require additional observability.

The harness must therefore distinguish:

```text
Black-box evidence is sufficient
        |
        +--> PASS / FAIL

Black-box evidence is insufficient
        |
        +--> Can the missing evidence be established with
             a defined additional observation?
                    |
                    +--> YES -> escalate this test only
                    |
                    +--> NO  -> INCONCLUSIVE
```

This preserves the existing requirement that an unobserved packet must not be treated as proof of silent discard.

### 27.6 White-Box Access Is Test-Scoped

If white-box access is required, it applies only to the test or test group for which the additional observability is necessary.

It must not become a general prerequisite for the entire conformance harness.

The result must record:

```text
Observability level: WHITEBOX
Escalation reason: <specific reason>
Additional evidence: <state/field observed>
```

Tests that do not require this information remain executable using the lower observability level.

### 27.7 Observability and Verdict Semantics

The observability level must be considered when determining the verdict.

A test must not receive `PASS` merely because the DUT's internal state appears correct if the actual ER requirement concerns externally observable behavior that was not established.

Conversely, a test must not receive `INCONCLUSIVE` merely because black-box observation is insufficient when the test definition explicitly permits the required white-box observation.

The objective is:

```text
minimum observability
        +
sufficient evidence
        =
defensible verdict
```

rather than:

```text
black-box only
```

or:

```text
white-box everywhere
```

### 27.8 Reproducibility

The selected observability level and any escalation must be recorded with the live-test result, alongside the existing configuration, packet parameters, software versions, interface information, capture evidence, and verdict requirements.

A rerun must therefore be able to determine not only **what stimulus was generated**, but also **what level of DUT observability was required to establish the result**.

