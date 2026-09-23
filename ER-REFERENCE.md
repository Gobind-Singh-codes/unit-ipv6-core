# IPv6 ER Conformance Tables Reference — Enhanced RFC Context

## Source

This document records the ER tables that define the explicit IPv6 conformance requirements for the project.

**Source:** Annexure to ERs - 2.29 / December 2025, pages 280–284
**Parameter Group:** IP Conformance (CONFIP)

The five supplied tables are:

- Table-3 — IPv6 as per RFC 8200
- Table-4 — IPv6 as per RFC 4861
- Table-5 — IPv6 as per RFC 4862
- Table-6 — IPv6 as per RFC 8201
- Table-7 — IPv6 as per RFC 4443

> **Source-fidelity rule:** These tables are the requirements supplied for this project. The table wording, RFC number, section number, and requirement must be preserved for traceability.

---

# Table-3 — IPv6 as per RFC 8200

**Parameter Group:** IP Conformance (CONFIP)

| Test ID | RFC Section | ER Requirement |
|---|---|---|
| IP-01 | 4.1 | IPv6 nodes must accept and attempt to process extension headers in any order and occurring any number of times in the same packet. |
| IP-02 | 4.2 | Unknown Option Type action `11`: discard the packet and, only if the packet's Destination Address was not a multicast address, send an ICMP Parameter Problem, Code 2, message to the packet's Source Address, pointing to the unrecognized Option Type. |
| IP-03 | 4.2 | Unknown Option Type action `01`: discard the packet. |
| IP-04 | 4.2 | Unknown Option Type action `10`: discard the packet and, regardless of whether or not the packet's Destination Address was a multicast address, send an ICMP Parameter Problem, Code 2, message to the packet's Source Address, pointing to the unrecognized Option Type. |
| IP-05 | 4.4 | If Segments Left is zero, the node must ignore the Routing header and proceed to process the next header in the packet, whose type is identified by the Next Header field in the Routing header. |

### Table-3 traceability

```text
ER table:       Table-3
ER RFC:         RFC 8200
Implementation: RFC 8200 may be used as modern implementation/reference context
```

For this project, Table-3 is referenced as RFC 8200. Preserve the original annexure wording separately when source-fidelity evidence is required.

The supplied annexure states that where a particular IP test is implemented through an RFC different from the RFC named in the ER, confirmation from Helpdesk should be obtained before submission.

---

# Table-4 — IPv6 as per RFC 4861

**Parameter Group:** IP Conformance (CONFIP)

| Test ID | RFC Section | ER Requirement |
|---|---|---|
| ND-01 | 6.1.1 | A router MUST silently discard any received Router Solicitation messages that do not satisfy the validity checks, including an IP Hop Limit value of 255. |
| ND-02 | 6.1.2 | A node MUST silently discard any received Router Advertisement messages that do not satisfy the validity checks, including an IP Hop Limit value of 255. |
| ND-03 | 6.2.2 | A router MUST NOT send Router Advertisements out any interface that is not an advertising interface. |
| ND-04 | 7.1.1 | A node MUST silently discard any received Neighbour Solicitation messages that do not satisfy the validity checks, including an IP Hop Limit value of 255. |
| ND-05 | 7.1.2 | A node MUST silently discard any received Neighbour Advertisement messages that do not satisfy the validity checks, including an IP Hop Limit value of 255. |

### Table-4 traceability

```text
ER table: Table-4
ER RFC:   RFC 4861
```

---

# Table-5 — IPv6 as per RFC 4862

**Parameter Group:** IP Conformance (CONFIP)

| Test ID | RFC Section | ER Requirement |
|---|---|---|
| SLAAC-01 | 5.4.2 | To improve DAD robustness, an interface MUST receive and process datagrams sent to the all-nodes multicast address or solicited-node multicast address of the tentative address during the delay period. |
| SLAAC-02 | 5.4 | Duplicate Address Detection MUST NOT be performed on anycast addresses. |
| SLAAC-03 | 7.1.1 | A node MUST silently discard any received Neighbour Solicitation messages that do not satisfy the validity checks, including an IP Hop Limit value of 255. |
| SLAAC-04 | 7.1.1 | The contents of the Reserved field, and of any unrecognized options, MUST be ignored. |
| SLAAC-05 | 7.1.2 | A node MUST silently discard any received Neighbour Advertisement messages that do not satisfy the validity checks, including an IP Hop Limit value of 255. |

### Table-5 traceability

```text
ER table: Table-5
ER RFC:   RFC 4862
```

SLAAC-03 overlaps with RFC 4861 ND-04 at the packet-behavior level, but the two ER requirements must retain separate test identifiers and verdicts.

---

# Table-6 — IPv6 as per RFC 8201

**Parameter Group:** IP Conformance (CONFIP)

| Test ID | RFC Section | ER Requirement |
|---|---|---|
| PMTU-01 | 4 | If a node receives a Packet Too Big message reporting a next-hop MTU less than the IPv6 minimum link MTU, it must discard it. A node must not reduce its estimate of the Path MTU below the IPv6 minimum link MTU on receipt of a Packet Too Big message. |

### Table-6 traceability

```text
ER table: Table-6
ER RFC:   RFC 8201
```

The conformance test must evaluate Packet Too Big processing and resulting PMTU behavior; it must not be reduced to merely sending an oversized packet.

---

# Table-7 — IPv6 as per RFC 4443

**Parameter Group:** IP Conformance (CONFIP)

| Test ID | RFC Section | ER Requirement |
|---|---|---|
| ICMP-01 | 2.2(a) | If the message is a response to a message sent to one of the node's unicast addresses, the Source Address of the reply MUST be that same address. |
| ICMP-02 | 2.2 | If the message is a response to a multicast group address, an anycast address implemented by the node, or a unicast address that does not belong to the node, the Source Address of the ICMPv6 packet MUST be a unicast address belonging to the node. |
| ICMP-03 | 2.4 | If an ICMPv6 informational message of unknown type is received, it MUST be silently discarded. |
| ICMP-04 | 2.4(e.3) | An ICMPv6 error message MUST NOT be originated as a result of receiving a packet destined to an IPv6 multicast address. |
| ICMP-05 | 2.4(e.6) | An ICMPv6 error message MUST NOT be originated as a result of receiving a packet whose source address does not uniquely identify a single node, such as the IPv6 Unspecified Address, an IPv6 multicast address, or an address known by the ICMP message originator to be an IPv6 anycast address. |

### Table-7 traceability

```text
ER table: Table-7
ER RFC:   RFC 4443
```

---


---

# RFC-Aware Test Enhancement

This section enriches the ER table with implementation and test-design context
from the named RFCs. It does **not** change the ER requirements.

The distinction is deliberate:

```text
ER requirement
    ↓
exact requirement that must be demonstrated

RFC context
    ↓
technical interpretation and useful test mechanism

Test evidence
    ↓
what the harness actually observed
```

An RFC-derived observation must not be presented as though it were an
additional ER requirement.

---

## RFC 8200 — IPv6 Core

RFC 8200 is the current Internet Standard IPv6 specification and obsoletes
RFC 2460. It defines the IPv6 base header and extension-header processing
model.

For Table-3, the test implementation should be capable of
constructing and inspecting:

- IPv6 Version;
- Traffic Class;
- Flow Label;
- Payload Length;
- Next Header;
- Hop Limit;
- source and destination addresses;
- extension-header chains;
- Hop-by-Hop Options;
- Destination Options;
- Routing Header;
- Fragment Header;
- unknown option types and action bits.

### IP-01 enhancement

The test should not merely generate one unusual extension-header chain.

Use a bounded matrix of syntactically valid chains, including:

```text
IPv6 → HBH → Destination → payload
IPv6 → Routing → Destination → payload
IPv6 → Fragment → Destination → payload
IPv6 → Destination → Routing → payload
IPv6 → Routing → Routing → payload
IPv6 → Destination → Destination → payload
```

The exact matrix should remain bounded and should distinguish:

```text
valid extension-header sequence
```

from:

```text
intentionally malformed sequence
```

The primary observation is whether the DUT accepts and processes the
required valid cases.

### IP-02 / IP-03 / IP-04 enhancement

Construct an actually unknown Option Type with controlled action bits.

The harness should verify:

1. the Option Type is not one known to the receiving implementation;
2. the action bits are exactly the intended value;
3. the packet destination is unicast or multicast as required by the test;
4. the packet reaches the DUT;
5. the resulting ICMPv6 response, if required, has:
   - Type 4;
   - Code 2;
   - the correct source;
   - the correct destination;
   - a Parameter Pointer identifying the unrecognized Option Type.

Do not use "Scapy accepted the packet" as evidence of DUT conformance.

### IP-05 enhancement

For Routing Header `Segments Left = 0`, the test should make continuation to the next header observable.

For example:

```text
IPv6
  → Routing Header (Segments Left = 0)
  → ICMPv6 Echo Request
```

Then verify that processing proceeds to the header identified by the Routing
Header's Next Header field.

---

## RFC 4861 — Neighbor Discovery

RFC 4861 defines Neighbor Discovery for IPv6, including Router Discovery,
address resolution, neighbor reachability, and neighbor state maintenance.
It has subsequently been updated by several RFCs, so the project should
preserve the ER requirement while recording any newer RFC used as
implementation context.

### ND Hop Limit tests

For ND-01, ND-02, ND-04, and ND-05, the fundamental stimulus is:

```text
IPv6 Hop Limit = 254
```

rather than the required:

```text
IPv6 Hop Limit = 255
```

A robust test should:

1. establish that the corresponding valid message would be meaningful on the
   test topology;
2. inject exactly one invalid message;
3. verify transmission/capture;
4. observe whether the DUT accepts/processes it;
5. verify absence of prohibited resulting behavior;
6. return `INCONCLUSIVE` if delivery or relevant DUT observation cannot be
   established.

The test should not equate "no response" with silent discard.

### ND-03 enhancement

ND-03 is fundamentally a router-interface configuration test.

The harness should record:

```text
interface
advertising-interface state
RA observation window
RA packets observed
```

The primary evidence should be a packet capture showing whether an RA was
sent from the non-advertising interface.

If the harness cannot establish the interface's advertising state, the
correct result is not an inferred PASS.

---

## RFC 4862 — Stateless Address Autoconfiguration

RFC 4862 defines host IPv6 autoconfiguration, including link-local address
generation, SLAAC, address lifetimes, and Duplicate Address Detection.
RFC 4862 has been updated by RFC 7527 and RFC 9762.

### SLAAC-01 enhancement

This requirement is specifically about traffic reception/processing during
the DAD delay period.

The test should record:

```text
tentative address
DAD start
DAD delay interval
destination address
packet transmission time
packet reception evidence
address state
```

Do not reduce the result to:

```text
DAD succeeded
```

because that does not demonstrate the supplied requirement.

### SLAAC-02 enhancement

Anycast is not identifiable solely from IPv6 address syntax.

The test must establish the DUT's anycast configuration through explicit
DUT-side configuration or another authoritative observation.

If the harness cannot establish the address as anycast:

```text
INCONCLUSIVE
```

is the appropriate result rather than constructing an unverified test condition.

### SLAAC-04 enhancement

Test both dimensions independently:

```text
Reserved field altered
```

and:

```text
unrecognized ND option present
```

The expected behavior is that these fields are ignored according to the ER
requirement.

Do not substitute RFC 8200 generic IPv6 option-action semantics for the
specific ND requirement.

---

## RFC 8201 — Path MTU Discovery

RFC 8201 defines IPv6 Path MTU Discovery and relies on ICMPv6 Packet Too Big
messages for PMTU discovery. It obsoletes RFC 1981.

### PMTU-01 enhancement

The test should be stateful.

Recommended sequence:

```text
1. Establish a known initial PMTU or establish the observable baseline.
2. Send/control traffic over the tested path.
3. Inject a validly formed ICMPv6 Packet Too Big.
4. Set PTB MTU < 1280.
5. Continue controlled traffic.
6. Observe resulting packet sizing/PMTU behavior.
7. Evaluate whether the DUT reduced its PMTU below 1280.
```

Record:

```text
initial observable PMTU
PTB MTU
quoted packet
PTB source
PTB destination
subsequent packet sizes
observed PMTU behavior
```

The test must not claim visibility into an internal PMTU cache unless the DUT
actually exposes that state.

RFC 8201 notes that PMTUD may be omitted by minimal IPv6 implementations, so
the test result must record whether PMTUD is an applicable DUT capability.
A lack of observable PMTU state must not, by itself, be treated as evidence of the ER behavior.

---

## RFC 4443 — ICMPv6

RFC 4443 specifies ICMPv6 and assigns ICMPv6 the IPv6 Next Header value 58.
It is an Internet Standard and was updated by RFC 4884.

### ICMP-01 enhancement

For a request sent to a DUT unicast address:

```text
request.dst == response.src
```

must be checked at the wire level.

Do not infer the response source from the DUT configuration alone.

### ICMP-02 enhancement

Exercise the applicable destination classes separately:

```text
multicast
anycast
unicast address not belonging to DUT
```

For each case, establish the destination semantics independently.

Anycast must not be inferred merely from the address string.

### ICMP-03 enhancement

Construct an ICMPv6 informational message with an unknown Type while keeping
the surrounding IPv6 packet sufficiently valid to reach the DUT.

The test should distinguish:

```text
unknown informational type silently discarded
```

from:

```text
packet rejected before ICMPv6 Type processing
```

where the observation point allows that distinction.

### ICMP-04 / ICMP-05 enhancement

Use a control stimulus that would produce the corresponding ICMPv6 error
under the valid/unicast condition.

Then change only the relevant negative condition:

```text
control:
    error-generating stimulus
        ↓
    expected ICMPv6 error

negative:
    same stimulus
    + multicast destination / non-unique source
        ↓
    error suppressed
```

This provides stronger evidence for the negative verdict.

---

# Recommended Test Metadata

Every enhanced test should carry both requirement and implementation context:

```yaml
id: IP-02
er_table: Table-3
er_rfc: "8200"
rfc_section: "4.2"

er_requirement: "..."

rfc_context:
  rfc: "8200"
  purpose: "IPv6 unknown-option processing"

stimulus:
  generator: scapy
  packet: "..."

preconditions:
  - "..."

observation:
  capture: "..."
  parsed_packets: []

expected:
  - "..."

verdict: INCONCLUSIVE

evidence:
  pcap: "..."
```

The important point is that `er_requirement` and `rfc_context` are separate
fields.

---

# Recommended Evidence Model

For each live test, retain:

```text
<test-id>.json
<test-id>.pcap
<test-id>.md
```

The JSON should contain the machine-readable result.

The PCAP is the primary packet evidence.

The Markdown file should explain:

```text
Requirement
Preconditions
Stimulus
Expected
Observed
Verdict
Evidence
Limitations
```

For external tools, additionally retain:

```text
<test-id>.tool.json
<test-id>.stdout
<test-id>.stderr
```

where useful.

This allows the project to use THC-IPv6, SI6 tools, Scapy, tcpdump, and
other utilities without making any individual tool's output the conformance
oracle.

---

# Recommended Test Execution Strategy

For tests where a negative result depends on proving delivery, use:

```text
CONTROL
  |
  +--> establish path / DUT response
  |
NEGATIVE
  |
  +--> alter only the RFC-required invalid condition
  |
COMPARE
  |
  +--> evaluate packet-level evidence
```

This is especially useful for:

- silent discard;
- ICMPv6 error suppression;
- invalid ND messages;
- unknown ICMPv6 types;
- malformed IPv6 option behavior.

---

# Scope Boundary

The ER remains the minimum conformance scope.

The RFC-aware material in this document may be used to:

- design better stimuli;
- construct control cases;
- improve packet validation;
- improve evidence;
- identify required preconditions;
- identify observability limitations;
- make tests more deterministic.

It must **not** silently turn every RFC requirement into a new ER test.

Additional RFC-derived tests should be labelled explicitly as:

```text
RFC-CONTEXT
```

or:

```text
OPTIONAL-RFC-COVERAGE
```

rather than being represented as supplied ER requirements.

---

# RFC Reference Status

| RFC | Project role | Current RFC status/context |
|---|---|---|
| RFC 8200 | IPv6 base specification / Table-3 | Internet Standard; obsoletes RFC 2460; updated by RFC 9673.  |
| RFC 4861 | Neighbor Discovery / Table-4 | Standards Track; updated by multiple RFCs including RFC 5942, 6980, 7527, 8319, 9131, 9685 and others.  |
| RFC 4862 | SLAAC / Table-5 | Standards Track; updated by RFC 7527 and RFC 9762.  |
| RFC 8201 | IPv6 PMTUD / Table-6 | Internet Standard; obsoletes RFC 1981.  |
| RFC 4443 | ICMPv6 / Table-7 | Internet Standard; updated by RFC 4884.  |

This status information is reference context only and does not modify the ER
requirements.

# Complete ER Test Index

| ER Table | ER RFC | Test IDs | Count |
|---|---|---|---:|
| Table-3 | RFC 8200 | IP-01 … IP-05 | 5 |
| Table-4 | RFC 4861 | ND-01 … ND-05 | 5 |
| Table-5 | RFC 4862 | SLAAC-01 … SLAAC-05 | 5 |
| Table-6 | RFC 8201 | PMTU-01 | 1 |
| Table-7 | RFC 4443 | ICMP-01 … ICMP-05 | 5 |
| **Total** | | | **21** |

---

# Important Traceability Rules

1. The ER table number is part of the requirement identity.
2. The RFC number supplied by the ER must be preserved.
3. The RFC section is part of the traceability key.
4. The ER clause must not be silently rewritten.
5. Table-3 is identified as RFC 8200 for this project.
6. If RFC 8200 is used as implementation/reference context for Table-3, record that mapping explicitly.
7. Duplicate or overlapping behavior across RFCs must retain separate test IDs and separate verdicts.
8. The Helpdesk confirmation note applies when implementation uses an RFC different from the RFC named by the ER.
9. This document is a requirements reference; it is not itself a test result.
10. A test result must identify the applicable ER table, RFC, section, test ID, stimulus, expected behavior, observed behavior, verdict, and evidence.


---

## IP-01 — Full Extension-Header Processing Matrix

### ER requirement

**ID:** IP-01
**RFC:** RFC 8200
**Section:** §4.1
**Requirement:** IPv6 nodes must accept and process extension headers in any order and any number.

The executable IP-01 implementation shall treat extension-header ordering and repetition as separate test dimensions. A small sample of permutations shall not be represented as proof of unrestricted ordering.

### 1. Extension-header set

The matrix uses the following extension-header types:

| Symbol | Extension Header | RFC 8200 |
|---|---|---|
| H | Hop-by-Hop Options | §4.3 |
| D | Destination Options | §4.6 |
| R | Routing | §4.4 |
| F | Fragment | §4.5 |
| A | Authentication Header (AH) | §4.7 |
| E | Encapsulating Security Payload (ESP) | §4.8 |

Where an extension header requires security state that cannot be established, the corresponding case is not treated as a fabricated conformance condition. The result shall be `NOT_APPLICABLE` or `INCONCLUSIVE`, as appropriate.

The normal observable upper-layer payload for directly testable chains is ICMPv6 Echo Request.

### 2. Matrix A — Single extension header

| Test ID | Chain | Purpose | Expected |
|---|---|---|---|
| IP-01-001 | `H → ICMPv6` | Hop-by-Hop | Packet processed |
| IP-01-002 | `D → ICMPv6` | Destination Options | Packet processed |
| IP-01-003 | `R → ICMPv6` | Routing | Packet processed |
| IP-01-004 | `F → ICMPv6` | Fragment | Packet processed |
| IP-01-005 | `A → ICMPv6` | AH | Processed when valid security context exists |
| IP-01-006 | `E → ...` | ESP | Processed when valid security context exists |

### 3. Matrix B — Two distinct extension headers, both orders

Every pair of distinct extension-header types is tested in both orders. The two orders shall not be collapsed into a single test.

| Test ID | Chain |
|---|---|
| IP-01-101 | `H → D → ICMPv6` |
| IP-01-102 | `D → H → ICMPv6` |
| IP-01-103 | `H → R → ICMPv6` |
| IP-01-104 | `R → H → ICMPv6` |
| IP-01-105 | `H → F → ICMPv6` |
| IP-01-106 | `F → H → ICMPv6` |
| IP-01-107 | `H → A → ICMPv6` |
| IP-01-108 | `A → H → ICMPv6` |
| IP-01-109 | `H → E → ...` |
| IP-01-110 | `E → H → ...` |
| IP-01-111 | `D → R → ICMPv6` |
| IP-01-112 | `R → D → ICMPv6` |
| IP-01-113 | `D → F → ICMPv6` |
| IP-01-114 | `F → D → ICMPv6` |
| IP-01-115 | `D → A → ICMPv6` |
| IP-01-116 | `A → D → ICMPv6` |
| IP-01-117 | `D → E → ...` |
| IP-01-118 | `E → D → ...` |
| IP-01-119 | `R → F → ICMPv6` |
| IP-01-120 | `F → R → ICMPv6` |
| IP-01-121 | `R → A → ICMPv6` |
| IP-01-122 | `A → R → ICMPv6` |
| IP-01-123 | `R → E → ...` |
| IP-01-124 | `E → R → ...` |
| IP-01-125 | `F → A → ICMPv6` |
| IP-01-126 | `A → F → ICMPv6` |
| IP-01-127 | `F → E → ...` |
| IP-01-128 | `E → F → ...` |
| IP-01-129 | `A → E → ...` |
| IP-01-130 | `E → A → ...` |

This produces 30 ordered two-header cases for six distinct extension-header types.

### 4. Matrix C — Repeated extension headers

“Any number” requires explicit repetition tests.

| Test ID | Chain |
|---|---|
| IP-01-201 | `H → H → ICMPv6` |
| IP-01-202 | `H → H → H → ICMPv6` |
| IP-01-203 | `D → D → ICMPv6` |
| IP-01-204 | `D → D → D → ICMPv6` |
| IP-01-205 | `R → R → ICMPv6` |
| IP-01-206 | `R → R → R → ICMPv6` |
| IP-01-207 | `F → F → ICMPv6` |
| IP-01-208 | `F → F → F → ICMPv6` |
| IP-01-209 | `A → A → ...` |
| IP-01-210 | `A → A → A → ...` |
| IP-01-211 | `E → E → ...` |
| IP-01-212 | `E → E → E → ...` |

AH and ESP remain conditional on an established valid security context.

### 5. Matrix D — Mixed repetition

Mixed repetition tests both multiplicity and order in the same chain.

| Test ID | Chain |
|---|---|
| IP-01-301 | `H → H → D → ICMPv6` |
| IP-01-302 | `H → D → D → ICMPv6` |
| IP-01-303 | `D → H → H → ICMPv6` |
| IP-01-304 | `D → D → H → ICMPv6` |
| IP-01-305 | `H → R → R → ICMPv6` |
| IP-01-306 | `R → H → H → ICMPv6` |
| IP-01-307 | `D → R → R → ICMPv6` |
| IP-01-308 | `R → D → D → ICMPv6` |
| IP-01-309 | `H → F → F → ICMPv6` |
| IP-01-310 | `F → H → H → ICMPv6` |
| IP-01-311 | `D → F → F → ICMPv6` |
| IP-01-312 | `F → D → D → ICMPv6` |

### 6. Matrix E — Three distinct extension headers

For six extension-header types, the complete ordered three-header matrix contains:

```text
6P3 = 6 × 5 × 4 = 120
```

The implementation shall generate these cases programmatically rather than maintaining 120 manually written rows.

The generated range is:

```text
IP-01-400 through IP-01-519
```

Representative cases include:

| Test ID | Chain |
|---|---|
| IP-01-400 | `H → D → R → ICMPv6` |
| IP-01-401 | `H → D → F → ICMPv6` |
| IP-01-402 | `H → D → A → ICMPv6` |
| IP-01-403 | `H → D → E → ...` |
| IP-01-404 | `H → R → D → ICMPv6` |
| IP-01-405 | `H → R → F → ICMPv6` |
| … | … |
| IP-01-519 | Final generated ordered permutation |

The actual generated permutation list shall be saved with the test-run evidence.

### 7. Matrix F — Four or more extension headers

A complete ordered matrix becomes combinatorial:

| Chain length | Ordered permutations from six distinct types |
|---:|---:|
| 4 | 6P4 = 360 |
| 5 | 6P5 = 720 |
| 6 | 6P6 = 720 |

The test harness shall therefore generate these cases programmatically.

The executable boundary shall be explicit:

```text
IP01_MAX_CHAIN_LENGTH=<configured value>
```

For example, a maximum length of six permits exhaustive ordered permutations through six distinct extension headers. Longer chains may be exercised through deterministic repeated-header cases.

The project shall not claim that a finite hand-written subset proves the unrestricted phrase “any number.”

### 8. Execution profiles

IP-01 should provide three execution profiles.

#### Core profile

Includes:

- single extension headers;
- all ordered two-header permutations;
- repeated-header cases;
- selected three-header cases.

#### Exhaustive profile

Programmatically generates:

- all ordered permutations;
- configured repeated-header combinations;
- chain lengths from 1 through `MAX_CHAIN_LENGTH`.

The exact generated matrix shall be retained as run evidence.

#### Security-dependent profile

Runs AH and ESP cases only when the required security context and packet validity can be established.

### 9. Validity boundary

IP-01 is primarily a test of valid extension-header processing.

| Condition | IP-01 treatment |
|---|---|
| Valid extension header | In scope |
| Valid extension header repeated | In scope |
| Valid extension headers in non-default order | In scope |
| Valid mixed extension-header chain | In scope |
| Malformed extension-header length | Separate malformed-header test |
| Truncated extension header | Separate malformed-header test |
| Invalid Routing Header | Separate Routing Header test |
| Invalid Fragment Header | Separate Fragment test |
| Unknown Next Header | Separate test |
| Unknown option action bits | IP-02 / IP-03 / IP-04 |
| Invalid ICMPv6 | Separate ICMPv6 test |
| Invalid AH/ESP authentication | Separate security-dependent test |

This boundary prevents IP-01 from becoming an omnibus malformed-packet test.

### 10. Observation and PASS criteria

The test shall not define PASS merely as absence of an ICMP error.

For directly observable chains, capture shall begin before transmission and the test shall establish:

1. the stimulus was transmitted;
2. the stimulus reached the relevant observation point;
3. the IPv6 extension-header chain was processed;
4. the expected upper-layer response was observed;
5. the response corresponds to the stimulus.

For an ICMPv6 Echo exchange, evidence should include:

- IPv6 source and destination;
- extension-header chain;
- ICMPv6 Echo Identifier;
- ICMPv6 Sequence Number;
- corresponding Echo Reply;
- packet capture.

If processing cannot be established, the result shall not be promoted to PASS solely because no error was observed.

### 11. Machine-readable definition

```yaml
id: IP-01
rfc: RFC 8200
section: "4.1"
requirement: >
  IPv6 nodes must accept and process extension headers in any order
  and any number.

header_set:
  - HBH
  - DEST
  - ROUTING
  - FRAGMENT
  - AH
  - ESP

matrix:
  single:
    enabled: true

  ordered_pairs:
    exhaustive: true

  repeated_headers:
    counts: [2, 3]

  mixed_repetition:
    enabled: true

  ordered_triples:
    exhaustive: true

  ordered_quadruples:
    exhaustive: true

  ordered_quintuples:
    exhaustive: true

  ordered_six_headers:
    exhaustive: true

  longer_chains:
    enabled: true
    max_length: configurable

validity:
  malformed_headers: excluded
  invalid_options: separate_tests
  unknown_next_header: separate_test
  invalid_routing_header: separate_test

observation:
  primary: ICMPv6_echo_reply
  capture_before_transmission: true

verdict:
  pass_requires:
    - stimulus_transmitted
    - packet_reached_observation_point
    - extension_chain_was_processed
    - expected_upper_layer_response_observed

  inconclusive_when:
    - delivery_cannot_be_established
    - required_security_context_is_missing
```

### 12. Evidence requirements

Each IP-01 run should preserve:

```text
IP-01.json
IP-01.pcap
IP-01.md
IP-01-matrix.json
```

`IP-01-matrix.json` shall contain the exact generated chains executed in that run, including:

- test ID;
- extension-header sequence;
- packet parameters;
- execution profile;
- configured maximum chain length;
- security-context status where applicable;
- verdict.

This makes the finite executable matrix auditable against the broader ER requirement.
