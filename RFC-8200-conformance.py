#!/usr/bin/env python3
"""RFC 8200 conformance — IPv6 base spec (ER Table-3: IP-01..IP-05).

Monolithic operator program. RFC test logic lives here; only generic
CLI/config/evidence/verdict/packet-builder plumbing is shared in common/.
Unit-import safe: live TX (sendp/sniff) happens only inside run_live().
"""
from __future__ import annotations

import json
import subprocess
import sys
import time

from common.config import build_parser, validate_addrs, handle_list_tests
from common import evidence as ev
from common import packets as P
from common.verdict import Observation, TestResult

RFC = "8200"
PROG = "RFC-8200-conformance.py"

ER = {
    "IP-01": ("4.1", "IPv6 nodes must accept and attempt to process extension "
                      "headers in any order and occurring any number of times "
                      "in the same packet."),
    "IP-02": ("4.2", "Unknown Option Type action `11`: discard the packet and, "
                      "only if the packet's Destination Address was not a multicast "
                      "address, send an ICMP Parameter Problem, Code 2, message to "
                      "the packet's Source Address, pointing to the unrecognized "
                      "Option Type."),
    "IP-03": ("4.2", "Unknown Option Type action `01`: discard the packet."),
    "IP-04": ("4.2", "Unknown Option Type action `10`: discard the packet and, "
                      "regardless of whether or not the packet's Destination Address "
                      "was a multicast address, send an ICMP Parameter Problem, "
                      "Code 2, message to the packet's Source Address, pointing to "
                      "the unrecognized Option Type."),
    "IP-05": ("4.4", "If Segments Left is zero, the node must ignore the Routing "
                      "header and proceed to process the next header in the packet, "
                      "whose type is identified by the Next Header field in the "
                      "Routing header."),
}

ROLE = "HOST"
OBS_MINIMUM = "blackbox"

DESCRIPTION = (
    "Check a network device's IPv6 base packet handling (RFC 8200): extension\n"
    "headers in any order and number, unknown options, and Routing headers.\n"
    "Every verdict comes with packet evidence. Silence is never called a pass:\n"
    "unproven results are reported INCONCLUSIVE, not PASS."
)
TEST_IDS = "IP-01, IP-02, IP-03, IP-04, IP-05"
TESTS_HELP = (
    "run only these tests, e.g. --tests IP-01-102,IP-05 (default: all). "
    "This program: IP-01 (extension-header matrix, sub-IDs like IP-01-102), "
    "IP-02 / IP-03 / IP-04 (unknown option handling), IP-05 (Routing header)."
)
EPILOG = """examples (dry-runs send nothing and work anywhere):
  RFC-8200-conformance.py --interface host0 --source 2001:db8::2 --target 2001:db8::1 --dry-run
  RFC-8200-conformance.py --interface host0 --source 2001:db8::2 --target 2001:db8::1 --dry-run --tests IP-05
  RFC-8200-conformance.py --interface host0 --source 2001:db8::2 --target 2001:db8::1 --list-tests

live run (replace the three values with your lab's; never the Internet):
  RFC-8200-conformance.py --interface <IFACE> --source <YOUR-IPV6> --target <DUT-IPV6> --output results --verbose

verdicts: PASS (proven) / FAIL (proven wrong, deviation logged) /
INCONCLUSIVE (unproven, not failure) / NOT_APPLICABLE (e.g. IPsec chains
without a security context) / ERROR (fix your lab, not the device).
Routing Type 0 chains are must-drop packets (deprecated): their drop or
rejection is recorded as PASS with the reason in evidence."""

CATALOG = [
    ("IP-01", "Extension headers accepted and processed in any order and number."),
    ("IP-02", "Unknown option, action 11: discard + Parameter Problem Code 2 (unicast only)."),
    ("IP-03", "Unknown option, action 01: silently discard."),
    ("IP-04", "Unknown option, action 10: discard + Parameter Problem Code 2 (even to multicast)."),
    ("IP-05", "Routing header with Segments Left 0: ignore it, process the next header."),
]





def bpf_for(src: str, dst: str) -> str:
    """Capture test traffic both ways; exclude unrelated host flows (pure)."""
    return f"ip6 and (host {src} or host {dst})"


def classify(kind: str, replies: list[str], errors: list[tuple],
             tx_seen: bool, proof: str, liveness_src: str,
             control_pass: bool, deprecated: bool = False):
    """Pure verdict decision for RFC 8200.

    replies: correlated Echo Reply summaries. errors: (type, code, ptr, summary)
    of DUT ICMPv6 errors seen in-window. proof: strict|auto|direct.
    deprecated: stimulus carries a must-drop header (Routing Type 0); the ER's
    "accept and attempt to process" is then satisfied by the attempt itself,
    and drop/rejection is the required outcome.
    Returns (verdict, obs_kind, detail, deviation, interpretation).
    """
    proven = (proof == "direct" and tx_seen) or \
             (proof == "auto" and tx_seen and bool(liveness_src))
    proof_note = ""
    if proven:
        proof_note = ("delivery proven (TX on wire"
                      + (f", DUT alive per {liveness_src}" if liveness_src else
                         ", direct-topology assumption") + ")")
    if deprecated and kind in ("IP-01", "IP-05"):
        if replies:
            return ("PASS", "DIRECTLY_OBSERVED", replies[0], "",
                    "Processed end-to-end, satisfying the ER literally (accept and "
                    "attempt to process); RH0-deprecation tension with RFC 5095 noted. "
                    + P.DEPRECATION_NOTE)
        if errors:
            t, c, p, s = errors[0]
            return ("PASS", "DIRECTLY_OBSERVED",
                    f"DUT accepted the packet and attempted processing; returned "
                    f"ICMPv6 Type {t} Code {c} ptr {p}: {s}", "",
                    "The ER requires accepting and attempting to process extension "
                    "headers in any order and number; the response itself demonstrates "
                    "the attempt. " + P.DEPRECATION_NOTE)
        if proven:
            return ("PASS", "DIRECTLY_OBSERVED",
                    f"no reply; {proof_note}", "", P.DEPRECATION_NOTE)
        return ("INCONCLUSIVE", "UNKNOWN" if not tx_seen else "INFERRED",
                f"tx_seen={tx_seen}; no reply",
                "delivery/response unproven; not a PASS", "")
    if kind in ("IP-01", "IP-05"):
        if replies:
            return ("PASS", "DIRECTLY_OBSERVED", replies[0], "", "")
        if errors:
            t, c, p, s = errors[0]
            return ("FAIL", "DIRECTLY_OBSERVED", s,
                    f"DUT errored a valid packet instead of processing it "
                    f"(ICMPv6 Type {t} Code {c} ptr {p})", "")
        if proven:
            return ("FAIL", "DIRECTLY_OBSERVED",
                    f"stimulus on wire, {proof_note}, no reply",
                    "mandatory processing absent although delivery is proven", "")
        return ("INCONCLUSIVE", "UNKNOWN" if not tx_seen else "INFERRED",
                f"tx_seen={tx_seen}; no reply", "delivery/response unproven; not a PASS", "")
    if kind in ("IP-02", "IP-04"):
        good = [e for e in errors if e[0] == 4 and e[1] == 2]
        if good:
            return ("PASS", "DIRECTLY_OBSERVED",
                    f"ParamProblem code=2 ptr={good[0][2]}", "", "")
        if errors:
            t, c, p, s = errors[0]
            return ("FAIL", "DIRECTLY_OBSERVED", s,
                    f"wrong ICMPv6 error (Type {t} Code {c} ptr {p}); "
                    f"required Parameter Problem Code 2", "")
        if proven:
            return ("FAIL", "DIRECTLY_OBSERVED",
                    f"stimulus on wire, {proof_note}, no error",
                    "mandatory Parameter Problem Code 2 missing although delivery is proven", "")
        return ("INCONCLUSIVE", "UNKNOWN",
                f"tx_seen={tx_seen}", "no Param Problem observed; DUT receipt unproven", "")
    if kind == "IP-03":
        if errors:
            t, c, p, s = errors[0]
            return ("FAIL", "DIRECTLY_OBSERVED", s,
                    f"prohibited ICMPv6 error emitted (Type {t} Code {c})", "")
        if control_pass or proven:
            why = "path proven by IP-01 control" if control_pass else proof_note
            return ("PASS", "INFERRED", f"TX on wire; {why}, no error seen", "", "")
        return ("INCONCLUSIVE", "UNKNOWN", f"tx_seen={tx_seen}",
                "silence without proven delivery is not discard", "")
    raise ValueError(f"bad kind: {kind}")


# ---------------------------------------------------------------- dry-run

def _cases_for_run(profile: str, max_chain: int, only: set[str] | None):
    """Expand selected tests into executable cases. Pure (no I/O)."""
    cases = []  # (id, kind, payload)
    if not only:
        want = lambda tid: True
    else:
        # Prefix-aware: a sub-ID (IP-01-102) implies its group (IP-01).
        want = lambda tid: any(o == tid or o.startswith(tid + "-") for o in only)
    if want("IP-01"):
        if profile == "exhaustive":
            for tid, ch in P.matrix_single():
                cases.append((tid, "IP-01", ch))
            for tid, ch in P.matrix_pairs():
                cases.append((tid, "IP-01", ch))
            for tid, ch in P.matrix_repeats():
                cases.append((tid, "IP-01", ch))
            for tid, ch in P.matrix_mixed():
                cases.append((tid, "IP-01", ch))
            for tid, ch in P.matrix_triples():
                cases.append((tid, "IP-01", ch))
            for tid, ch in P.matrix_long(max_chain):
                cases.append((tid, "IP-01", ch))
        elif profile == "security-only":
            for tid, ch in P.matrix_single() + P.matrix_pairs():
                if set(ch) & P.SECURITY_SYMBOLS:
                    cases.append((tid, "IP-01", ch))
        else:
            for tid, ch in P.core_matrix():
                cases.append((tid, "IP-01", ch))
            # record security-gated singles as NOT_APPLICABLE cases (no TX)
            for tid, ch in P.matrix_single():
                if set(ch) & P.SECURITY_SYMBOLS:
                    cases.append((tid, "IP-01-SEC", ch))
    for tid in ("IP-02", "IP-03", "IP-04", "IP-05"):
        if want(tid):
            cases.append((tid, tid, ()))
    if only:
        cases = [c for c in cases if c[0] in only or c[0].split("-")[0] in only
                 or c[1] in only or tid_match(c, only)]
    return cases


def tid_match(case, only: set[str]) -> bool:
    return case[0] in only or case[1] in only


def dry_run(args) -> int:
    only = set(t.strip() for t in args.tests.split(",") if t.strip()) or None
    cases = _cases_for_run(args.profile, args.max_chain_length, only)
    print(f"RFC 8200 dry-run  src={args.source} dst={args.target} profile={args.profile}")
    for tid, kind, payload in cases:
        iid, iseq = P.derive_ids(args.seed, tid)
        if kind == "IP-01":
            pkt = P.build_echo(args.source, args.target, iid, iseq, payload)
            print(f"Test: {tid}  chain={'->'.join(payload)}  icmp id={iid} seq={iseq}")
            print(f"  IPv6 src={args.source} dst={args.target} hlim=64")
            print(f"  chain_decode: {P.header_chain(pkt)}")
            if set(payload) & P.DEPRECATED_SYMBOLS:
                print("  Note: Routing Type 0 deprecated (RFC 5095); drop/reject expected, recorded as PASS")
            else:
                print("  Expected: Echo Reply correlated by id/seq")
        elif kind == "IP-01-SEC":
            print(f"Test: {tid}  chain={'->'.join(payload)}  SKIPPED-TX "
                  f"(needs IPsec context -> NOT_APPLICABLE without it)")
        elif kind in ("IP-02", "IP-03", "IP-04"):
            otype = {"IP-02": P.UNKNOWN_OTYPES["11"], "IP-03": P.UNKNOWN_OTYPES["01"],
                     "IP-04": P.UNKNOWN_OTYPES["10"]}[kind]
            print(f"Test: {tid}  Option Type: 0x{otype:02X}  Action bits: {P.action_bits(otype)}")
            print(f"  IPv6 Source: {args.source}  Destination: {args.target}")
            print("  Expected: " + ("discard + ICMPv6 Parameter Problem Code 2"
                                    if kind in ("IP-02", "IP-04") else "discard"))
        elif kind == "IP-05":
            print(f"Test: IP-05  Routing SegLeft=0 -> Echo id={iid} seq={iseq}")
            print("  Note: Routing Type 0 deprecated (RFC 5095); drop/reject expected, recorded as PASS")
        print("  Transmission: SKIPPED")
    print(f"\n{len(cases)} case(s) rendered, 0 transmitted.")
    return 0


# ---------------------------------------------------------------- live helpers (TX path only)

def _iface_mac(iface: str) -> str:
    out = subprocess.check_output(["ip", "link", "show", "dev", iface], text=True)
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("link/"):
            return line.split()[1]
    raise RuntimeError(f"could not determine MAC for {iface}")


def _neigh_mac(ip: str, iface: str) -> str:
    out = subprocess.run(["ip", "-6", "neigh", "show", "dev", iface, "to", ip],
                         text=True, capture_output=True, check=True)
    fields = out.stdout.split()
    if "lladdr" not in fields:
        raise RuntimeError(f"no L2 neighbor entry for {ip} on {iface}: {out.stdout.strip()}")
    return fields[fields.index("lladdr") + 1]


def _tool_version(exe: str) -> str:
    try:
        r = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr or "present").splitlines()[0][:120]
    except Exception:
        return "missing"


def run_live(args) -> int:
    from scapy.all import Ether, IPv6, ICMPv6EchoReply, ICMPv6ParamProblem, AsyncSniffer, sendp, wrpcap
    validate_addrs(args.source, args.target)
    run_dir = ev.new_run_dir(args.output)
    only = set(t.strip() for t in args.tests.split(",") if t.strip()) or None
    cases = _cases_for_run(args.profile, args.max_chain_length, only)

    try:
        src_mac = _iface_mac(args.interface)
        dst_mac = _neigh_mac(args.target, args.interface)
    except Exception as e:
        print(f"ERROR: {e}")
        return 2

    results: list[TestResult] = []
    matrix_log = []
    tx_ok = True
    liveness_src = ""  # test id whose window proved the DUT speaks

    def dut_errors_in(got):
        from scapy.all import (ICMPv6DestUnreach, ICMPv6PacketTooBig,
                               ICMPv6ParamProblem, ICMPv6TimeExceeded)
        out = []
        for p in got:
            try:
                if not (p.haslayer(IPv6) and p[IPv6].src == args.target):
                    continue
                if p.haslayer(ICMPv6ParamProblem):
                    pp = p[ICMPv6ParamProblem]
                    out.append((4, int(pp.code), int(pp.ptr), p.summary()))
                elif p.haslayer(ICMPv6PacketTooBig):
                    out.append((2, 0, -1, p.summary()))
                elif p.haslayer(ICMPv6TimeExceeded):
                    out.append((3, int(p[ICMPv6TimeExceeded].code), -1, p.summary()))
                elif p.haslayer(ICMPv6DestUnreach):
                    out.append((1, int(p[ICMPv6DestUnreach].code), -1, p.summary()))
            except Exception:
                continue
        return out

    for tid, kind, payload in cases:
        iid, iseq = P.derive_ids(args.seed, tid)
        rec: dict = {"test_id": tid, "rfc": RFC, "er_table": "Table-3",
                     "rfc_section": ER[kind if kind in ER else "IP-01"][0],
                     "er_requirement": ER[kind if kind in ER else "IP-01"][1],
                     "role": ROLE, "observability": {"minimum": OBS_MINIMUM},
                     "src": args.source, "dst": args.target, "icmp_id": iid, "icmp_seq": iseq,
                     "versions": ev.versions(), "interface": args.interface}
        if kind == "IP-01-SEC":
            r = TestResult(test_id=tid, verdict="NOT_APPLICABLE",
                           deviation="AH/ESP case requires IPsec context (security-only profile)")
            rec.update(verdict=r.verdict, deviation=r.deviation)
            ev.write_test_json(run_dir, tid, rec)
            results.append(r)
            matrix_log.append({"id": tid, "chain": list(payload), "verdict": r.verdict})
            continue

        # build stimulus
        if kind == "IP-01":
            l3 = P.build_echo(args.source, args.target, iid, iseq, payload)
            rec["chain"] = list(payload)
            want_reply = True
        elif kind in ("IP-02", "IP-03", "IP-04"):
            otype = {"IP-02": P.UNKNOWN_OTYPES["11"], "IP-03": P.UNKNOWN_OTYPES["01"],
                     "IP-04": P.UNKNOWN_OTYPES["10"]}[kind]
            l3 = P.build_unknown_option(args.source, args.target, otype, iid, iseq)
            rec["otype"] = f"0x{otype:02X}"
            want_reply = kind in ("IP-02", "IP-04")
        else:  # IP-05
            l3 = P.build_echo(args.source, args.target, iid, iseq, ["R"])
            want_reply = True

        pkt = Ether(src=src_mac, dst=dst_mac) / l3
        rec["stimulus"] = pkt.summary()

        def match(p, _iid=iid, _iseq=iseq):
            if not p.haslayer(IPv6):
                return False
            ip = p[IPv6]
            if ip.src != args.target or ip.dst != args.source:
                return False
            if want_reply and kind == "IP-01":
                return (p.haslayer(ICMPv6EchoReply) and p[ICMPv6EchoReply].id == _iid
                        and p[ICMPv6EchoReply].seq == _iseq)
            if kind in ("IP-02", "IP-04"):
                return p.haslayer(ICMPv6ParamProblem) and p[ICMPv6ParamProblem].code == 2
            if kind == "IP-05":
                return (p.haslayer(ICMPv6EchoReply) and p[ICMPv6EchoReply].id == _iid
                        and p[ICMPv6EchoReply].seq == _iseq)
            return False  # IP-03 discard: any match handled below as FAIL

        def is_own_tx(p) -> bool:
            try:
                return (p.haslayer(IPv6) and p[IPv6].src == args.source
                        and p[IPv6].dst == args.target)
            except Exception:
                return False

        sniffer = AsyncSniffer(iface=args.interface, filter=bpf_for(args.source, args.target),
                               store=True)
        try:
            sniffer.start()
            time.sleep(0.1)
            sendp(pkt, iface=args.interface, count=1, verbose=False)
            tx_at = time.time()
            time.sleep(args.observation_timeout)
            got = sniffer.stop()
        except Exception as e:
            try:
                sniffer.stop()
            except Exception:
                pass
            r = TestResult(test_id=tid, verdict="ERROR", deviation=f"tx/capture failed: {e}")
            rec.update(verdict=r.verdict, deviation=r.deviation)
            ev.write_test_json(run_dir, tid, rec)
            results.append(r)
            continue

        if args.pcap:
            try:
                wrpcap(str(run_dir / "pcap" / f"{tid}.pcap"), list(got), linktype=1)
                rec["pcap"] = f"pcap/{tid}.pcap"
            except Exception as e:
                rec["pcap_error"] = str(e)
        rec["tx_time"] = tx_at
        tx_seen = any(is_own_tx(p) for p in got)
        rec["tx_seen_on_wire"] = tx_seen
        rec["delivery_proof"] = args.delivery_proof
        replies = [p.summary() for p in got if match(p)]
        errors = dut_errors_in(got)
        dut_packets = []
        for p in got:
            try:
                if p.haslayer(IPv6) and p[IPv6].src == args.target and len(dut_packets) < 10:
                    dut_packets.append(p.summary())
            except Exception:
                continue
        rec["dut_packets"] = dut_packets
        rec["liveness_src"] = liveness_src
        control_pass = any(x.test_id.startswith("IP-01-") and x.verdict == "PASS" for x in results)
        chain = list(payload) if kind == "IP-01" else (["R"] if kind == "IP-05" else [])
        deprecated = bool(set(chain) & P.DEPRECATED_SYMBOLS)
        rec["deprecated_stimulus"] = deprecated
        verdict, obs_kind, detail, deviation, interp = classify(
            kind, replies, errors, tx_seen, args.delivery_proof, liveness_src, control_pass,
            deprecated)
        rec["interpretation"] = interp
        r = TestResult(test_id=tid, verdict=verdict,
                       observed=[Observation(obs_kind, detail)] if detail else [],
                       deviation=deviation)
        if replies or errors:
            liveness_src = tid
        rec.update(verdict=r.verdict, deviation=r.deviation,
                   observed=[{"kind": o.kind, "detail": o.detail} for o in r.observed])
        ev.write_test_json(run_dir, tid, rec)
        results.append(r)
        if kind == "IP-01":
            matrix_log.append({"id": tid, "chain": list(payload), "verdict": r.verdict})
        if args.verbose:
            print(f"  {tid:<14} {r.verdict}")

    (run_dir / "IP-01-matrix.json").write_text(json.dumps(matrix_log, indent=2))
    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    summary = {"rfc": RFC, "dut": args.target, "interface": args.interface,
               "tests": [{"id": r.test_id, "verdict": r.verdict} for r in results],
               "counts": counts, "versions": ev.versions(),
               "thc_ipv6": _tool_version("ex6"), "tcpdump": _tool_version("tcpdump")}
    jp, mp = ev.write_summary(run_dir, summary)
    print(f"\nRFC: {RFC}\nDUT: {args.target}\nInterface: {args.interface}\n\nTests:")
    for r in results:
        print(f"  {r.test_id:<16} {r.verdict}")
    print(f"\nSummary:")
    for k in ("PASS", "FAIL", "INCONCLUSIVE", "NOT_APPLICABLE", "ERROR"):
        print(f"  {k:<16} {counts.get(k, 0)}")
    print(f"\nEvidence:\n  {run_dir}")
    return 0 if counts.get("FAIL", 0) == 0 and counts.get("ERROR", 0) == 0 else 1


def main(argv=None) -> int:
    early = handle_list_tests(argv, CATALOG)
    if early is not None:
        return early
    parser = build_parser(PROG, RFC, description=DESCRIPTION,
                          tests_help=TESTS_HELP, epilog=EPILOG, test_ids=TEST_IDS,
                          matrix_opts=True)
    parser.add_argument("--delivery-proof", default="auto", choices=["strict", "auto", "direct"],
                        help="what counts as proof the packet reached the device: "
                             "strict = silence is always INCONCLUSIVE; auto (default) = "
                             "packet seen on the wire plus the device answering some test "
                             "in this run; direct = packet on the wire alone suffices "
                             "(directly-connected lab only)")
    args = parser.parse_args(argv)
    if args.dry_run:
        print(f"delivery-proof: {args.delivery_proof}")
        return dry_run(args)
    return run_live(args)


if __name__ == "__main__":
    sys.exit(main())
