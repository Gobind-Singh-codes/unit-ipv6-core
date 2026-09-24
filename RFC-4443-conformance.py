#!/usr/bin/env python3
"""RFC 4443 conformance — ICMPv6 (ER Table-7: ICMP-01..ICMP-05). Base build.

Control-then-negative pattern for suppression tests (ICMP-04/05) and
discard tests (ICMP-03). Import-safe: live TX only inside run_live().
"""
from __future__ import annotations

import subprocess
import sys
import time

from common.config import build_parser, validate_addrs, handle_list_tests
from common import evidence as ev
from common import packets as P
from common.verdict import Observation, TestResult

RFC = "4443"
PROG = "RFC-4443-conformance.py"
ROLE = "HOST"
OBS_MINIMUM = "blackbox"

ER = {
    "ICMP-01": ("2.2(a)", "If the message is a response to a message sent to one of "
                "the node's unicast addresses, the Source Address of the reply MUST "
                "be that same address."),
    "ICMP-02": ("2.2", "If the message is a response to a multicast group address, "
                "an anycast address implemented by the node, or a unicast address "
                "that does not belong to the node, the Source Address of the ICMPv6 "
                "packet MUST be a unicast address belonging to the node."),
    "ICMP-03": ("2.4", "If an ICMPv6 informational message of unknown type is "
                "received, it MUST be silently discarded."),
    "ICMP-04": ("2.4(e.3)", "An ICMPv6 error message MUST NOT be originated as a "
                "result of receiving a packet destined to an IPv6 multicast address."),
    "ICMP-05": ("2.4(e.6)", "An ICMPv6 error message MUST NOT be originated as a "
                "result of receiving a packet whose source address does not uniquely "
                "identify a single node, such as the IPv6 Unspecified Address, an IPv6 "
                "multicast address, or an address known by the ICMP message originator "
                "to be an IPv6 anycast address."),
}

CASES = ["ICMP-01", "ICMP-02a", "ICMP-02b", "ICMP-02c",
         "ICMP-03", "ICMP-04", "ICMP-05a", "ICMP-05b", "ICMP-05c"]

DESCRIPTION = (
    "Check a network device's ICMPv6 messages (RFC 4443): reply source addresses,\n"
    "discarding unknown message types, and suppressing error messages where they\n"
    "are forbidden (to multicast destinations, from non-unique sources).\n"
    "Suppression tests run a valid control first, then the forbidden case."
)
TEST_IDS = "ICMP-01, ICMP-02a/b/c, ICMP-03, ICMP-04, ICMP-05a/b/c"
TESTS_HELP = (
    "run only these tests, e.g. --tests ICMP-04,ICMP-05a (default: all). "
    "This program: ICMP-01 (reply source), ICMP-02a/b/c (reply source for "
    "multicast/anycast/unmine destinations), ICMP-03 (unknown type discard), "
    "ICMP-04/05a/b/c (error suppression). Letter suffixes select subcases."
)
EPILOG = """examples (dry-runs send nothing and work anywhere):
  RFC-4443-conformance.py --interface host0 --source 2001:db8::2 --target 2001:db8::1 --dry-run
  RFC-4443-conformance.py --interface host0 --source 2001:db8::2 --target 2001:db8::1 --dry-run --tests ICMP-04
  RFC-4443-conformance.py --interface host0 --source 2001:db8::2 --target 2001:db8::1 --list-tests

live run (replace the three values with your lab's; never the Internet):
  RFC-4443-conformance.py --interface <IFACE> --source <YOUR-IPV6> --target <DUT-IPV6> --output results --verbose

anycast tests need a configured anycast address plus proof, e.g.:
  ... --anycast-target <ANYCAST> --anycast-proof 'dut:ip-addr-show' --tests ICMP-02b,ICMP-05c
ICMP-02c needs a unicast address that is NOT the device's but routed via it:
  ... --unmine-target <ROUTED-NOT-DUT> --tests ICMP-02c
Without these, those tests report NOT_APPLICABLE/INCONCLUSIVE instead of guessing."""

CATALOG = [
    ("ICMP-01", "Reply to a DUT unicast address comes from that same address."),
    ("ICMP-02a", "Reply to a multicast address comes from a DUT unicast address."),
    ("ICMP-02b", "Same for an anycast address (needs --anycast-target + proof)."),
    ("ICMP-02c", "Same for a unicast address not on the DUT (needs --unmine-target)."),
    ("ICMP-03", "Unknown informational message type is silently discarded."),
    ("ICMP-04", "No error message for packets sent to a multicast destination."),
    ("ICMP-05a", "No error message for packets from the Unspecified address (::)."),
    ("ICMP-05b", "No error message for packets from a multicast source."),
    ("ICMP-05c", "No error message for packets from a known anycast source."),
]





def extra_args(p):
    p.add_argument("--anycast-target", default="",
                   help="the device's anycast address under test (ICMP-02b/05c only); "
                        "empty = those tests report NOT_APPLICABLE instead of guessing")
    p.add_argument("--anycast-proof", default="",
                   help="how you proved it is anycast, e.g. 'dut:ip-addr-show'; "
                        "empty with a target = INCONCLUSIVE (an address string alone "
                        "never proves anycast)")
    p.add_argument("--unmine-target", default="",
                   help="a unicast address that is NOT the device's but is routed via it "
                        "(ICMP-02c only); empty = INCONCLUSIVE")
    p.add_argument("--mcast-dst", default="ff02::1",
                   help="multicast destination for ICMP-02a/04 (default: ff02::1, all nodes)")
    return p


def selected(args) -> list[str]:
    only = set(t.strip() for t in args.tests.split(",") if t.strip())
    if not only:
        return list(CASES)
    out = []
    for c in CASES:
        if c in only or c.split("-")[0] in only or c.rstrip("abc") in only:
            out.append(c)
    return out


def dry_run(args) -> int:
    print(f"RFC 4443 dry-run  src={args.source} dst={args.target}")
    for tid in selected(args):
        iid, iseq = P.derive_ids(args.seed, tid)
        if tid == "ICMP-01":
            print(f"Test: {tid}  Echo to DUT unicast {args.target} id={iid} seq={iseq}")
            print("  Expected: reply src == request dst (wire-checked)")
        elif tid == "ICMP-02a":
            print(f"Test: {tid}  Echo to multicast {args.mcast_dst} id={iid} seq={iseq}")
            print("  Expected: any reply src is DUT unicast (never multicast)")
        elif tid == "ICMP-02b":
            print(f"Test: {tid}  Echo to anycast target={args.anycast_target or '(unset)'}")
            print("  Expected: reply src is DUT unicast; needs --anycast-proof or NOT_APPLICABLE/INCONCLUSIVE")
        elif tid == "ICMP-02c":
            print(f"Test: {tid}  Echo to unmine-unicast target={args.unmine_target or '(unset)'}")
            print("  Expected: reply src is DUT unicast; unset target -> INCONCLUSIVE")
        elif tid == "ICMP-03":
            print(f"Test: {tid}  Unknown informational Type 200, valid IPv6 envelope")
            print("  Expected: silently discarded (control echo first proves path)")
        elif tid == "ICMP-04":
            print(f"Test: {tid}  CONTROL UDP-to-closed-port -> Port Unreachable (fallback: unknown-opt); "
                  f"NEGATIVE same to multicast {args.mcast_dst} -> suppressed")
        elif tid in ("ICMP-05a", "ICMP-05b", "ICMP-05c"):
            cond = {"ICMP-05a": "src=:: (unspecified)", "ICMP-05b": "src=ff02::9 (multicast)",
                    "ICMP-05c": f"src=anycast({args.anycast_target or 'unset'})"}[tid]
            print(f"Test: {tid}  CONTROL UDP-to-closed-port -> Port Unreachable; NEGATIVE {cond} -> suppressed")
        print("  Transmission: SKIPPED")
    return 0


def _iface_mac(iface: str) -> str:
    out = subprocess.check_output(["ip", "link", "show", "dev", iface], text=True)
    for line in out.splitlines():
        if line.strip().startswith("link/"):
            return line.split()[1]
    raise RuntimeError(f"no MAC for {iface}")


def _neigh_mac(ip: str, iface: str) -> str:
    out = subprocess.run(["ip", "-6", "neigh", "show", "dev", iface, "to", ip],
                         text=True, capture_output=True, check=True)
    f = out.stdout.split()
    if "lladdr" not in f:
        raise RuntimeError(f"no neighbor entry for {ip} on {iface}: {out.stdout.strip()}")
    return f[f.index("lladdr") + 1]


def _l2_dst(dst: str, iface: str) -> str:
    m = P.eth_dst_for_ipv6(dst)
    return m if m else _neigh_mac(dst, iface)


def run_live(args) -> int:
    from scapy.all import (AsyncSniffer, Ether, IPv6, ICMPv6EchoReply,
                           ICMPv6DestUnreach, ICMPv6PacketTooBig, ICMPv6ParamProblem,
                           ICMPv6TimeExceeded, sendp, wrpcap)
    validate_addrs(args.source, args.target)
    run_dir = ev.new_run_dir(args.output)
    try:
        src_mac = _iface_mac(args.interface)
    except Exception as e:
        print(f"ERROR: {e}")
        return 2
    results: list[TestResult] = []

    def tx_rx(l3, bpf_extra: str, timeout: float):
        pkt = Ether(src=src_mac, dst=_l2_dst(l3.dst, args.interface)) / l3
        sniffer = AsyncSniffer(iface=args.interface,
                               filter=f"ip6 and dst host {args.source} {bpf_extra}",
                               store=True)
        sniffer.start()
        time.sleep(0.1)
        sendp(pkt, iface=args.interface, count=1, verbose=False)
        time.sleep(timeout)
        return pkt, sniffer.stop()

    def save(tid: str, rec: dict, got) -> None:
        if args.pcap:
            try:
                wrpcap(str(run_dir / "pcap" / f"{tid}.pcap"), list(got), linktype=1)
                rec["pcap"] = f"pcap/{tid}.pcap"
            except Exception as e:
                rec["pcap_error"] = str(e)
        ev.write_test_json(run_dir, tid, rec)

    def base_rec(tid: str, er_key: str, extra: dict | None = None) -> dict:
        sec, req = ER[er_key]
        rec = {"test_id": tid, "rfc": RFC, "er_table": "Table-7", "rfc_section": sec,
               "er_requirement": req, "role": ROLE,
               "observability": {"minimum": OBS_MINIMUM},
               "src": args.source, "dst": args.target, "versions": ev.versions(),
               "interface": args.interface}
        if extra:
            rec.update(extra)
        return rec

    def control_echo_ok() -> bool:
        """Valid echo control; returns True iff Echo Reply correlated."""
        iid, iseq = P.derive_ids(args.seed, "ICMP-01")
        l3 = P.build_echo(args.source, args.target, iid, iseq)
        try:
            _, got = tx_rx(l3, "", min(3.0, args.observation_timeout))
        except Exception:
            return False
        return any(p.haslayer(ICMPv6EchoReply) and p[ICMPv6EchoReply].id == iid
                   and p[ICMPv6EchoReply].seq == iseq for p in got)

    path_ok: bool | None = None  # memoized control

    for tid in selected(args):
        iid, iseq = P.derive_ids(args.seed, tid)
        if tid == "ICMP-01":
            rec = base_rec(tid, tid, {"icmp_id": iid, "icmp_seq": iseq})
            try:
                _, got = tx_rx(P.build_echo(args.source, args.target, iid, iseq),
                               "", args.observation_timeout)
            except Exception as e:
                r = TestResult(test_id=tid, verdict="ERROR", deviation=str(e))
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            save(tid, rec, got)
            rep = [p for p in got if p.haslayer(ICMPv6EchoReply)
                   and p[ICMPv6EchoReply].id == iid and p[ICMPv6EchoReply].seq == iseq]
            if rep and rep[0][IPv6].src == args.target:
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("DIRECTLY_OBSERVED", rep[0].summary())])
            elif rep:
                r = TestResult(test_id=tid, verdict="FAIL",
                               deviation=f"reply src {rep[0][IPv6].src} != request dst {args.target}")
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="no correlated Echo Reply; path unproven")
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        elif tid in ("ICMP-02a", "ICMP-02c"):
            dst = args.mcast_dst if tid == "ICMP-02a" else args.unmine_target
            rec = base_rec(tid, "ICMP-02", {"stimulus_dst": dst, "icmp_id": iid, "icmp_seq": iseq})
            if tid == "ICMP-02c" and not dst:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="--unmine-target unset; destination semantics unproven")
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            try:
                _, got = tx_rx(P.build_echo(args.source, dst, iid, iseq),
                               "", args.observation_timeout)
            except Exception as e:
                r = TestResult(test_id=tid, verdict="ERROR", deviation=str(e))
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            save(tid, rec, got)
            rep = [p for p in got if p.haslayer(ICMPv6EchoReply)
                   and p[ICMPv6EchoReply].id == iid and p[ICMPv6EchoReply].seq == iseq]
            if not rep:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="no reply; src rule untestable without a response")
            elif P.is_multicast(rep[0][IPv6].src):
                r = TestResult(test_id=tid, verdict="FAIL",
                               deviation=f"reply src {rep[0][IPv6].src} is multicast")
            else:
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("DIRECTLY_OBSERVED",
                                                     f"reply src={rep[0][IPv6].src} (unicast)")])
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        elif tid == "ICMP-02b":
            rec = base_rec(tid, "ICMP-02", {"anycast_target": args.anycast_target,
                                            "anycast_proof": args.anycast_proof})
            if not args.anycast_target:
                r = TestResult(test_id=tid, verdict="NOT_APPLICABLE",
                               deviation="no --anycast-target configured")
            elif not args.anycast_proof:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="anycast unproven (need --anycast-proof); never infer from address string")
            else:
                try:
                    _, got = tx_rx(P.build_echo(args.source, args.anycast_target, iid, iseq),
                                   "", args.observation_timeout)
                except Exception as e:
                    r = TestResult(test_id=tid, verdict="ERROR", deviation=str(e))
                    rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
                save(tid, rec, got)
                rep = [p for p in got if p.haslayer(ICMPv6EchoReply)
                       and p[ICMPv6EchoReply].id == iid and p[ICMPv6EchoReply].seq == iseq]
                if not rep:
                    r = TestResult(test_id=tid, verdict="INCONCLUSIVE", deviation="no reply to anycast echo")
                elif P.is_multicast(rep[0][IPv6].src):
                    r = TestResult(test_id=tid, verdict="FAIL", deviation="reply src is multicast")
                else:
                    r = TestResult(test_id=tid, verdict="PASS",
                                   observed=[Observation("DIRECTLY_OBSERVED", f"reply src={rep[0][IPv6].src}")])
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r)

        elif tid == "ICMP-03":
            rec = base_rec(tid, tid, {"itype": 200})
            if path_ok is None:
                path_ok = control_echo_ok()
            try:
                stim, got = tx_rx(P.build_unknown_informational(args.source, args.target),
                                  "", args.observation_timeout)
            except Exception as e:
                r = TestResult(test_id=tid, verdict="ERROR", deviation=str(e))
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            rec["stimulus"] = stim.summary()
            save(tid, rec, got)
            dus = [p for p in got if p.haslayer(IPv6) and p[IPv6].src == args.target]
            if dus:
                r = TestResult(test_id=tid, verdict="FAIL",
                               deviation=f"DUT answered unknown informational: {dus[0].summary()}")
            elif path_ok:
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("INFERRED", "path proven by echo control; unknown type elicited nothing")])
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="silence + control echo also silent; delivery unproven")
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        elif tid in ("ICMP-04", "ICMP-05a", "ICMP-05b", "ICMP-05c"):
            if tid == "ICMP-04":
                neg_src, neg_dst, cond = args.source, args.mcast_dst, f"dst={args.mcast_dst} (multicast)"
            elif tid == "ICMP-05a":
                neg_src, neg_dst, cond = "::", args.target, "src=:: (unspecified)"
            elif tid == "ICMP-05b":
                neg_src, neg_dst, cond = "ff02::9", args.target, "src=ff02::9 (multicast)"
            else:
                if not args.anycast_target:
                    rec = base_rec(tid, "ICMP-05", {})
                    r = TestResult(test_id=tid, verdict="NOT_APPLICABLE", deviation="no --anycast-target")
                    rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
                if not args.anycast_proof:
                    rec = base_rec(tid, "ICMP-05", {"anycast_target": args.anycast_target})
                    r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                                   deviation="anycast src unproven (need --anycast-proof)")
                    rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
                neg_src, neg_dst, cond = args.anycast_target, args.target, f"src={args.anycast_target} (anycast)"
            rec = base_rec(tid, tid[:7], {"negative_condition": cond})

            def is_error(p) -> bool:
                return (p.haslayer(ICMPv6DestUnreach) or p.haslayer(ICMPv6TimeExceeded)
                        or p.haslayer(ICMPv6PacketTooBig)
                        or (p.haslayer(ICMPv6ParamProblem)))

            # CONTROL: prefer UDP-to-closed-port (Port Unreachable), fall back to
            # unknown-option (Parameter Problem). The lab DUT answers neither for
            # unknown options, so UDP is the stronger trigger.
            sport, _ = P.derive_ids(args.seed, tid + "-sport")
            triggers = [
                ("udp-closed-port", P.build_udp_trigger(args.source, args.target, sport)),
                ("unknown-opt", P.build_unknown_option(args.source, args.target, 0xC1, iid, iseq)),
            ]
            ctrl_kind, ctrl_err = "", None
            for name, l3 in triggers:
                try:
                    _, got_c = tx_rx(l3, "", min(3.0, args.observation_timeout))
                except Exception as e:
                    r = TestResult(test_id=tid, verdict="ERROR", deviation=f"control failed: {e}")
                    rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); break
                hits = [p for p in got_c if is_error(p)]
                if hits:
                    ctrl_kind, ctrl_err = name, hits[0]
                    break
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="neither UDP-closed-port nor unknown-opt control elicited "
                                         "an ICMPv6 error; suppression untestable")
                rec.update(verdict=r.verdict, deviation=r.deviation,
                           observed=[{"kind": "UNKNOWN", "detail": "both controls silent"}])
                save(tid, rec, got_c); results.append(r); continue
            if ctrl_err is None:  # ERROR branch above used break
                continue
            rec["control"] = f"{ctrl_kind}: {ctrl_err.summary()}"
            try:  # NEGATIVE: same trigger shape under the negative condition
                if ctrl_kind == "udp-closed-port":
                    neg_l3 = P.build_udp_trigger(neg_src, neg_dst, sport)
                else:
                    neg_l3 = P.build_unknown_option(neg_src, neg_dst, 0xC1, iid, iseq)
                stim, got = tx_rx(neg_l3, "", args.observation_timeout)
            except Exception as e:
                r = TestResult(test_id=tid, verdict="ERROR", deviation=f"negative failed: {e}")
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            rec["stimulus"] = stim.summary()
            save(tid, rec, got)
            bad = [p for p in got if is_error(p)]
            if bad:
                r = TestResult(test_id=tid, verdict="FAIL",
                               deviation=f"error NOT suppressed under {cond}: {bad[0].summary()}")
            else:
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("INFERRED", f"control ({ctrl_kind}) error seen, {cond} elicited none")])
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        if args.verbose:
            print(f"  {tid:<10} {results[-1].verdict}")

    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    summary = {"rfc": RFC, "dut": args.target, "interface": args.interface,
               "tests": [{"id": r.test_id, "verdict": r.verdict} for r in results],
               "counts": counts, "versions": ev.versions()}
    ev.write_summary(run_dir, summary)
    print(f"\nRFC: {RFC}\nDUT: {args.target}\nInterface: {args.interface}\n\nTests:")
    for r in results:
        print(f"  {r.test_id:<10} {r.verdict}")
    print("\nSummary:")
    for k in ("PASS", "FAIL", "INCONCLUSIVE", "NOT_APPLICABLE", "ERROR"):
        print(f"  {k:<16} {counts.get(k, 0)}")
    print(f"\nEvidence:\n  {run_dir}")
    return 0 if counts.get("FAIL", 0) == 0 and counts.get("ERROR", 0) == 0 else 1


def main(argv=None) -> int:
    early = handle_list_tests(argv, CATALOG)
    if early is not None:
        return early
    args = extra_args(build_parser(PROG, RFC, description=DESCRIPTION,
                                   tests_help=TESTS_HELP, epilog=EPILOG,
                                   test_ids=TEST_IDS)).parse_args(argv)
    if args.dry_run:
        return dry_run(args)
    return run_live(args)


if __name__ == "__main__":
    sys.exit(main())
