#!/usr/bin/env python3
"""RFC 4862 conformance — SLAAC (ER Table-5: SLAAC-01..SLAAC-05). Base build.

SLAAC-03/05 reuse the ND-04/05 wire pattern with separate IDs/verdicts
(shared trace allowed, verdicts independent). Anycast is never inferred.
Import-safe: live TX only inside run_live().
"""
from __future__ import annotations

import subprocess
import sys
import time

from common.config import build_parser, validate_addrs
from common import evidence as ev
from common import packets as P
from common.verdict import Observation, TestResult

RFC = "4862"
PROG = "RFC-4862-conformance.py"
OBS_MINIMUM = "blackbox"

ER = {
    "SLAAC-01": ("5.4.2", "To improve DAD robustness, an interface MUST receive "
                 "and process datagrams sent to the all-nodes multicast address or "
                 "solicited-node multicast address of the tentative address during "
                 "the delay period."),
    "SLAAC-02": ("5.4", "Duplicate Address Detection MUST NOT be performed on "
                 "anycast addresses."),
    "SLAAC-03": ("7.1.1", "A node MUST silently discard any received Neighbour "
                 "Solicitation messages that do not satisfy the validity checks, "
                 "including an IP Hop Limit value of 255."),
    "SLAAC-04": ("7.1.1", "The contents of the Reserved field, and of any "
                 "unrecognized options, MUST be ignored."),
    "SLAAC-05": ("7.1.2", "A node MUST silently discard any received Neighbour "
                 "Advertisement messages that do not satisfy the validity checks, "
                 "including an IP Hop Limit value of 255."),
}

CASES = ["SLAAC-01", "SLAAC-02", "SLAAC-03", "SLAAC-04a", "SLAAC-04b", "SLAAC-05"]


def extra_args(p):
    p.add_argument("--tentative-addr", default="",
                   help="SLAAC-01: tentative address under DAD on the DUT")
    p.add_argument("--dad-delay", type=float, default=1.0,
                   help="SLAAC-01: DAD delay window to exercise (seconds)")
    p.add_argument("--dad-proof", default="",
                   help="SLAAC-01: how DAD state was proven, e.g. 'dut:dad-log'; empty=unproven")
    p.add_argument("--anycast-target", default="",
                   help="SLAAC-02: DUT anycast address (needs proof)")
    p.add_argument("--anycast-proof", default="",
                   help="SLAAC-02: how anycast was proven; empty=unproven")
    p.add_argument("--lladdr", default="", help="link-layer addr for ND options")
    return p


def selected(args) -> list[str]:
    only = set(t.strip() for t in args.tests.split(",") if t.strip())
    if not only:
        return list(CASES)
    out = []
    for c in CASES:
        if c in only or c.rstrip("ab") in only:
            out.append(c)
    return out


def dry_run(args) -> int:
    print(f"RFC 4862 dry-run  src={args.source} dst={args.target}")
    for tid in selected(args):
        if tid == "SLAAC-01":
            print(f"Test: SLAAC-01  tentative={args.tentative_addr or '(unset)'} dad-delay={args.dad_delay}s")
            print("  Stimulus: datagrams to all-nodes + solicited-node of tentative during delay")
            print("  Expected: DUT receives/processes them (needs --dad-proof or INCONCLUSIVE)")
        elif tid == "SLAAC-02":
            print(f"Test: SLAAC-02  anycast-target={args.anycast_target or '(unset)'}")
            print("  Expected: no DAD performed on anycast; unproven anycast -> NOT_APPLICABLE/INCONCLUSIVE")
        elif tid == "SLAAC-03":
            print("Test: SLAAC-03  NS hlim=254 (invalid) vs control hlim=255 (same wire as ND-04, separate verdict)")
        elif tid == "SLAAC-04a":
            print("Test: SLAAC-04a  NS with Reserved=0x00FFFFFF (altered), hlim=255")
            print("  Expected: ignored -> normal NA processing continues")
        elif tid == "SLAAC-04b":
            print("Test: SLAAC-04b  NS with unrecognized option type=30, hlim=255")
            print("  Expected: option ignored -> normal NA processing continues")
        elif tid == "SLAAC-05":
            print("Test: SLAAC-05  NA hlim=254 (invalid, bogus lladdr) then NS probe (separate verdict from ND-05)")
        print("  Transmission: SKIPPED")
    return 0


def _iface_mac(iface: str) -> str:
    out = subprocess.check_output(["ip", "link", "show", "dev", iface], text=True)
    for line in out.splitlines():
        if line.strip().startswith("link/"):
            return line.split()[1]
    raise RuntimeError(f"no MAC for {iface}")


def run_live(args) -> int:
    from scapy.all import (AsyncSniffer, Ether, IPv6, ICMPv6EchoRequest,
                           ICMPv6ND_NA, ICMPv6ND_NS, sendp, wrpcap)
    validate_addrs(args.source, args.target)
    run_dir = ev.new_run_dir(args.output)
    try:
        src_mac = _iface_mac(args.interface)
    except Exception as e:
        print(f"ERROR: {e}")
        return 2
    lladdr = args.lladdr or src_mac
    results: list[TestResult] = []

    def l2(dst: str) -> str:
        m = P.eth_dst_for_ipv6(dst)
        if m:
            return m
        out = subprocess.run(["ip", "-6", "neigh", "show", "dev", args.interface, "to", dst],
                             text=True, capture_output=True, check=True)
        f = out.stdout.split()
        if "lladdr" not in f:
            raise RuntimeError(f"no neighbor entry for {dst}: {out.stdout.strip()}")
        return f[f.index("lladdr") + 1]

    def tx_rx(l3, bpf: str, timeout: float):
        pkt = Ether(src=src_mac, dst=l2(l3.dst)) / l3
        sniffer = AsyncSniffer(iface=args.interface, filter=f"ip6 {bpf}", store=True)
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
        rec = {"test_id": tid, "rfc": RFC, "er_table": "Table-5", "rfc_section": sec,
               "er_requirement": req, "role": "HOST",
               "observability": {"minimum": OBS_MINIMUM},
               "src": args.source, "dst": args.target, "versions": ev.versions(),
               "interface": args.interface}
        if extra:
            rec.update(extra)
        return rec

    for tid in selected(args):
        if tid == "SLAAC-01":
            rec = base_rec(tid, tid, {"tentative": args.tentative_addr,
                                      "dad_delay": args.dad_delay, "dad_proof": args.dad_proof})
            if not args.tentative_addr:
                r = TestResult(test_id=tid, verdict="NOT_APPLICABLE",
                               deviation="no --tentative-addr configured")
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            if not args.dad_proof:
                # Still send the robustness stimuli and record, but cannot claim the requirement.
                try:
                    from scapy.layers.inet6 import IPv6
                    iid, iseq = P.derive_ids(args.seed, tid)
                    s1, g1 = tx_rx(P.build_echo(args.source, "ff02::1", iid, iseq), "", 1.0)
                    s2, g2 = tx_rx(P.build_echo(args.source, args.tentative_addr, iid, iseq + 1), "", 1.0)
                    got = list(g1) + list(g2)
                except Exception as e:
                    r = TestResult(test_id=tid, verdict="ERROR", deviation=str(e))
                    rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
                save(tid, rec, got)
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="stimuli sent/recorded but DAD state unproven (need --dad-proof); "
                                         "'DAD succeeded' alone would not prove this requirement")
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="dad-proof supplied but white-box correlation is a kink pass (base records only)")
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r)

        elif tid == "SLAAC-02":
            rec = base_rec(tid, tid, {"anycast_target": args.anycast_target,
                                      "anycast_proof": args.anycast_proof})
            if not args.anycast_target:
                r = TestResult(test_id=tid, verdict="NOT_APPLICABLE", deviation="no --anycast-target configured")
            elif not args.anycast_proof:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="anycast unproven (need --anycast-proof); harness will not fabricate it")
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="anycast proven but DAD-absence observation is a kink pass (base records only)")
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r)

        elif tid == "SLAAC-03":
            rec = base_rec(tid, tid)
            try:
                _, got_c = tx_rx(P.build_nd("NS", args.source, args.target, tgt=args.target,
                                            hlim=255, lladdr=lladdr),
                                 f"and src host {args.target}", min(4.0, args.observation_timeout))
                _, got = tx_rx(P.build_nd("NS", args.source, args.target, tgt=args.target,
                                          hlim=254, lladdr=lladdr),
                               f"and src host {args.target}", args.observation_timeout)
            except Exception as e:
                r = TestResult(test_id=tid, verdict="ERROR", deviation=str(e))
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            bad = [p for p in got if p.haslayer(ICMPv6ND_NA)]
            ctrl = [p for p in got_c if p.haslayer(ICMPv6ND_NA)]
            rec["control_na_seen"] = len(ctrl)
            save(tid, rec, got)
            if bad:
                r = TestResult(test_id=tid, verdict="FAIL", deviation=f"invalid NS elicited NA: {bad[0].summary()}")
            elif ctrl:
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("INFERRED", "control NS(255)->NA; NS(254)->none (RFC 4862 verdict)")])
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE", deviation="control NS got no NA")
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        elif tid in ("SLAAC-04a", "SLAAC-04b"):
            rec = base_rec(tid, "SLAAC-04")
            try:
                if tid == "SLAAC-04a":
                    l3 = P.build_ns_reserved(args.source, args.target, args.target)
                    rec["altered"] = "Reserved=0x00FFFFFF"
                else:
                    l3 = P.build_ns_unknown_opt(args.source, args.target, args.target, 30)
                    rec["altered"] = "unknown ND option type=30"
                _, got = tx_rx(l3, f"and src host {args.target}", args.observation_timeout)
            except Exception as e:
                r = TestResult(test_id=tid, verdict="ERROR", deviation=str(e))
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            save(tid, rec, got)
            nas = [p for p in got if p.haslayer(ICMPv6ND_NA)]
            if nas:
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("DIRECTLY_OBSERVED", f"NA despite {rec['altered']}: {nas[0].summary()}")])
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="no NA; cannot tell ignore-failure from delivery failure")
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        elif tid == "SLAAC-05":
            rec = base_rec(tid, tid)
            bogus = "02:00:00:aa:bb:cc"
            try:
                _, _ = tx_rx(P.build_nd("NA", args.source, args.target, tgt=args.target,
                                        hlim=254, lladdr=bogus),
                             f"and src host {args.target}", 2.0)
                _, got = tx_rx(P.build_nd("NS", args.source, args.target, tgt=args.target,
                                          hlim=255, lladdr=lladdr),
                               f"and src host {args.target}", args.observation_timeout)
            except Exception as e:
                r = TestResult(test_id=tid, verdict="ERROR", deviation=str(e))
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            save(tid, rec, got)
            from scapy.layers.inet6 import ICMPv6NDOptDstLLAddr
            nas = [p for p in got if p.haslayer(ICMPv6ND_NA)]
            poisoned = [p for p in nas if p.haslayer(ICMPv6NDOptDstLLAddr)
                        and p[ICMPv6NDOptDstLLAddr].lladdr.lower() == bogus]
            if poisoned:
                r = TestResult(test_id=tid, verdict="FAIL", deviation="invalid NA poisoned cache")
            elif nas:
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("INFERRED", "probe NA clean (RFC 4862 verdict)")])
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE", deviation="probe got no NA")
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
    args = extra_args(build_parser(PROG, RFC)).parse_args(argv)
    if args.dry_run:
        return dry_run(args)
    return run_live(args)


if __name__ == "__main__":
    sys.exit(main())
