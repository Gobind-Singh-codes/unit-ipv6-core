#!/usr/bin/env python3
"""RFC 4861 conformance — Neighbor Discovery (ER Table-4: ND-01..ND-05). Base build.

Invalid stimulus is always Hop Limit 254 (vs required 255) with a valid
hlim=255 control first. Import-safe: live TX only inside run_live().
"""
from __future__ import annotations

import subprocess
import sys
import time

from common.config import build_parser, validate_addrs
from common import evidence as ev
from common import packets as P
from common.verdict import Observation, TestResult

RFC = "4861"
PROG = "RFC-4861-conformance.py"
OBS_MINIMUM = "blackbox"

ER = {
    "ND-01": ("6.1.1", "A router MUST silently discard any received Router "
              "Solicitation messages that do not satisfy the validity checks, "
              "including an IP Hop Limit value of 255."),
    "ND-02": ("6.1.2", "A node MUST silently discard any received Router "
              "Advertisement messages that do not satisfy the validity checks, "
              "including an IP Hop Limit value of 255."),
    "ND-03": ("6.2.2", "A router MUST NOT send Router Advertisements out any "
              "interface that is not an advertising interface."),
    "ND-04": ("7.1.1", "A node MUST silently discard any received Neighbour "
              "Solicitation messages that do not satisfy the validity checks, "
              "including an IP Hop Limit value of 255."),
    "ND-05": ("7.1.2", "A node MUST silently discard any received Neighbour "
              "Advertisement messages that do not satisfy the validity checks, "
              "including an IP Hop Limit value of 255."),
}

CASES = ["ND-01", "ND-02", "ND-03", "ND-04", "ND-05"]


def extra_args(p):
    p.add_argument("--dut-role", default="auto", choices=["auto", "host", "router"],
                   help="DUT role assumption (recorded in evidence)")
    p.add_argument("--advertising-state", default="unknown",
                   choices=["unknown", "advertising", "non-advertising"],
                   help="ND-03: is the observed iface an advertising interface?")
    p.add_argument("--ra-window", type=float, default=10.0,
                   help="ND-03: seconds to listen for (non-)RA")
    p.add_argument("--lladdr", default="",
                   help="source link-layer address to advertise in ND options (default: iface MAC)")
    return p


def selected(args) -> list[str]:
    only = set(t.strip() for t in args.tests.split(",") if t.strip())
    if not only:
        return list(CASES)
    return [c for c in CASES if c in only]


def dry_run(args) -> int:
    print(f"RFC 4861 dry-run  src={args.source} dst={args.target} dut-role={args.dut_role}")
    for tid in selected(args):
        if tid == "ND-01":
            print("Test: ND-01  RS hlim=254 (invalid) vs control RS hlim=255")
            print("  Expected: router discards invalid (no RA elicited); control may elicit RA")
        elif tid == "ND-02":
            print("Test: ND-02  RA hlim=254 (invalid) injected toward DUT")
            print("  Expected: silently discarded (no processing); weak black-box -> INCONCLUSIVE unless linked behavior seen")
        elif tid == "ND-03":
            print(f"Test: ND-03  listen {args.ra_window}s for RA; advertising-state={args.advertising_state}")
            print("  Expected: no RA out non-advertising iface; unknown state -> INCONCLUSIVE")
        elif tid == "ND-04":
            print("Test: ND-04  NS tgt=<DUT> hlim=254 (invalid) vs control hlim=255")
            print("  Expected: invalid elicits no NA; control NA proves path")
        elif tid == "ND-05":
            print("Test: ND-05  NA hlim=254 (invalid, bogus lladdr) then NS probe")
            print("  Expected: cache unpoisoned (probe NA carries real lladdr); poisoned -> FAIL")
        print("  Transmission: SKIPPED")
    return 0


def _iface_mac(iface: str) -> str:
    out = subprocess.check_output(["ip", "link", "show", "dev", iface], text=True)
    for line in out.splitlines():
        if line.strip().startswith("link/"):
            return line.split()[1]
    raise RuntimeError(f"no MAC for {iface}")


def run_live(args) -> int:
    from scapy.all import (AsyncSniffer, Ether, IPv6, ICMPv6ND_NA, ICMPv6ND_NS,
                           ICMPv6ND_RA, ICMPv6ND_RS, sendp, wrpcap)
    validate_addrs(args.source, args.target)
    run_dir = ev.new_run_dir(args.output)
    try:
        src_mac = _iface_mac(args.interface)
    except Exception as e:
        print(f"ERROR: {e}")
        return 2
    lladdr = args.lladdr or src_mac
    results: list[TestResult] = []

    def tx_rx(l3, bpf: str, timeout: float):
        pkt = Ether(src=src_mac, dst=_l2(l3.dst)) / l3
        sniffer = AsyncSniffer(iface=args.interface, filter=f"ip6 {bpf}", store=True)
        sniffer.start()
        time.sleep(0.1)
        sendp(pkt, iface=args.interface, count=1, verbose=False)
        time.sleep(timeout)
        return pkt, sniffer.stop()

    def _l2(dst: str) -> str:
        m = P.eth_dst_for_ipv6(dst)
        if m:
            return m
        from scapy.all import conf  # lazy; neighbor lookup via ip cmd
        out = subprocess.run(["ip", "-6", "neigh", "show", "dev", args.interface, "to", dst],
                             text=True, capture_output=True, check=True)
        f = out.stdout.split()
        if "lladdr" not in f:
            raise RuntimeError(f"no neighbor entry for {dst}: {out.stdout.strip()}")
        return f[f.index("lladdr") + 1]

    def save(tid: str, rec: dict, got) -> None:
        if args.pcap:
            try:
                wrpcap(str(run_dir / "pcap" / f"{tid}.pcap"), list(got), linktype=1)
                rec["pcap"] = f"pcap/{tid}.pcap"
            except Exception as e:
                rec["pcap_error"] = str(e)
        ev.write_test_json(run_dir, tid, rec)

    def base_rec(tid: str) -> dict:
        sec, req = ER[tid]
        return {"test_id": tid, "rfc": RFC, "er_table": "Table-4", "rfc_section": sec,
                "er_requirement": req, "role": args.dut_role.upper(),
                "observability": {"minimum": OBS_MINIMUM},
                "src": args.source, "dst": args.target, "versions": ev.versions(),
                "interface": args.interface}

    for tid in selected(args):
        rec = base_rec(tid)
        if tid == "ND-01":
            if args.dut_role == "host":
                r = TestResult(test_id=tid, verdict="NOT_APPLICABLE",
                               deviation="DUT is host; RS-discard is a router requirement")
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            try:
                _, got_c = tx_rx(P.build_nd("RS", args.source, "ff02::2", hlim=255, lladdr=lladdr),
                                 f"and src host {args.target}", min(4.0, args.observation_timeout))
                _, got = tx_rx(P.build_nd("RS", args.source, "ff02::2", hlim=254, lladdr=lladdr),
                               f"and src host {args.target}", args.observation_timeout)
            except Exception as e:
                r = TestResult(test_id=tid, verdict="ERROR", deviation=str(e))
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            rec["control_ra_seen"] = any(p.haslayer(ICMPv6ND_RA) for p in got_c)
            save(tid, rec, got)
            ra = [p for p in got if p.haslayer(ICMPv6ND_RA)]
            if ra:
                r = TestResult(test_id=tid, verdict="FAIL",
                               deviation=f"invalid RS (hlim 254) elicited RA: {ra[0].summary()}")
            elif any(p.haslayer(ICMPv6ND_RA) for p in got_c):
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("INFERRED", "control RS(255) elicited RA; RS(254) elicited none")])
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="control RS(255) elicited no RA; RS meaningfulness unproven")
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        elif tid == "ND-02":
            try:
                stim, got = tx_rx(P.build_nd("RA", args.source, "ff02::1", hlim=254, lladdr=lladdr),
                                  f"and src host {args.target}", args.observation_timeout)
            except Exception as e:
                r = TestResult(test_id=tid, verdict="ERROR", deviation=str(e))
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            rec["stimulus"] = stim.summary()
            save(tid, rec, got)
            linked = [p for p in got if p.haslayer(ICMPv6ND_NS) or p.haslayer(ICMPv6ND_NA)]
            if linked:
                r = TestResult(test_id=tid, verdict="FAIL",
                               deviation=f"DUT acted on invalid RA: {linked[0].summary()}")
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="no linked DUT behavior; silent-discard of RA is weakly observable black-box")
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        elif tid == "ND-03":
            from scapy.all import AsyncSniffer as AS
            rec["advertising_state"] = args.advertising_state
            rec["ra_window"] = args.ra_window
            if args.advertising_state == "unknown":
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="advertising state unknown (need --advertising-state); no inferred PASS")
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            if args.advertising_state == "advertising":
                r = TestResult(test_id=tid, verdict="NOT_APPLICABLE",
                               deviation="iface IS advertising; test targets non-advertising ifaces")
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            sniffer = AS(iface=args.interface, filter="ip6 and icmp6 and ip6[40] == 134", store=True)
            sniffer.start()
            time.sleep(args.ra_window)
            got = sniffer.stop()
            ours = [p for p in got if p.haslayer(IPv6) and p[IPv6].src == args.source]
            ras = [p for p in got if p.haslayer(ICMPv6ND_RA) and not (p.haslayer(IPv6) and p[IPv6].src == args.source)]
            rec["ra_observed"] = len(ras)
            save(tid, rec, got)
            if ras:
                r = TestResult(test_id=tid, verdict="FAIL",
                               deviation=f"RA seen from non-advertising iface: {ras[0].summary()}")
            else:
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("INFERRED",
                                                     f"no RA in {args.ra_window}s window ({len(got)} pkts total)")])
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        elif tid == "ND-04":
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
            ctrl_na = [p for p in got_c if p.haslayer(ICMPv6ND_NA)]
            bad_na = [p for p in got if p.haslayer(ICMPv6ND_NA)]
            rec["control_na_seen"] = len(ctrl_na)
            save(tid, rec, got)
            if bad_na:
                r = TestResult(test_id=tid, verdict="FAIL",
                               deviation=f"invalid NS (hlim 254) elicited NA: {bad_na[0].summary()}")
            elif ctrl_na:
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("INFERRED", "control NS(255)->NA; NS(254)->no NA")])
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="control NS(255) got no NA; resolution path unproven")
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        elif tid == "ND-05":
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
            nas = [p for p in got if p.haslayer(ICMPv6ND_NA)]
            from scapy.layers.inet6 import ICMPv6NDOptDstLLAddr
            poisoned = [p for p in nas if p.haslayer(ICMPv6NDOptDstLLAddr)
                        and p[ICMPv6NDOptDstLLAddr].lladdr.lower() == bogus]
            if poisoned:
                r = TestResult(test_id=tid, verdict="FAIL",
                               deviation="invalid NA poisoned cache (probe returned bogus lladdr)")
            elif nas:
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("INFERRED", "probe NA carries non-bogus lladdr; invalid NA ignored")])
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="probe NS got no NA; cache state unobservable")
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        if args.verbose:
            print(f"  {tid:<8} {results[-1].verdict}")

    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    summary = {"rfc": RFC, "dut": args.target, "interface": args.interface,
               "dut_role": args.dut_role,
               "tests": [{"id": r.test_id, "verdict": r.verdict} for r in results],
               "counts": counts, "versions": ev.versions()}
    ev.write_summary(run_dir, summary)
    print(f"\nRFC: {RFC}\nDUT: {args.target}\nInterface: {args.interface} (role={args.dut_role})\n\nTests:")
    for r in results:
        print(f"  {r.test_id:<8} {r.verdict}")
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
