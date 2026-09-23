#!/usr/bin/env python3
"""RFC 8201 conformance — Path MTU Discovery (ER Table-6: PMTU-01). Base build.

Never reduced to 'send oversized packet': injects a valid PTB with
MTU < 1280 quoting a real DUT packet, records baseline + post sizes, and
refuses to claim internal cache state. Import-safe: TX only in run_live().
"""
from __future__ import annotations

import subprocess
import sys
import time

from common.config import build_parser, validate_addrs
from common import evidence as ev
from common import packets as P
from common.verdict import Observation, TestResult

RFC = "8201"
PROG = "RFC-8201-conformance.py"
OBS_MINIMUM = "blackbox"

ER = {
    "PMTU-01": ("4", "If a node receives a Packet Too Big message reporting a "
                "next-hop MTU less than the IPv6 minimum link MTU, it must discard "
                "it. A node must not reduce its estimate of the Path MTU below the "
                "IPv6 minimum link MTU on receipt of a Packet Too Big message."),
}


def extra_args(p):
    p.add_argument("--ptb-mtu", type=int, default=1000,
                   help="injected PTB MTU (must be <1280 to exercise the requirement)")
    p.add_argument("--ptb-src", default="",
                   help="PTB source (default: --target's pretended router; recorded explicitly)")
    p.add_argument("--observed-pmtu", default="",
                   help="white-box cache readout supplied by operator, e.g. 'pmtu=1280'; empty=unexposed")
    p.add_argument("--post-probes", type=int, default=3,
                   help="post-PTB echo probes to size")
    p.add_argument("--probe-size", type=int, default=2000,
                   help="echo payload size forcing fragmentation so reply fragment sizes "
                        "reveal the DUT's effective path MTU (small replies carry no PMTU info)")
    return p


def dry_run(args) -> int:
    print(f"RFC 8201 dry-run  src={args.source} dst={args.target}")
    print(f"Test: PMTU-01  baseline {args.probe_size}B echo exchange (record reply fragment sizes)")
    print(f"  -> inject PTB src={args.ptb_src or '(path router)'} mtu={args.ptb_mtu} quoting last DUT packet")
    print(f"  -> {args.post_probes} post probes, record fragment sizes")
    print("  Expected: PMTU never reduced below 1280; PTB itself discarded as estimate")
    print("  Transmission: SKIPPED")
    if args.ptb_mtu >= 1280:
        print("  WARNING: --ptb-mtu >= 1280 does not exercise this ER (needs MTU < 1280)")
    return 0


def _iface_mac(iface: str) -> str:
    out = subprocess.check_output(["ip", "link", "show", "dev", iface], text=True)
    for line in out.splitlines():
        if line.strip().startswith("link/"):
            return line.split()[1]
    raise RuntimeError(f"no MAC for {iface}")


def run_live(args) -> int:
    from scapy.all import (AsyncSniffer, Ether, IPv6, ICMPv6EchoReply,
                           ICMPv6PacketTooBig, sendp, wrpcap)
    validate_addrs(args.source, args.target)
    if args.ptb_mtu >= 1280:
        print("ERROR: --ptb-mtu must be < 1280 to exercise PMTU-01")
        return 2
    run_dir = ev.new_run_dir(args.output)
    try:
        src_mac = _iface_mac(args.interface)
    except Exception as e:
        print(f"ERROR: {e}")
        return 2
    out = subprocess.run(["ip", "-6", "neigh", "show", "dev", args.interface, "to", args.target],
                         text=True, capture_output=True, check=False)
    f = out.stdout.split()
    if "lladdr" not in f:
        print(f"ERROR: no neighbor entry for {args.target}: {out.stdout.strip()}")
        return 2
    dst_mac = f[f.index("lladdr") + 1]
    ptb_src = args.ptb_src or args.target
    results: list[TestResult] = []
    rec = {"test_id": "PMTU-01", "rfc": RFC, "er_table": "Table-6", "rfc_section": "4",
           "er_requirement": ER["PMTU-01"][1], "role": "HOST",
           "observability": {"minimum": OBS_MINIMUM},
           "src": args.source, "dst": args.target, "versions": ev.versions(),
           "interface": args.interface, "ptb_mtu": args.ptb_mtu, "ptb_src": ptb_src,
           "observed_pmtu": args.observed_pmtu}

    def tx_echo(iid: int, iseq: int, timeout: float):
        pad = max(0, args.probe_size - len(b"RFC8200"))
        l3 = P.build_echo(args.source, args.target, iid, iseq, pad_len=pad)
        pkt = Ether(src=src_mac, dst=dst_mac) / l3
        sniffer = AsyncSniffer(iface=args.interface,
                               filter=f"ip6 and src host {args.target} and dst host {args.source}",
                               store=True)
        sniffer.start()
        time.sleep(0.1)
        sendp(pkt, iface=args.interface, count=1, verbose=False)
        time.sleep(timeout)
        return pkt, sniffer.stop()

    def echo_replies(got):
        return [p for p in got if p.haslayer(ICMPv6EchoReply)]

    try:
        # 1. baseline with fragmentation-forcing probes
        base_frags, last_dut_pkt = [], None
        for i in range(2):
            iid, iseq = P.derive_ids(args.seed, f"PMTU-01-base{i}")
            _, got = tx_echo(iid, iseq, min(4.0, args.observation_timeout))
            reps = echo_replies(got)
            base_frags += P.first_frag_payloads(reps)
            if reps:
                last_dut_pkt = reps[-1]
        rec["probe_size"] = args.probe_size
        rec["baseline_first_frag_payloads"] = base_frags
        if last_dut_pkt is None:
            r = TestResult(test_id="PMTU-01", verdict="INCONCLUSIVE",
                           deviation="no baseline DUT packet; nothing to quote in PTB, path unproven")
            rec.update(verdict=r.verdict, deviation=r.deviation)
            ev.write_test_json(run_dir, "PMTU-01", rec)
            print(f"\nRFC: {RFC}\n  PMTU-01    INCONCLUSIVE\nEvidence:\n  {run_dir}")
            return 0
        # 2. inject PTB quoting the real DUT packet (truncate quote like a router would)
        quoted = IPv6(bytes(last_dut_pkt[IPv6])[:128])
        ptb = P.build_ptb(ptb_src, args.source, args.ptb_mtu, quoted)
        ether_ptb = Ether(src=src_mac, dst=dst_mac) / ptb
        rec["ptb_summary"] = ether_ptb.summary()
        sniffer = AsyncSniffer(iface=args.interface, filter="ip6", store=True)
        sniffer.start()
        time.sleep(0.1)
        sendp(ether_ptb, iface=args.interface, count=1, verbose=False)
        time.sleep(1.0)
        # 3. post probes: fragment sizes reveal effective path MTU
        post_frags = []
        post_got_all = []
        for i in range(args.post_probes):
            iid, iseq = P.derive_ids(args.seed, f"PMTU-01-post{i}")
            _, got = tx_echo(iid, iseq, min(4.0, args.observation_timeout))
            post_got_all += list(got)
            post_frags += P.first_frag_payloads(echo_replies(got))
        inj_got = sniffer.stop()
        rec["post_first_frag_payloads"] = post_frags
        try:
            wrpcap(str(run_dir / "pcap" / "PMTU-01.pcap"), list(inj_got) + post_got_all, linktype=1)
            rec["pcap"] = "pcap/PMTU-01.pcap"
        except Exception as e:
            rec["pcap_error"] = str(e)
        ev.write_test_json(run_dir, "PMTU-01", rec)

        sub_floor = [x for x in post_frags if x < P.MIN_FLOOR_FIRST_FRAG]
        if args.observed_pmtu:
            try:
                val = int(args.observed_pmtu.split("=")[1])
            except Exception:
                val = -1
            rec["parsed_observed_pmtu"] = val
            if val != -1 and val < 1280:
                r = TestResult(test_id="PMTU-01", verdict="FAIL",
                               deviation=f"DUT PMTU readout {val} < 1280 after PTB mtu={args.ptb_mtu}",
                               observed=[Observation("DIRECTLY_OBSERVED", args.observed_pmtu)])
            elif val != -1:
                r = TestResult(test_id="PMTU-01", verdict="PASS",
                               observed=[Observation("DIRECTLY_OBSERVED", args.observed_pmtu)])
            else:
                r = TestResult(test_id="PMTU-01", verdict="ERROR",
                               deviation=f"unparseable --observed-pmtu: {args.observed_pmtu}")
        elif sub_floor and base_frags and min(base_frags) >= P.MIN_FLOOR_FIRST_FRAG:
            implied = P.implied_wire_mtu(min(sub_floor))
            r = TestResult(test_id="PMTU-01", verdict="FAIL",
                           deviation=f"post-PTB first-fragment {min(sub_floor)}B implies wire MTU ~{implied} "
                                     f"(<1280) while baseline stayed >= floor; DUT honored sub-floor PTB",
                           observed=[Observation("DIRECTLY_OBSERVED",
                                                 f"baseline={base_frags} post={post_frags}")])
        elif (base_frags and post_frags
                and min(base_frags) >= P.MIN_FLOOR_FIRST_FRAG
                and min(post_frags) >= P.MIN_FLOOR_FIRST_FRAG):
            r = TestResult(test_id="PMTU-01", verdict="PASS",
                           observed=[Observation("INFERRED",
                                                 f"fragmentation unchanged at/above floor "
                                                 f"(baseline={base_frags} post={post_frags}); "
                                                 f"PTB mtu={args.ptb_mtu} did not drag PMTU below 1280")])
        else:
            r = TestResult(test_id="PMTU-01", verdict="INCONCLUSIVE",
                           observed=[Observation("DIRECTLY_OBSERVED",
                                                 f"baseline_frags={base_frags} post_frags={post_frags}")],
                           deviation="fragment evidence insufficient (unfragmented or already-small path); "
                                     "internal PMTU cache unexposed (supply --observed-pmtu for a direct verdict)")
        rec.update(verdict=r.verdict, deviation=r.deviation,
                   observed=[{"kind": o.kind, "detail": o.detail} for o in r.observed])
        ev.write_test_json(run_dir, "PMTU-01", rec)
        results.append(r)
    except Exception as e:
        r = TestResult(test_id="PMTU-01", verdict="ERROR", deviation=str(e))
        rec.update(verdict=r.verdict, deviation=r.deviation)
        ev.write_test_json(run_dir, "PMTU-01", rec)
        results.append(r)

    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    ev.write_summary(run_dir, {"rfc": RFC, "dut": args.target, "interface": args.interface,
                               "tests": [{"id": r.test_id, "verdict": r.verdict} for r in results],
                               "counts": counts, "versions": ev.versions()})
    print(f"\nRFC: {RFC}\nDUT: {args.target}\nInterface: {args.interface}\n\nTests:")
    for r in results:
        print(f"  {r.test_id:<10} {r.verdict}")
    print(f"\nEvidence:\n  {run_dir}")
    return 0 if counts.get("FAIL", 0) == 0 and counts.get("ERROR", 0) == 0 else 1


def main(argv=None) -> int:
    args = extra_args(build_parser(PROG, RFC)).parse_args(argv)
    if args.dry_run:
        return dry_run(args)
    return run_live(args)


if __name__ == "__main__":
    sys.exit(main())
