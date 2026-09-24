#!/usr/bin/env python3
"""RFC 4861 conformance — Neighbor Discovery (ER Table-4: ND-01..ND-05). Base build.

Invalid stimulus is always Hop Limit 254 (vs required 255) with a valid
hlim=255 control first. Import-safe: live TX only inside run_live().
"""
from __future__ import annotations

import subprocess
import sys
import time

from common.config import build_parser, validate_addrs, handle_list_tests
from common import evidence as ev
from common import packets as P
from common import whitebox as WB
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

#: Bogus documentation prefix for the ND-02 invalid RA. Full literal form is
#: required: Scapy's PrefixInfo field treats a bare "2001:db8:dead" as a
#: hostname and attempts DNS resolution. Must never appear in real DUT state.
BOGUS_PREFIX = "2001:db8:dead::"
BOGUS_PLEN = 48
#: Substring used when scanning DUT state for the marker.
BOGUS_MARKER = "2001:db8:dead"

#: sysctl knobs inspected for the ND-03 pre-flight audit. send_ra may not
#: exist on all kernels; absence is neutral, never a contradiction.
RA_SYSCTLS = ("forwarding", "accept_ra", "send_ra")

VAR_MEANINGS = {
    "forwarding": "1 means routing is on (expected on a router; says nothing about advertising)",
    "accept_ra": "controls RECEIVING RAs (0=ignore, 1=accept, 2=accept even when forwarding); says nothing about sending",
    "send_ra": "RA sending toggle where present; absent on kernels without this knob (neutral)",
}


def audit_ra_config(sysctl_out: str, radvd_out: str, iface: str) -> dict:
    """Pure ND-03 pre-flight audit. Returns values, radvd finding, and whether
    the non-advertising claim is contradicted, with reasons.

    forwarding is recorded but NEVER a contradiction (a router forwards on all
    interfaces; that says nothing about advertising). send_ra==1 or a real
    radvd config attachment contradicts. Lines containing our own probe
    command (grep) are excluded so the check cannot match itself.
    """
    import re
    vals: dict[str, str] = {}
    for line in (sysctl_out or "").splitlines():
        m = re.search(rf"conf\.{re.escape(iface)}\.(\w+)\s*=\s*(\S+)", line)
        if m and m.group(1) in RA_SYSCTLS:
            vals[m.group(1)] = m.group(2)
    for k in RA_SYSCTLS:
        vals.setdefault(k, "absent")
    parts = (radvd_out or "").split("---")
    own = [ln for ln in (parts[0] if parts else "").splitlines() if "grep" not in ln]
    running = any("radvd" in ln for ln in own)
    cfg_lines = [ln for ln in (parts[1] if len(parts) > 1 else "").splitlines()
                 if "grep" not in ln]
    cfg_hit = any(iface in ln for ln in cfg_lines)
    manages = bool(cfg_hit)
    reasons = []
    if vals["send_ra"] not in ("absent", "0"):
        reasons.append(f"send_ra={vals['send_ra']}: RA sending toggle is on")
    if manages:
        reasons.append("radvd manages this interface: an advertiser is attached")
    return {"iface": iface, "values": vals, "radvd_running": running,
            "radvd_manages": manages, "contradiction": bool(reasons),
            "reasons": reasons}


def parse_dut_addrs(addr_out: str) -> dict:
    """Pure: map lowercase IPv6 address (no prefixlen) -> interface name from
    `ip -6 addr show` output."""
    import re
    table: dict[str, str] = {}
    cur: str | None = None
    for line in (addr_out or "").splitlines():
        m = re.match(r"\d+:\s+(\S+?):", line)
        if m:
            cur = m.group(1)
            continue
        m = re.search(r"\binet6\s+([0-9a-fA-F:]+)(?:%\S+)?/", line)
        if m and cur:
            table[m.group(1).lower()] = cur
    return table


def attribute_ra(ra_src: str, addr_map: dict) -> str | None:
    """Pure: egress interface for an RA source address, or None if unmapped."""
    return addr_map.get((ra_src or "").split("%")[0].lower())


def refusal_text(audit: dict) -> str:
    lines = ["Are you sure you want to continue?",
             f"RA appears CONFIGURED on interface '{audit['iface']}':"]
    lines += [f"  {r}" for r in audit["reasons"]]
    lines.append("Var meanings:")
    for k in RA_SYSCTLS:
        lines.append(f"  {k}={audit['values'][k]:<7} -> {VAR_MEANINGS[k]}")
    lines.append("A non-advertising test needs an interface with no advertiser: no radvd "
                 "entry, forwarding off or RA sending disabled.")
    lines.append("Re-run with --force to proceed anyway (recorded in evidence as forced=true).")
    return "\n".join(lines)


def red(text: str) -> str:
    import sys
    if sys.stderr.isatty():
        return f"\033[31m{text}\033[0m"
    return text


def bpf_both(src: str, dst: str) -> str:
    """Capture test traffic both ways; exclude unrelated host flows (pure)."""
    return f"ip6 and (host {src} or host {dst})"


def parse_own_ll(ip_out: str) -> str:
    """First non-tentative link-local address from `ip -6 addr show` (pure)."""
    import re
    for line in (ip_out or "").splitlines():
        m = re.search(r"\binet6\s+(fe80:[0-9a-fA-F:]+)(?:%\S+)?/", line)
        if m and "tentative" not in line and "deprecated" not in line:
            return m.group(1).lower()
    raise ValueError("no usable link-local address in ip output")


def routes_changed(pre_out: str, post_out: str, marker: str) -> tuple[bool, bool]:
    """Pure route-state compare. Returns (changed, marker_introduced) where
    marker_introduced means the bogus marker appears in post but not pre.
    Volatile `expires Nsec` countdowns are normalized: their ticking is not
    state change."""
    import re
    norm = lambda t: sorted(re.sub(r"expires \d+sec", "expires _",
                                   ln.strip()) for ln in (t or "").splitlines()
                            if ln.strip())
    pre, post = norm(pre_out), norm(post_out)
    changed = pre != post
    marker_hit = any(marker in ln for ln in post) and not any(marker in ln for ln in pre)
    return changed, marker_hit


DESCRIPTION = (
    "Check a network device's Neighbor Discovery (RFC 4861): Router\n"
    "Solicitation/Advertisement and Neighbor Solicitation/Advertisement handling,\n"
    "including the rule that packets with Hop Limit other than 255 are discarded.\n"
    "Tell the tool what the device is (host or router) so verdicts mean something."
)
TEST_IDS = "ND-01, ND-02, ND-03, ND-04, ND-05"
TESTS_HELP = (
    "run only these tests, e.g. --tests ND-04,ND-05 (default: all). "
    "This program: ND-01 (bad Router Solicitation), ND-02 (bad Router "
    "Advertisement), ND-03 (no advertisements from silent interfaces), ND-04 "
    "(bad Neighbor Solicitation), ND-05 (bad Neighbor Advertisement)."
)
EPILOG = """examples (dry-runs send nothing and work anywhere):
  RFC-4861-conformance.py --interface host0 --source 2001:db8::2 --target 2001:db8::1 --dry-run
  RFC-4861-conformance.py --interface host0 --source 2001:db8::2 --target 2001:db8::1 --dry-run --tests ND-04
  RFC-4861-conformance.py --interface host0 --source 2001:db8::2 --target 2001:db8::1 --list-tests

live run (replace the three values with your lab's; never the Internet):
  RFC-4861-conformance.py --interface <IFACE> --source <YOUR-IPV6> --target <DUT-IPV6> --output results --verbose

tell the tool what the device is (recorded in evidence):
  ... --dut-role host        (a host cannot fail router-only ND-01: NOT_APPLICABLE)
  ... --dut-role router --advertising-state non-advertising --non-adv-iface <DUT-IFACE> --ra-window 10
                             (ND-03: name the DEVICE's interface under test, e.g. wan_300.
                              Pick one with no advertiser: no radvd entry, RA sending
                              disabled. NOTE: accept_ra governs RECEIVING (WAN side) and
                              does NOT make an interface non-advertising; the SEND side
                              is what matters. ND-03 listens 10s; any Advertisement
                              from that interface is a FAIL.)
prove it with the device's own state (needs non-interactive ssh):
  ... --whitebox --whitebox-tunnel 'ssh -i lab.key admin@<DUT-IPV6>'
                             (ND-03 pre-flight reads forwarding/accept_ra/send_ra + radvd;
                              contradiction prints a red warning and refuses unless
                              --force is given, recorded as forced=true;
                              ND-02 snapshots accepted routes around the invalid RA:
                              bogus prefix present -> FAIL, unchanged -> PASS)"""

CATALOG = [
    ("ND-01", "A router discards Router Solicitations with Hop Limit != 255."),
    ("ND-02", "A node discards Router Advertisements with Hop Limit != 255."),
    ("ND-03", "A router sends no Advertisements from non-advertising interfaces."),
    ("ND-04", "A node discards Neighbor Solicitations with Hop Limit != 255."),
    ("ND-05", "A node discards Neighbor Advertisements with Hop Limit != 255."),
]





def extra_args(p):
    p.add_argument("--dut-role", default="auto", choices=["auto", "host", "router"],
                   help="what the device is: host, router, or auto if unsure "
                        "(default: auto; recorded in evidence; a host cannot fail "
                        "the router-only ND-01)")
    p.add_argument("--advertising-state", default="unknown",
                   choices=["unknown", "advertising", "non-advertising"],
                   help="ND-03 only: is the watched DUT interface supposed to advertise? "
                        "(default: unknown, which reports INCONCLUSIVE rather than guessing). "
                        "Picking non-advertising means: no radvd entry, no RA sending. "
                        "NOTE: accept_ra governs RECEIVING RAs (your WAN side) and does NOT "
                        "qualify an interface as non-advertising; the SEND side is what matters.")
    p.add_argument("--non-adv-iface", default="",
                   help="ND-03 only: NAME of the DUT interface under test, e.g. --non-adv-iface "
                        "wan_300 (the device's own interface name, not yours). Required for "
                        "ND-03 to decide; empty = INCONCLUSIVE.")
    p.add_argument("--force", action="store_true",
                   help="ND-03 only: proceed even when the pre-flight audit says RA looks "
                        "configured on --non-adv-iface (recorded in evidence as forced=true)")
    p.add_argument("--ra-window", type=float, default=10.0,
                   help="ND-03 only: seconds to listen for Advertisements (default: 10.0)")
    p.add_argument("--lladdr", default="",
                   help="link-layer address put in ND options (default: your interface's MAC)")
    p.add_argument("--whitebox", action="store_true",
                   help="white-box checks through --whitebox-tunnel: ND-03 RA-knob audit; "
                        "ND-02 route-state snapshot around the invalid RA")
    p.add_argument("--whitebox-tunnel", default="",
                   help="how this machine runs commands on the device, non-interactively, "
                        "e.g. 'ssh -i lab.key admin@2001:db8:100::1' (key/agent auth only; "
                        "stored in evidence, so never put a password here)")
    p.add_argument("--whitebox-timeout", type=float, default=10.0,
                   help="seconds allowed per remote check (default: 10.0)")
    p.add_argument("--nd-remote-cmd", default="ip -6 route show",
                   help="ND-02 only: remote command printing accepted routes/prefixes "
                        "(default: 'ip -6 route show'); a bogus documentation prefix in "
                        "the post snapshot proves the invalid RA was processed")
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
            print("Test: ND-01  three RS variants, each control hlim=255 then invalid hlim=254:")
            print("  a: global src + SLL option; b: link-local src + SLL; c: global src, no SLL")
            print("  Expected: router discards invalid (no RA) while some control elicits RA")
        elif tid == "ND-02":
            print("Test: ND-02  RA hlim=254 with bogus prefix 2001:db8:dead::/48 injected toward DUT")
            print("  Expected: silently discarded. Black-box alone -> INCONCLUSIVE; with --whitebox, "
                  "DUT route state is snapshotted around it (bogus present -> FAIL, unchanged -> PASS)")
        elif tid == "ND-03":
            print(f"Test: ND-03  listen {args.ra_window}s for RA from DUT iface "
                  f"{args.non_adv_iface or '(unset: --non-adv-iface)'}; "
                  f"advertising-state={args.advertising_state}")
            print("  Expected: no RA out non-advertising iface; unknown state -> INCONCLUSIVE")
            if args.whitebox:
                print(f"  Pre-flight audit via [{args.whitebox_tunnel or '(unset)'}]: sysctl "
                      "forwarding/accept_ra/send_ra + radvd; contradiction refuses unless --force")
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

    def tx_rx(l3, timeout: float):
        pkt = Ether(src=src_mac, dst=_l2(l3.dst)) / l3
        sniffer = AsyncSniffer(iface=args.interface,
                               filter=bpf_both(args.source, args.target), store=True)
        sniffer.start()
        time.sleep(0.1)
        sendp(pkt, iface=args.interface, count=1, verbose=False)
        time.sleep(timeout)
        return pkt, sniffer.stop()

    def tx_seen(got, src: str | None = None) -> bool:
        want = src or args.source
        for p in got:
            try:
                if p.haslayer(IPv6) and p[IPv6].src == want:
                    return True
            except Exception:
                continue
        return False

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
                own_ll = parse_own_ll(subprocess.run(
                    ["ip", "-6", "addr", "show", "dev", args.interface, "scope", "link"],
                    text=True, capture_output=True, check=True).stdout)
            except Exception as e:
                own_ll, ll_err = "", str(e)
            else:
                ll_err = ""
            variants = [
                ("a", args.source, lladdr, "global src + SLL option"),
                ("b", own_ll, lladdr, "link-local src + SLL option"),
                ("c", args.source, None, "global src, no SLL option"),
            ]
            rec["variants"] = []
            all_got = []
            try:
                for name, rsrc, rll, desc in variants:
                    if not rsrc:
                        rec["variants"].append({"name": name, "desc": desc, "skipped": True,
                                                "reason": ll_err or "no source address"})
                        continue
                    _, got_c = tx_rx(P.build_nd("RS", rsrc, "ff02::2", hlim=255, lladdr=rll),
                                     min(4.0, args.observation_timeout))
                    _, got = tx_rx(P.build_nd("RS", rsrc, "ff02::2", hlim=254, lladdr=rll),
                                   args.observation_timeout)
                    v = {"name": name, "desc": desc,
                         "control_ra": any(p.haslayer(ICMPv6ND_RA) for p in got_c),
                         "invalid_ra": [p.summary() for p in got if p.haslayer(ICMPv6ND_RA)],
                         "tx_seen": tx_seen(got_c, rsrc) and tx_seen(got, rsrc)}
                    rec["variants"].append(v)
                    all_got += list(got_c) + list(got)
                    if args.pcap:
                        try:
                            wrpcap(str(run_dir / "pcap" / f"{tid}{name}.pcap"),
                                   list(got_c) + list(got), linktype=1)
                            v["pcap"] = f"pcap/{tid}{name}.pcap"
                        except Exception as e:
                            v["pcap_error"] = str(e)
            except Exception as e:
                r = TestResult(test_id=tid, verdict="ERROR", deviation=str(e))
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, all_got); results.append(r); continue
            save(tid, rec, all_got)
            bad = [v for v in rec["variants"] if v.get("invalid_ra")]
            good = [v for v in rec["variants"]
                    if v.get("control_ra") and not v.get("invalid_ra")]
            if bad:
                r = TestResult(test_id=tid, verdict="FAIL",
                               deviation=f"invalid RS (hlim 254) elicited RA in variant "
                                         f"{bad[0]['name']} ({bad[0]['desc']}): {bad[0]['invalid_ra'][0]}")
            elif good:
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("INFERRED",
                                                     f"variant {good[0]['name']} ({good[0]['desc']}): "
                                                     f"control RS(255)->RA, RS(254)->none")])
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="no variant's control RS(255) elicited an RA; "
                                         "RS meaningfulness unproven on this path")
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, all_got); results.append(r)

        elif tid == "ND-02":
            wb = None
            if args.whitebox:
                if not args.whitebox_tunnel:
                    r = TestResult(test_id=tid, verdict="ERROR",
                                   deviation="misconfigured white-box: --whitebox needs --whitebox-tunnel "
                                             "(how to reach the DUT)")
                    rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
                wb = {"enabled": True, "tunnel": args.whitebox_tunnel,
                      "remote_cmd": args.nd_remote_cmd}
                pre_chk = WB.run_check(args.whitebox_tunnel, args.nd_remote_cmd,
                                       args.whitebox_timeout)
                wb["pre"] = {"check": pre_chk}
                if pre_chk["rc"] != 0 or pre_chk["timed_out"]:
                    r = TestResult(test_id=tid, verdict="ERROR",
                                   deviation="white-box route snapshot unreadable; see whitebox.pre.check")
                    rec["whitebox"] = wb
                    rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            try:
                stim, got = tx_rx(P.build_nd("RA", args.source, "ff02::1", hlim=254, lladdr=lladdr,
                                             prefix=BOGUS_PREFIX, plen=BOGUS_PLEN),
                                  args.observation_timeout)
            except Exception as e:
                r = TestResult(test_id=tid, verdict="ERROR", deviation=str(e))
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            rec["stimulus"] = stim.summary()
            rec["tx_seen_on_wire"] = tx_seen(got)
            rec["bogus_prefix"] = f"{BOGUS_PREFIX}/{BOGUS_PLEN}"
            save(tid, rec, got)
            linked = [p for p in got if p.haslayer(ICMPv6ND_NS) or p.haslayer(ICMPv6ND_NA)]
            if linked:
                r = TestResult(test_id=tid, verdict="FAIL",
                               deviation=f"DUT acted on invalid RA: {linked[0].summary()}")
            elif wb is not None:
                post_chk = WB.run_check(args.whitebox_tunnel, args.nd_remote_cmd,
                                        args.whitebox_timeout)
                wb["post"] = {"check": post_chk}
                rec["whitebox"] = wb
                if post_chk["rc"] != 0 or post_chk["timed_out"]:
                    r = TestResult(test_id=tid, verdict="ERROR",
                                   deviation="white-box post snapshot unreadable; see whitebox.post.check")
                else:
                    changed, marker = routes_changed(wb["pre"]["check"]["stdout"],
                                                     post_chk["stdout"], BOGUS_MARKER)
                    rec["state_changed"] = changed
                    rec["bogus_introduced"] = marker
                    if marker:
                        r = TestResult(test_id=tid, verdict="FAIL",
                                       observed=[Observation("DIRECTLY_OBSERVED",
                                                             f"bogus prefix {rec['bogus_prefix']} present "
                                                             f"in DUT state after invalid RA")],
                                       deviation="DUT processed an RA that fails validity (hlim 254)")
                    elif not changed:
                        r = TestResult(test_id=tid, verdict="PASS",
                                       observed=[Observation("DIRECTLY_OBSERVED",
                                                             "DUT route state identical before/after invalid RA")])
                    else:
                        r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                                       deviation="DUT state changed but without the bogus marker; "
                                                 "unattributable to our RA")
            else:
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="no linked DUT behavior; add --whitebox for a route-state "
                                         "snapshot (silent RA discard is unobservable black-box)")
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        elif tid == "ND-03":
            from scapy.all import AsyncSniffer as AS
            rec["advertising_state"] = args.advertising_state
            rec["ra_window"] = args.ra_window
            rec["non_adv_iface"] = args.non_adv_iface
            rec["forced"] = bool(args.force)
            if args.advertising_state == "unknown":
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="advertising state unknown (need --advertising-state); no inferred PASS")
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            if args.advertising_state == "advertising":
                r = TestResult(test_id=tid, verdict="NOT_APPLICABLE",
                               deviation="iface IS advertising; test targets non-advertising ifaces")
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            import re as _re
            if not args.non_adv_iface or not _re.fullmatch(r"[A-Za-z0-9_.:-]+", args.non_adv_iface):
                r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                               deviation="ND-03 needs --non-adv-iface: the DUT's own interface name "
                                         "under test (e.g. wan_300); refusing to guess which interface")
                rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            if args.whitebox:
                if not args.whitebox_tunnel:
                    r = TestResult(test_id=tid, verdict="ERROR",
                                   deviation="misconfigured white-box: --whitebox needs --whitebox-tunnel "
                                             "(how to reach the DUT), e.g. --whitebox-tunnel "
                                             "'ssh -i lab.key admin@2001:db8:100::1'")
                    rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
                di = args.non_adv_iface
                sys_cmd = ("sysctl " + " ".join(f"net.ipv6.conf.{di}.{k}" for k in
                           ("forwarding", "accept_ra", "send_ra")))
                radvd_cmd = ("ps -ef | grep '[r]advd'; echo ---; "
                             f"grep -H '{di}' /etc/radvd.conf /etc/radvd/*.conf 2>/dev/null")
                rec["whitebox"] = {"enabled": True, "tunnel": args.whitebox_tunnel}
                sys_chk = WB.run_check(args.whitebox_tunnel, sys_cmd, args.whitebox_timeout)
                radvd_chk = WB.run_check(args.whitebox_tunnel, radvd_cmd, args.whitebox_timeout)
                rec["whitebox"]["sysctl"] = sys_chk
                rec["whitebox"]["radvd"] = radvd_chk
                audit = audit_ra_config(sys_chk["stdout"], radvd_chk["stdout"], di)
                rec["ra_audit"] = audit
                if audit["contradiction"] and not args.force:
                    import sys as _sys
                    print(red(refusal_text(audit)), file=_sys.stderr)
                    r = TestResult(test_id=tid, verdict="ERROR",
                                   deviation="refused: RA looks configured on "
                                             f"'{di}' ({'; '.join(audit['reasons'])}); re-run with "
                                             "--force to proceed anyway")
                    rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, []); results.append(r); continue
            sniffer = AS(iface=args.interface, filter="ip6 and icmp6 and ip6[40] == 134", store=True)
            sniffer.start()
            time.sleep(args.ra_window)
            got = sniffer.stop()
            ras = [p for p in got if p.haslayer(ICMPv6ND_RA) and not (p.haslayer(IPv6) and p[IPv6].src == args.source)]
            rec["ra_observed"] = len(ras)
            save(tid, rec, got)
            if ras:
                ra_src = ras[0][IPv6].src if ras[0].haslayer(IPv6) else ""
                owner = None
                if args.whitebox:
                    addr_chk = WB.run_check(args.whitebox_tunnel, "ip -6 addr show",
                                            args.whitebox_timeout)
                    addr_map = parse_dut_addrs(addr_chk["stdout"])
                    rec["whitebox"]["addrs"] = addr_chk
                    rec["addr_map"] = addr_map
                    owner = attribute_ra(ra_src, addr_map)
                    rec["ra_attribution"] = {"src": ra_src, "egress_iface": owner}
                    ev.write_test_json(run_dir, tid, rec)
                if owner == args.non_adv_iface:
                    r = TestResult(test_id=tid, verdict="FAIL",
                                   deviation=f"RA from the interface under test '{owner}': "
                                             f"{ras[0].summary()}")
                elif owner:
                    r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                                   observed=[Observation("DIRECTLY_OBSERVED",
                                                         f"RA belongs to '{owner}', not the interface "
                                                         f"under test '{args.non_adv_iface}'")],
                                   deviation="observed RA cannot be attributed to --non-adv-iface; "
                                             "likely leaked from an advertising interface")
                else:
                    r = TestResult(test_id=tid, verdict="INCONCLUSIVE",
                                   observed=[Observation("DIRECTLY_OBSERVED",
                                                         f"RA from {ra_src or 'unknown source'}")],
                                   deviation="RA egress interface unproven; re-run with --whitebox "
                                             "so the source can be mapped to a DUT interface")
            else:
                r = TestResult(test_id=tid, verdict="PASS",
                               observed=[Observation("INFERRED",
                                                     f"no RA in {args.ra_window}s window ({len(got)} pkts total)")])
            rec.update(verdict=r.verdict, deviation=r.deviation); save(tid, rec, got); results.append(r)

        elif tid == "ND-04":
            try:
                _, got_c = tx_rx(P.build_nd("NS", args.source, args.target, tgt=args.target,
                                            hlim=255, lladdr=lladdr),
                                 min(4.0, args.observation_timeout))
                _, got = tx_rx(P.build_nd("NS", args.source, args.target, tgt=args.target,
                                          hlim=254, lladdr=lladdr),
                               args.observation_timeout)
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
                             2.0)
                _, got = tx_rx(P.build_nd("NS", args.source, args.target, tgt=args.target,
                                          hlim=255, lladdr=lladdr),
                               args.observation_timeout)
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
