"""CLI + config shared across RFC programs (PROJECT.md section 5).

Each RFC program passes its own description, test catalog, and examples so
--help reads as a standalone tool. The flags themselves stay identical.
"""
from __future__ import annotations

import argparse
import ipaddress


def build_parser(prog: str, rfc: str, description: str | None = None,
                 tests_help: str | None = None, epilog: str | None = None,
                 test_ids: str = "", matrix_opts: bool = False) -> argparse.ArgumentParser:
    """matrix_opts: show the RFC 8200 extension-header matrix flags; other
    programs still accept them (contract) but hide them from --help so each
    program reads as its own tool."""
    p = argparse.ArgumentParser(
        prog=prog,
        description=description or f"IPv6 RFC {rfc} conformance",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--interface", required=True,
                   help="network interface to send/capture on, e.g. --interface host0 "
                        "(list yours with: ip -o link show)")
    p.add_argument("--source", required=True,
                   help="YOUR machine's literal IPv6 address, e.g. --source 2001:db8::2 "
                        "(an address assigned to --interface)")
    p.add_argument("--target", required=True,
                   help="the DEVICE under test's literal IPv6 address, "
                        "e.g. --target 2001:db8::1 (never the public Internet)")
    p.add_argument("--tests", default="",
                   help=tests_help or "comma-separated test IDs (default: all)")
    p.add_argument("--list-tests", action="store_true",
                   help=f"print this program's test catalog ({test_ids}) and exit; "
                        f"sends nothing")
    p.add_argument("--dry-run", action="store_true",
                   help="show every packet that WOULD be sent, then exit; sends nothing, "
                        "safe anywhere")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="seconds allowed per test step (default: 5.0)")
    p.add_argument("--observation-timeout", type=float, default=5.0,
                   help="seconds to listen for the device's answer after each packet "
                        "(default: 5.0; raise on slow labs)")
    p.add_argument("--output", default="results",
                   help="directory for evidence (default: results); a new timestamped "
                        "folder is created per run, old runs are never overwritten")
    p.add_argument("--pcap", action="store_true", default=True,
                   help="save packet captures (default: on)")
    p.add_argument("--no-pcap", dest="pcap", action="store_false",
                   help="skip packet captures")
    p.add_argument("--verbose", action="store_true",
                   help="print each test's verdict as it finishes")
    p.add_argument("--profile", default="core",
                   choices=["core", "exhaustive", "security-only"],
                   help="RFC 8200 extension-header matrix size: core = bounded default "
                        "(44 chains); exhaustive = every permutation (slow, maintenance "
                        "window); security-only = IPsec chains (needs security context)."
                        if matrix_opts else argparse.SUPPRESS)
    p.add_argument("--max-chain-length", type=int, default=6,
                   help="longest generated header chain in exhaustive profile (default: 6)"
                   if matrix_opts else argparse.SUPPRESS)
    p.add_argument("--seed", type=int, default=0,
                   help="number steering generated packet IDs (default: 0); same seed + "
                        "same flags = same packets, logged in evidence")
    return p


def handle_list_tests(argv, catalog) -> int | None:
    """Print a test catalog without requiring interface/addrs. Returns 0 when
    --list-tests was requested (caller returns it), else None. Pure."""
    import sys
    raw = list(argv) if argv is not None else sys.argv[1:]
    if "--list-tests" in raw:
        for tid, meaning in catalog:
            print(f"{tid:<8} {meaning}")
        return 0
    return None


def validate_addrs(source: str, target: str) -> None:
    for label, val in (("source", source), ("target", target)):
        try:
            ipaddress.IPv6Address(val)
        except ValueError as e:
            raise SystemExit(f"ERROR: --{label} must be a literal IPv6 address: {e}")
        if val.lower().startswith("ff") is False and "%" in val:
            raise SystemExit(f"ERROR: --{label} must not contain a zone index")
    # Refuse obvious non-test defaults (loopback allowed only if explicit -- fine,
    # but refuse DNS names: already enforced by literal parse above).
