"""CLI + config shared across RFC programs (PROJECT.md section 5)."""
from __future__ import annotations

import argparse
import ipaddress


def build_parser(prog: str, rfc: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=prog, description=f"IPv6 RFC {rfc} conformance")
    p.add_argument("--interface", required=True, help="TX/RX interface")
    p.add_argument("--source", required=True, help="literal IPv6 source address")
    p.add_argument("--target", required=True, help="literal IPv6 destination (DUT)")
    p.add_argument("--tests", default="", help="comma-separated test IDs (default: all)")
    p.add_argument("--dry-run", action="store_true", help="render stimuli, never transmit")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--observation-timeout", type=float, default=5.0)
    p.add_argument("--output", default="results")
    p.add_argument("--pcap", action="store_true", default=True)
    p.add_argument("--no-pcap", dest="pcap", action="store_false")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--profile", default="core",
                   choices=["core", "exhaustive", "security-only"],
                   help="IP-01 matrix profile (RFC 8200 only; ignored elsewhere)")
    p.add_argument("--max-chain-length", type=int, default=6)
    p.add_argument("--seed", type=int, default=0, help="deterministic ID/seq seed base")
    return p


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
