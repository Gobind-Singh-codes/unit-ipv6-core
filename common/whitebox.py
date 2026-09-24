"""White-box transport: run operator-supplied remote checks through an
explicit tunnel (e.g. ssh). Test-scoped escalation per constraints section 27.

Nothing here executes during dry-run: RFC programs must only call run_check()
from their live path and print the would-be commands in dry-run.
"""
from __future__ import annotations

import re
import shlex
import subprocess

STDOUT_CAP = 8192

EXAMPLE_TUNNEL = "ssh -i lab.key admin@fd:33:33:33::1"
EXAMPLE_PMTU_CMD = "ip -6 route get fd:33:33:33:7446:4ff:fe34:5702"


def default_pmtu_remote_cmd(src: str) -> str:
    """Remote command inferred from run info: open a UDP socket to the source
    and read its cached path MTU. Pure. Assumes python3 on the DUT."""
    return ("python3 -c \"import socket; "
            "s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); "
            f"s.connect(('{src}',0)); "
            "print(f'cache mtu {s.getsockopt(socket.IPPROTO_IPV6,24)}')\"")


def validate(args, remote_attr: str = "pmtu_remote_cmd",
             remote_required: bool = True) -> str | None:
    """Return an error string (with fix example) for bad white-box config, else None."""
    remote = getattr(args, remote_attr, "")
    if args.whitebox and not args.whitebox_tunnel:
        return ("--whitebox needs --whitebox-tunnel (how to reach the DUT).\n"
                f"Example:\n  --whitebox --whitebox-tunnel '{EXAMPLE_TUNNEL}'\n"
                "Use key/agent auth; the tunnel string is stored in evidence.")
    if args.whitebox and not remote and remote_required:
        return (f"--whitebox needs --{remote_attr.replace('_', '-')} "
                f"(what to run on the DUT).\n"
                f"Example:\n  --whitebox --whitebox-tunnel '{EXAMPLE_TUNNEL}' "
                f"--{remote_attr.replace('_', '-')} \"{EXAMPLE_PMTU_CMD}\"")
    if not args.whitebox and remote:
        return (f"--{remote_attr.replace('_', '-')} without --whitebox is rejected: "
                f"escalation must be explicit.\n"
                f"Example:\n  --whitebox --whitebox-tunnel '{EXAMPLE_TUNNEL}' "
                f"--{remote_attr.replace('_', '-')} \"{EXAMPLE_PMTU_CMD}\"")
    if not args.whitebox and getattr(args, "whitebox_tunnel", ""):
        return ("--whitebox-tunnel without --whitebox is rejected: escalation must "
                "be explicit. Add --whitebox (plus the test's --*-remote-cmd), e.g.:\n"
                f"  --whitebox --whitebox-tunnel '{EXAMPLE_TUNNEL}'")
    return None


def run_check(tunnel: str, remote: str, timeout: float) -> dict:
    """Execute <tunnel> '<remote>' once, bounded. Returns an evidence-ready dict."""
    argv = shlex.split(tunnel) + [remote]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        out, err = r.stdout, r.stderr
        truncated = False
        if len(out) > STDOUT_CAP:
            out = out[:STDOUT_CAP]
            truncated = True
        return {"cmd": " ".join(argv), "rc": r.returncode, "stdout": out,
                "stderr": err[-2000:], "timed_out": False, "truncated": truncated}
    except subprocess.TimeoutExpired as e:
        return {"cmd": " ".join(argv), "rc": -1,
                "stdout": (e.stdout or b"").decode(errors="replace")[:STDOUT_CAP]
                if isinstance(e.stdout, bytes) else (e.stdout or "")[:STDOUT_CAP],
                "stderr": "TIMEOUT", "timed_out": True, "truncated": False}


def cache_hit(check: dict) -> bool:
    """True if the remote output looks like a route cache entry rather than an
    interface-MTU fallback. Convention: the remote command must surface the word
    'cache' (e.g. `ip -6 route show cache ...`); raw output is always stored."""
    return "cache" in (check.get("stdout") or "").lower()


def parse_first_int(text: str) -> int | None:
    """First integer in remote output. The remote command must print the value
    of interest (e.g. the PMTU); raw output is always stored for audit."""
    m = re.search(r"(\d+)", text or "")
    return int(m.group(1)) if m else None


def decide_pmtu(pre: int | None, post: int | None,
                pre_hit: bool = True, post_hit: bool = True,
                require_cache: bool = False):
    """Pure white-box PMTU verdict. Returns (verdict, detail, deviation).

    require_cache: fail closed unless both readouts came from a real route
    cache entry (hit flags) rather than an interface-MTU fallback.
    """
    if pre is None or post is None:
        return ("ERROR", "",
                "white-box PMTU readout unreadable (see whitebox checks); "
                "transport fault, not a DUT verdict")
    if require_cache and not (pre_hit and post_hit):
        return ("ERROR", "",
                "no PMTU cache entry observed (readout looks like an interface-MTU "
                "fallback, not a cache hit); use a cache-surfacing remote command "
                f"(pre_hit={pre_hit} post_hit={post_hit})")
    if post < 1280:
        return ("FAIL", f"DUT PMTU readout {post} < 1280 after sub-floor PTB",
                f"pre={pre} post={post}")
    if post == pre:
        return ("PASS", f"DUT PMTU unchanged at {post} (pre={pre})", "")
    return ("PASS", f"DUT PMTU {pre} -> {post}, stayed at/above floor",
            f"PMTU moved but never below 1280 (pre={pre} post={post})")
