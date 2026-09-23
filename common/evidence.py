"""Evidence writer: results/<timestamp>/{summary.json,summary.md,<id>.json,<id>.pcap?}."""
from __future__ import annotations

import datetime
import json
import platform
from pathlib import Path


def new_run_dir(output_base: str) -> Path:
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    base = Path(output_base) / ts
    d = base
    n = 1
    while d.exists():
        n += 1
        d = Path(f"{base}-{n}")
    d.mkdir(parents=True, exist_ok=False)
    (d / "pcap").mkdir(exist_ok=True)
    return d


def versions() -> dict:
    try:
        import scapy
        scapy_v = scapy.__version__
    except Exception:
        scapy_v = "unknown"
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "scapy": scapy_v,
    }


def write_test_json(run_dir: Path, test_id: str, payload: dict) -> Path:
    p = run_dir / f"{test_id}.json"
    p.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return p


def write_summary(run_dir: Path, summary: dict) -> tuple[Path, Path]:
    jp = run_dir / "summary.json"
    jp.write_text(json.dumps(summary, indent=2, sort_keys=True))
    lines = [
        "# IPv6 RFC Conformance — run summary", "",
        f"RFC: {summary.get('rfc','')}",
        f"DUT: {summary.get('dut','')}",
        f"Interface: {summary.get('interface','')}", "",
        "Tests:",
    ]
    for t in summary.get("tests", []):
        lines.append(f"  {t['id']:<16} {t['verdict']}")
    lines += ["", "Summary:"]
    for k, v in summary.get("counts", {}).items():
        lines.append(f"  {k:<16} {v}")
    lines += ["", f"Evidence:", f"  {run_dir}"]
    mp = run_dir / "summary.md"
    mp.write_text("\n".join(lines) + "\n")
    return jp, mp
