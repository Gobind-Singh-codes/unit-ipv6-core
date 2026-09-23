# IPv6 RFC Conformance Test Suite — README for the Busy Evaluator

> You do not need to understand IPv6 to evaluate this project.
> Just copy-paste the commands in order. Each one tells you what success looks like.

## What is this?

A set of 5 test programs. Each one checks whether a network device (called the DUT)
follows one IPv6 rulebook (called an RFC):

| Program | Checks | Rulebook | Tests inside |
|---|---|---|---|
| `RFC-8200-conformance.py` | IPv6 base packet handling | RFC 8200 | IP-01 … IP-05 |
| `RFC-4443-conformance.py` | Error/info messages | RFC 4443 | ICMP-01 … ICMP-05 |
| `RFC-4861-conformance.py` | Neighbor Discovery | RFC 4861 | ND-01 … ND-05 |
| `RFC-4862-conformance.py` | Address setup / DAD | RFC 4862 | SLAAC-01 … SLAAC-05 |
| `RFC-8201-conformance.py` | Packet-Too-Big handling | RFC 8201 | PMTU-01 |

Total scope: **21 tests**. The exact requirements live in `ER-REFERENCE.md`.
The rules the tests follow live in `constraints.md` and `PROJECT.md`.

---

## 1. What you need (2 minutes)

- A Linux machine (tested on Debian 13).
- `uv` installed. Check with:

```bash
uv --version
```

- No network device needed for steps 2–4. You only need a real test network for step 5.

---

## 2. Setup — copy-paste exactly this (3 minutes)

```bash
cd /root/unit-RFCv6
uv sync --group dev
bash tools/get-prereqs.sh --check-only
```

**Success looks like this:**

```text
Wrote prereqs.json
...
RESULT: OK (core tools ready; thc-ipv6/SI6 are optional extras).
```

What that means:

- `OK (core)` = you can do everything in steps 3–4 right now.
- If it says `PREREQS INCOMPLETE`, run the installer version (needs root):

```bash
sudo bash tools/get-prereqs.sh --install
```

- `thc-ipv6 / SI6 MISSING` is **normal and fine**. They are optional extras
  and are not needed to run these tests.

---

## 3. Prove it works without any network (1 minute)

Run these three. All must pass. None of them sends a single packet.

```bash
uv run pytest -q
```

Success:

```text
18 passed
```

```bash
uv run RFC-8200-conformance.py --help
```

Success: a help screen listing `--interface --source --target --dry-run ...`.

```bash
uv run RFC-8200-conformance.py --interface host0 --source 2001:db8::2 --target 2001:db8::1 --dry-run
```

Success: ends with something like

```text
50 case(s) rendered, 0 transmitted.
```

The word to look for is **`0 transmitted`**. That is the whole point of dry-run:
it shows you what *would* be sent, without sending anything.

Repeat for the other four (all should print `SKIPPED` and exit 0):

```bash
for f in RFC-4443-conformance.py RFC-4861-conformance.py RFC-4862-conformance.py RFC-8201-conformance.py; do
  echo "== $f"
  uv run $f --interface host0 --source 2001:db8::2 --target 2001:db8::1 --dry-run
done
```

---

## 4. Look at one real test in plain English (30 seconds)

```bash
uv run RFC-8200-conformance.py --interface host0 --source 2001:db8::2 --target 2001:db8::1 --dry-run --tests IP-02
```

You will see:

```text
Test: IP-02  Option Type: 0xC1  Action bits: 11
  IPv6 Source: 2001:db8::2  Destination: 2001:db8::1
  Expected: discard + ICMPv6 Parameter Problem Code 2
  Transmission: SKIPPED
```

Translation: *"Send a packet with a made-up option. The device should throw it
away and send back a specific error."* Every test in the suite reads like that.

Try `IP-05` too — it checks that a Routing header with `Segments Left = 0`
gets ignored properly.

---

## 5. Live run — only if you have a test device (optional)

> Skip this whole section if you have no DUT. Steps 2–4 already prove the harness.
> Never point a live run at the Internet, your office network, or a production box.

You need three things from your lab: the interface name, your machine's IPv6,
and the device's IPv6. Then:

```bash
uv run RFC-8200-conformance.py \
  --interface <IFACE> \
  --source <YOUR-IPV6> \
  --target <DUT-IPV6> \
  --observation-timeout 5 \
  --output results
```

Example (lab values only — change to yours):

```bash
uv run RFC-8200-conformance.py \
  --interface eth0 \
  --source 2001:db8:100::2 \
  --target 2001:db8:100::1 \
  --observation-timeout 5 \
  --output results
```

**Success looks like this:**

```text
Tests:
  IP-01-001        PASS
  IP-02            INCONCLUSIVE
  ...

Summary:
  PASS             3
  FAIL             0
  ...

Evidence:
  results/2026-09-23T17-30-12/
```

Where to find the proof:

```text
results/<timestamp>/
├── summary.json        # machine-readable verdicts (send this to anyone who asks)
├── summary.md          # human-readable verdicts
├── IP-02.json          # one file per test: what was sent, what was seen, verdict
├── pcap/IP-02.pcap     # the actual packets (open in Wireshark)
└── IP-01-matrix.json   # the exact 44-chain matrix executed
```

**How to read a verdict (this matters):**

| Verdict | Meaning |
|---|---|
| `PASS` | Proven. The expected packets were seen on the wire. |
| `FAIL` | Proven wrong. The device answered incorrectly. Deviation is logged. |
| `INCONCLUSIVE` | Not proven either way. Usually "no reply and delivery unproven". Not a failure. |
| `NOT_APPLICABLE` | Needs something you don't have (e.g. IPsec security context for AH/ESP chains). |
| `ERROR` | The harness broke (bad interface, no neighbor entry). Fix your lab, not the device. |

Rules the suite enforces on itself:

- Capture starts **before** sending. Always.
- One packet per case. Bounded. No flooding, no scanning.
- Silence is never called `PASS`. If delivery can't be proven, you get `INCONCLUSIVE`.
- Nothing is ever edited to "make it pass". A bad stimulus reports `ERROR`.

---

## 6. Cheat sheet — the only commands that matter

| I want to… | Copy-paste |
|---|---|
| Install | `uv sync --group dev` |
| Health check | `bash tools/get-prereqs.sh --check-only` |
| Run offline self-tests | `uv run pytest -q` |
| See any program's options | `uv run RFC-8200-conformance.py --help` |
| Preview without sending | `uv run RFC-8200-conformance.py --interface host0 --source 2001:db8::2 --target 2001:db8::1 --dry-run` |
| Live run | Same as above, minus `--dry-run`, plus `--output results` |

---

## 7. If something goes wrong

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'common'` | You forgot `uv sync --group dev`. Run it, then use `uv run ...` (not bare `python3`). |
| `externally managed environment` from pip | Normal on Debian 13. Don't use pip. Use `uv sync --group dev`. |
| `no L2 neighbor entry for ...` on live run | Your machine doesn't know the DUT's MAC. Ping it once (`ping -6 -c1 <DUT>`) or add a static neighbor, then re-run. The suite refuses to guess. |
| `could not determine MAC for ...` | Wrong `--interface`. List yours with `ip -o link show`. |
| Live run shows all `INCONCLUSIVE` | Usually no real DUT path (packets never came back). Check cables, addresses, firewall. |
| Directly-connected lab, 8200 shows `INCONCLUSIVE` | Default `auto` proof already upgrades TX-on-wire + in-run liveness to `FAIL` where behavior is mandatory. Use `--delivery-proof strict` for the conservative mode. |
| `thc-ipv6 / SI6 MISSING` | Optional extras. Not needed to run these tests. |

---

## 8. What to send someone who asks "prove it"

1. `results/<timestamp>/summary.json` + `summary.md`
2. The per-test `<ID>.json` + `pcap/<ID>.pcap` for any disputed test
3. `prereqs.json` (from step 2) — proves which software versions produced the result

That's the entire audit trail. No screenshots needed.
