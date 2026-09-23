#!/usr/bin/env python3
import random

icmp_id = random.randint(0, 65535)
icmp_seq = random.randint(0,65535)

import subprocess

from scapy.all import (
    Ether,
    IPv6,
    IPv6ExtHdrDestOpt,
    PadN,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6ParamProblem,
    AsyncSniffer,
    sendp,
    hexdump,
)


IFACE = "wlp0s20f3"

SRC_IP = "cafe::9"
DST_IP = "cafe::3"

TIMEOUT = 5

def ipv6_header_chain(pkt):
    headers = []

    layer = pkt.getlayer(IPv6)

    while layer:
        headers.append(layer.__class__.__name__)

        if not hasattr(layer, "payload") or not layer.payload:
            break

        layer = layer.payload

    return " -> ".join(headers)


def get_iface_mac(iface: str) -> str:
    out = subprocess.check_output(
        ["ip", "link", "show", "dev", iface],
        text=True,
    )

    for line in out.splitlines():
        line = line.strip()

        if line.startswith("link/"):
            return line.split()[1]

    raise RuntimeError(f"Could not determine MAC for {iface}")


def get_neigh_mac(ip: str, iface: str) -> str:
    out = subprocess.run(
        ["ip", "-6", "neigh", "show", "dev", iface, "to", ip],
        text=True,
        capture_output=True,
        check=True,
    )

    fields = out.stdout.split()

    if "lladdr" not in fields:
        raise RuntimeError(
            f"No L2 neighbor entry for {ip} on {iface}.\n"
            f"Output: {out.stdout.strip()}"
        )

    return fields[fields.index("lladdr") + 1]

def is_reply(pkt) -> bool:
    if not pkt.haslayer(IPv6):
        return False

    if not pkt.haslayer(ICMPv6EchoReply):
        return False

    ip = pkt[IPv6]
    icmp = pkt[ICMPv6EchoReply]

    return (
        ip.src == DST_IP
        and ip.dst == SRC_IP
        and icmp.id == icmp_id
        and icmp.seq == icmp_seq
    )


src_mac = get_iface_mac(IFACE)

# Populate the IPv6 neighbor cache.
subprocess.run(
    ["ping", "-6", "-c1", DST_IP],
    text=True,
    capture_output=True,
    check=True,
)

dst_mac = get_neigh_mac(DST_IP, IFACE)


pkt = (
    Ether(
        src=src_mac,
        dst=dst_mac,
    )
    / IPv6(
        src=SRC_IP,
        dst=DST_IP,
        hlim=64,
        fl=0,
    )
    / IPv6ExtHdrDestOpt(
        options=[
            # Fill the 6-byte option area with PadN.
            PadN(optdata=b"\x00\x00\x00\x00"),
        ]
    )
    / ICMPv6EchoRequest(
        id=icmp_id,
        seq=icmp_seq,
        data=b"",
    )
)


print(f"Interface : {IFACE}")
print(f"Source MAC: {src_mac}")
print(f"Dest MAC  : {dst_mac}")
print(f"Source IP : {SRC_IP}")
print(f"Dest IP   : {DST_IP}")

print()
print("=" * 70)
print("PACKET BEING SENT")
print("=" * 70)

print("\nSummary:")
print(pkt.summary())

print("\nDecoded packet:")
pkt.show()

print("\nHexdump:")
hexdump(pkt)

print("\nIPv6 header chain:")
print(ipv6_header_chain(pkt))


# ------------------------------------------------------------
# Start capture BEFORE sending.
# ------------------------------------------------------------

print(f"\nWaiting up to {TIMEOUT} seconds for a reply...")

sniffer = AsyncSniffer(
    iface=IFACE,
    filter=f"ip6 and src host {DST_IP} and dst host {SRC_IP}",
    lfilter=is_reply,
    store=True,
)


sniffer.start()

# Give the sniffer a moment to initialize.
import time
time.sleep(0.1)


# ------------------------------------------------------------
# Send exactly one packet.
# ------------------------------------------------------------

print("Sending exactly one packet...")

sendp(
    pkt,
    iface=IFACE,
    count=1,
    verbose=True,
)


# ------------------------------------------------------------
# Wait for capture to finish.
# ------------------------------------------------------------

time.sleep(TIMEOUT)

replies = sniffer.stop()


# ------------------------------------------------------------
# Report result.
# ------------------------------------------------------------

if not replies:
    print(f"\nNO REPLY received within {TIMEOUT} seconds.")
    raise SystemExit(1)


print(f"\nReceived {len(replies)} matching packet(s).")

for i, reply in enumerate(replies, 1):
    print()
    print("=" * 70)
    print(f"REPLY #{i}")
    print("=" * 70)

    print("\nSummary:")
    print(reply.summary())

    print("\nDecoded packet:")
    reply.show()

    print("\nHexdump:")
    hexdump(reply)
