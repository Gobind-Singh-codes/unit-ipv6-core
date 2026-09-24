"""Deterministic Scapy builders + IP-01 matrix (no network I/O here)."""
from __future__ import annotations

import hashlib
import itertools

SYMBOLS = ("H", "D", "R", "F", "A", "E")
SECURITY_SYMBOLS = frozenset({"A", "E"})

#: Routing header type emitted by the R builder. Type 0 is deprecated per
#: RFC 8200 section 4.4 / RFC 5095: such packets are must-drop.
ROUTING_HDR_TYPE = 0
#: Chain symbols whose stimuli are must-drop (type-locked to the builder above:
#: if R ever stops emitting Type 0, this empties and must-process applies again).
DEPRECATED_SYMBOLS = frozenset({"R"}) if ROUTING_HDR_TYPE == 0 else frozenset()

DEPRECATION_NOTE = ("Routing Header Type 0 is deprecated per RFC 8200 section 4.4 / "
                    "RFC 5095; drop or rejection with reason is the required outcome.")

# Option types known to common stacks; test otypes must avoid these.
KNOWN_OPTION_TYPES = frozenset({0x00, 0x01, 0x05, 0x0B, 0x1E})
# ER Table-3 unknown-option action-bit vectors (otype top 2 bits = action).
UNKNOWN_OTYPES = {"11": 0xC1, "01": 0x41, "10": 0x81}


def derive_ids(seed: int, test_id: str) -> tuple[int, int]:
    h = hashlib.sha256(f"{seed}/{test_id}".encode()).digest()
    return (int.from_bytes(h[:2], "big"), int.from_bytes(h[2:4], "big"))


def is_unknown_otype(otype: int) -> bool:
    return otype not in KNOWN_OPTION_TYPES


def action_bits(otype: int) -> str:
    return format((otype >> 6) & 0x3, "02b")


def _ext_layer(sym: str, dst: str, frag_id: int = 0xBEEF):
    from scapy.layers.inet6 import (
        IPv6ExtHdrDestOpt, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop,
        IPv6ExtHdrRouting, PadN,
    )
    if sym == "H":
        return IPv6ExtHdrHopByHop(options=[PadN(optdata=b"\x00" * 4)])
    if sym == "D":
        return IPv6ExtHdrDestOpt(options=[PadN(optdata=b"\x00" * 4)])
    if sym == "R":
        assert ROUTING_HDR_TYPE == 0, "R builder drifted off Type 0; re-check DEPRECATED_SYMBOLS"
        return IPv6ExtHdrRouting(type=ROUTING_HDR_TYPE, segleft=0, addresses=[dst])
    if sym == "F":
        return IPv6ExtHdrFragment(offset=0, m=0, id=frag_id)
    if sym == "A":
        from scapy.layers.ipsec import AH
        return AH(spi=1, seq=0)
    if sym == "E":
        from scapy.layers.ipsec import ESP
        return ESP(spi=1, seq=0)
    raise ValueError(f"unknown chain symbol: {sym}")


def build_echo(src: str, dst: str, icmp_id: int, icmp_seq: int,
               chain: tuple[str, ...] | list[str] = (), hlim: int = 64,
               pad_len: int = 0):
    from scapy.layers.inet6 import IPv6
    from scapy.layers.inet6 import ICMPv6EchoRequest
    for s in chain:
        if s not in SYMBOLS:
            raise ValueError(f"bad symbol {s}")
    pkt = IPv6(src=src, dst=dst, hlim=hlim)
    for s in chain:
        pkt = pkt / _ext_layer(s, dst)
    return pkt / ICMPv6EchoRequest(id=icmp_id, seq=icmp_seq, data=b"RFC8200" + b"X" * pad_len)


def build_unknown_option(src: str, dst: str, otype: int,
                         icmp_id: int = 1, icmp_seq: int = 1, hlim: int = 64):
    from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt, HBHOptUnknown
    from scapy.layers.inet6 import ICMPv6EchoRequest
    if not is_unknown_otype(otype):
        raise ValueError(f"otype 0x{otype:02X} is not unknown")
    return (IPv6(src=src, dst=dst, hlim=hlim)
            / IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=otype, optdata=b"\xAA\xBB")])
            / ICMPv6EchoRequest(id=icmp_id, seq=icmp_seq, data=b"OPT"))


def header_chain(pkt) -> str:
    names, layer = [], pkt
    while layer is not None:
        try:
            names.append(layer.__class__.__name__)
            layer = layer.payload if layer.payload else None
            if names[-1] in ("ICMPv6EchoRequest", "ICMPv6EchoReply", "Raw", "NoPayload"):
                break
        except Exception:
            break
    return " -> ".join(names)


# ---- IP-01 matrix ----
def matrix_single() -> list[tuple[str, tuple[str, ...]]]:
    syms = ["H", "D", "R", "F", "A", "E"]
    return [(f"IP-01-00{i+1}", (s,)) for i, s in enumerate(syms)]


def matrix_pairs() -> list[tuple[str, tuple[str, ...]]]:
    out, n = [], 101
    for a, b in itertools.permutations(SYMBOLS, 2):
        out.append((f"IP-01-{n}", (a, b)))
        n += 1
    return out  # 30


def matrix_repeats() -> list[tuple[str, tuple[str, ...]]]:
    out, n = [], 201
    for s in SYMBOLS:
        for count in (2, 3):
            out.append((f"IP-01-{n}", (s,) * count))
            n += 1
    return out  # 12


_MIXED = [
    ("H", "H", "D"), ("H", "D", "D"), ("D", "H", "H"), ("D", "D", "H"),
    ("H", "R", "R"), ("R", "H", "H"), ("D", "R", "R"), ("R", "D", "D"),
    ("H", "F", "F"), ("F", "H", "H"), ("D", "F", "F"), ("F", "D", "D"),
]


def matrix_mixed() -> list[tuple[str, tuple[str, ...]]]:
    return [(f"IP-01-{301 + i}", tuple(c)) for i, c in enumerate(_MIXED)]


def matrix_triples() -> list[tuple[str, tuple[str, ...]]]:
    return [(f"IP-01-{400 + i}", tuple(p))
            for i, p in enumerate(itertools.permutations(SYMBOLS, 3))]  # 120


def matrix_long(max_len: int = 6):
    """Yield (sub_id, chain) for lengths 4..max_len. Full counts: 4->360, 5->720, 6->720."""
    start = 600
    for length in range(4, max(4, max_len) + 1):
        for p in itertools.permutations(SYMBOLS, length):
            yield (f"IP-01-L{length}-{start}", tuple(p))
            start += 1


CORE_TRIPLE_SAMPLE = [
    ("H", "D", "R"), ("H", "D", "F"), ("D", "R", "F"), ("R", "F", "D"),
    ("H", "R", "D"), ("D", "H", "R"), ("R", "D", "H"), ("F", "D", "R"),
]


def core_matrix() -> list[tuple[str, tuple[str, ...]]]:
    """Bounded default: all non-security singles/pairs/repeats/mixed + 8 triple samples."""
    cases = [c for c in matrix_single() if not (set(c[1]) & SECURITY_SYMBOLS)]
    cases += [c for c in matrix_pairs() if not (set(c[1]) & SECURITY_SYMBOLS)]
    cases += [c for c in matrix_repeats() if not (set(c[1]) & SECURITY_SYMBOLS)]
    cases += matrix_mixed()
    for i, ch in enumerate(CORE_TRIPLE_SAMPLE):
        cases.append((f"IP-01-4{i:02d}", tuple(ch)))
    return cases


# ---- Phases 2-5 shared builders (still no I/O) ----

def is_multicast(addr: str) -> bool:
    import ipaddress
    return ipaddress.IPv6Address(addr).is_multicast


def is_unspecified(addr: str) -> bool:
    import ipaddress
    return int(ipaddress.IPv6Address(addr)) == 0


def eth_dst_for_ipv6(addr: str) -> str | None:
    """Ethernet dst for an IPv6 dst: multicast maps to 33:33:.., else None (needs NDISC)."""
    import ipaddress
    a = ipaddress.IPv6Address(addr)
    if a.is_multicast:
        tail = a.packed[-4:]
        return "33:33:" + ":".join(f"{b:02x}" for b in tail)
    return None


def valid_nd_hlim(hlim: int) -> bool:
    return hlim == 255


def build_nd(kind: str, src: str, dst: str, tgt: str = "",
             hlim: int = 255, lladdr: str | None = None,
             prefix: str | None = None, plen: int = 48):
    """RS | RA | NS | NA with explicit Hop Limit. Pure builder.

    prefix/plen (RA only): attach a Prefix Information option, e.g. a
    documentation prefix that must never appear in real DUT state.
    """
    from scapy.layers.inet6 import (
        IPv6, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, ICMPv6ND_RS,
        ICMPv6NDOptDstLLAddr, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr,
    )
    k = kind.upper()
    if k == "RS":
        nd = ICMPv6ND_RS()
        if lladdr:
            nd = nd / ICMPv6NDOptSrcLLAddr(lladdr=lladdr)
    elif k == "RA":
        nd = ICMPv6ND_RA(routerlifetime=1800)
        if lladdr:
            nd = nd / ICMPv6NDOptSrcLLAddr(lladdr=lladdr)
        if prefix:
            nd = nd / ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=plen,
                                            L=1, A=1, validlifetime=300,
                                            preferredlifetime=150)
    elif k == "NS":
        if not tgt:
            raise ValueError("NS requires tgt")
        nd = ICMPv6ND_NS(tgt=tgt or dst)
        if lladdr:
            nd = nd / ICMPv6NDOptSrcLLAddr(lladdr=lladdr)
    elif k == "NA":
        if not tgt:
            raise ValueError("NA requires tgt")
        nd = ICMPv6ND_NA(tgt=tgt or dst, R=0, S=1, O=1)
        if lladdr:
            nd = nd / ICMPv6NDOptDstLLAddr(lladdr=lladdr)
    else:
        raise ValueError(f"bad ND kind: {kind}")
    return IPv6(src=src, dst=dst, hlim=hlim) / nd


def build_ns_reserved(src: str, dst: str, tgt: str, res: int = 0x00FFFFFF,
                      hlim: int = 255):
    from scapy.layers.inet6 import IPv6, ICMPv6ND_NS
    return IPv6(src=src, dst=dst, hlim=hlim) / ICMPv6ND_NS(res=res, tgt=tgt)


def build_ns_unknown_opt(src: str, dst: str, tgt: str, opttype: int = 30,
                         hlim: int = 255):
    from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6NDOptUnknown
    return (IPv6(src=src, dst=dst, hlim=hlim) / ICMPv6ND_NS(tgt=tgt)
            / ICMPv6NDOptUnknown(type=opttype, data=b"XXXX"))


def build_unknown_informational(src: str, dst: str, itype: int = 200,
                                hlim: int = 64):
    """ICMPv6 informational message with unknown Type (raw, nh=58)."""
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw
    if not 0 <= itype <= 255:
        raise ValueError("itype must fit in a byte")
    return IPv6(src=src, dst=dst, hlim=hlim, nh=58) / Raw(load=bytes([itype, 0, 0, 0]) + b"RFC4443")


def build_ptb(src: str, dst: str, mtu: int, quoted) -> object:
    """ICMPv6 Packet Too Big quoting an invoking packet. Pure builder."""
    from scapy.layers.inet6 import IPv6, ICMPv6PacketTooBig
    if not 0 <= mtu <= 0xFFFFFFFF:
        raise ValueError("bad MTU")
    return IPv6(src=src, dst=dst, hlim=64) / ICMPv6PacketTooBig(mtu=mtu) / quoted


def pmtu_floor_ok(mtu: int) -> bool:
    return mtu >= 1280


def solicited_node(addr: str) -> str:
    """Solicited-node multicast address for a unicast/anycast target (pure)."""
    import ipaddress
    packed = ipaddress.IPv6Address(addr).packed
    tail = packed[-3:]
    raw = "ff02::1:ff%02x:%02x%02x" % (tail[0], tail[1], tail[2])
    return ipaddress.IPv6Address(raw).compressed


def build_udp_trigger(src: str, dst: str, sport: int, dport: int = 59999,
                      hlim: int = 64):
    """UDP to (likely) closed port: elicits ICMPv6 Port Unreachable on unicast.

    Used as the error-trigger control for suppression tests. Pure builder.
    """
    from scapy.layers.inet import UDP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw
    return (IPv6(src=src, dst=dst, hlim=hlim)
            / UDP(sport=sport, dport=dport) / Raw(load=b"TRIGGER"))


def frag_info(pkt):
    """Return (offset_bytes, m_flag, frag_payload_len) for a fragmented pkt, else None."""
    from scapy.layers.inet6 import IPv6ExtHdrFragment
    if not pkt.haslayer(IPv6ExtHdrFragment):
        return None
    fh = pkt[IPv6ExtHdrFragment]
    inner = fh.payload
    try:
        plen = len(bytes(inner)) if inner and inner.__class__.__name__ != "NoPayload" else 0
    except Exception:
        plen = 0
    return (fh.offset * 8, int(fh.m), plen)


def first_frag_payloads(packets) -> list[int]:
    """Payload lens of first fragments (offset 0, M=1) — implies sender path MTU."""
    out = []
    for p in packets:
        fi = frag_info(p)
        if fi and fi[0] == 0 and fi[1] == 1:
            out.append(fi[2])
    return out


def implied_wire_mtu(first_frag_payload: int) -> int:
    """Wire MTU implied by a first-fragment payload: IPv6 hdr (40) + frag hdr (8)."""
    return first_frag_payload + 48


#: First-fragment payload proving the sender stayed at/above the 1280 floor.
MIN_FLOOR_FIRST_FRAG = 1280 - 48  # 1232
