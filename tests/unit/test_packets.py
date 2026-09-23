from common.packets import (
    CORE_TRIPLE_SAMPLE, action_bits, build_echo, build_unknown_option,
    core_matrix, derive_ids, header_chain, is_unknown_otype,
    matrix_long, matrix_mixed, matrix_pairs, matrix_repeats,
    matrix_single, matrix_triples,
)


def test_derive_ids_deterministic():
    assert derive_ids(0, "IP-01") == derive_ids(0, "IP-01")
    assert derive_ids(0, "IP-01") != derive_ids(1, "IP-01")
    i, s = derive_ids(0, "IP-01")
    assert 0 <= i <= 65535 and 0 <= s <= 65535


def test_unknown_otypes_action_bits():
    assert action_bits(0xC1) == "11"
    assert action_bits(0x41) == "01"
    assert action_bits(0x81) == "10"
    for o in (0xC1, 0x41, 0x81):
        assert is_unknown_otype(o)


def test_build_echo_fields():
    pkt = build_echo("2001:db8::2", "2001:db8::1", 1, 2, ["H", "D"], hlim=64)
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
    assert pkt[IPv6].src == "2001:db8::2"
    assert pkt[IPv6].hlim == 64
    assert pkt[ICMPv6EchoRequest].id == 1
    ch = header_chain(pkt)
    assert "IPv6ExtHdrHopByHop" in ch and "IPv6ExtHdrDestOpt" in ch


def test_build_unknown_option():
    pkt = build_unknown_option("2001:db8::2", "2001:db8::1", 0xC1)
    raw = bytes(pkt)
    assert b"\xaa\xbb" in raw


def test_routing_segleft_zero():
    pkt = build_echo("2001:db8::2", "2001:db8::1", 1, 1, ["R"])
    from scapy.layers.inet6 import IPv6ExtHdrRouting
    assert pkt[IPv6ExtHdrRouting].segleft == 0


def test_matrix_counts():
    assert len(matrix_single()) == 6
    assert len(matrix_pairs()) == 30
    assert len(matrix_repeats()) == 12
    assert len(matrix_mixed()) == 12
    assert len(matrix_triples()) == 120
    # pairs cover both orders
    chains = [c for _, c in matrix_pairs()]
    assert ("H", "D") in chains and ("D", "H") in chains


def test_matrix_long_counts():
    assert len(list(matrix_long(4))) == 360
    # core stays bounded and security-free
    core = core_matrix()
    assert len(core) == 4 + 12 + 8 + 12 + len(CORE_TRIPLE_SAMPLE)
    for _, ch in core:
        assert not (set(ch) & {"A", "E"})
