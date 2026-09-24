"""Phase 2-5 base-build unit tests. Zero network I/O (builders + dry-runs only)."""
from common import packets as P


def test_multicast_helpers():
    assert P.is_multicast("ff02::1")
    assert not P.is_multicast("2001:db8::1")
    assert P.is_unspecified("::")
    assert P.eth_dst_for_ipv6("ff02::1") == "33:33:00:00:00:01"
    assert P.eth_dst_for_ipv6("2001:db8::1") is None
    assert P.valid_nd_hlim(255) and not P.valid_nd_hlim(254)


def test_nd_builders_hlim():
    for kind, kw in (("RS", {}), ("RA", {}), ("NS", {"tgt": "2001:db8::1"}),
                     ("NA", {"tgt": "2001:db8::1"})):
        for hlim in (255, 254):
            pkt = P.build_nd(kind, "2001:db8::2", "ff02::1" if kind in ("RS", "RA") else "2001:db8::1",
                             hlim=hlim, **kw)
            from scapy.layers.inet6 import IPv6
            assert pkt[IPv6].hlim == hlim


def test_slaac04_builders():
    r = P.build_ns_reserved("2001:db8::2", "2001:db8::1", "2001:db8::1")
    from scapy.layers.inet6 import ICMPv6ND_NS
    assert r[ICMPv6ND_NS].res != 0
    u = P.build_ns_unknown_opt("2001:db8::2", "2001:db8::1", "2001:db8::1", 30)
    raw = bytes(u)
    assert bytes([30]) in raw


def test_unknown_informational():
    pkt = P.build_unknown_informational("2001:db8::2", "2001:db8::1", 200)
    from scapy.layers.inet6 import IPv6
    assert pkt[IPv6].nh == 58
    assert bytes(pkt[IPv6].payload)[:1] == bytes([200])


def test_ptb_builder_and_floor():
    q = P.build_echo("2001:db8::2", "2001:db8::1", 1, 1)
    ptb = P.build_ptb("2001:db8::99", "2001:db8::2", 1000, q)
    from scapy.layers.inet6 import ICMPv6PacketTooBig
    assert ptb[ICMPv6PacketTooBig].mtu == 1000
    assert not P.pmtu_floor_ok(1000) and P.pmtu_floor_ok(1280)


def test_udp_trigger_builder():
    pkt = P.build_udp_trigger("2001:db8::2", "2001:db8::1", 12345)
    from scapy.layers.inet import UDP
    from scapy.layers.inet6 import IPv6
    assert pkt[IPv6].dst == "2001:db8::1"
    assert pkt[UDP].dport == 59999 and pkt[UDP].sport == 12345


def test_echo_pad_len():
    small = P.build_echo("2001:db8::2", "2001:db8::1", 1, 1)
    big = P.build_echo("2001:db8::2", "2001:db8::1", 1, 1, pad_len=1993)
    assert len(bytes(big)) - len(bytes(small)) == 1993


def test_frag_info_helpers():
    from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
    from scapy.packet import Raw
    first = IPv6(src="::1", dst="::2") / IPv6ExtHdrFragment(offset=0, m=1, id=7) / Raw(load=b"Y" * 1448)
    assert P.frag_info(first) == (0, 1, 1448)
    last = IPv6(src="::1", dst="::2") / IPv6ExtHdrFragment(offset=181, m=0, id=7) / Raw(load=b"Z" * 100)
    assert P.frag_info(last) == (181 * 8, 0, 100)
    plain = P.build_echo("2001:db8::2", "2001:db8::1", 1, 1)
    assert P.frag_info(plain) is None
    assert P.first_frag_payloads([first, last, plain]) == [1448]
    assert P.implied_wire_mtu(1448) == 1496
    assert P.MIN_FLOOR_FIRST_FRAG == 1232


def _load(name):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, f"/root/unit-RFCv6/{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_fragment_for_wire():
    m01 = _load("RFC-8201-conformance")
    from common import packets as P
    small = P.build_echo("2001:db8::2", "2001:db8::1", 1, 1)
    assert m01.fragment_for_wire(small, 1500) == [small]
    big = P.build_echo("2001:db8::2", "2001:db8::1", 1, 1, pad_len=1993)
    frags = m01.fragment_for_wire(big, 1500)
    assert len(frags) == 2
    assert all(len(bytes(f)) <= 1500 for f in frags)
    from scapy.layers.inet6 import defragment6
    assert bytes(defragment6(frags)[0]) == bytes(big)
    assert m01._iface_mtu("lo") >= 1280


def test_list_tests_and_help(capsys):
    import pytest
    catalogs = {
        "RFC-8200-conformance": ["IP-01", "IP-02", "IP-03", "IP-04", "IP-05"],
        "RFC-4443-conformance": ["ICMP-01", "ICMP-02a", "ICMP-03", "ICMP-04", "ICMP-05a"],
        "RFC-4861-conformance": ["ND-01", "ND-02", "ND-03", "ND-04", "ND-05"],
        "RFC-4862-conformance": ["SLAAC-01", "SLAAC-02", "SLAAC-03", "SLAAC-04a", "SLAAC-05"],
        "RFC-8201-conformance": ["PMTU-01"],
    }
    for prog, ids in catalogs.items():
        m = _load(prog)
        assert m.main(["--list-tests"]) == 0
        out = capsys.readouterr().out
        for tid in ids:
            assert tid in out, f"{prog} catalog missing {tid}"
        with pytest.raises(SystemExit) as e:
            m.main(["--help"])
        assert e.value.code == 0


def test_solicited_node_and_dad_matcher():
    from common import packets as P

    def mod():
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "RFC4862", "/root/unit-RFCv6/RFC-4862-conformance.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    assert P.solicited_node("fd:33:33:33::1") == "ff02::1:ff00:1"
    assert P.solicited_node("2001:db8::abcd") == "ff02::1:ff00:abcd"
    m = mod()
    anycast, own = "fd:33:33:33::", "fd:33:33:33::9"
    ours = P.build_nd("NS", "::", P.solicited_node(anycast), tgt=anycast, hlim=255)
    dut = P.build_nd("NS", "fe80::1", P.solicited_node(anycast), tgt=anycast, hlim=255)
    other = P.build_nd("NS", "fe80::1", P.solicited_node("fd:33:33:33::9"),
                       tgt="fd:33:33:33::9", hlim=255)
    assert m.dut_dad_probes([ours], anycast, ("::", own)) == []
    found = m.dut_dad_probes([ours, dut, other], anycast, ("::", own))
    assert found == [dut]


def test_dad_log_shows():
    def mod():
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "RFC4862", "/root/unit-RFCv6/RFC-4862-conformance.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    m = mod()
    log = "rcvd NS for tentative 2001:db8::99 during DAD delay\nnoise line\n"
    found, line = m.dad_log_shows(log, "2001:db8::99", "ff02::1:ff00:99")
    assert found and "2001:db8::99" in line
    found, _ = m.dad_log_shows(log, "2001:db8::100", "ff02::1:ff00:100")
    assert not found
    found, _ = m.dad_log_shows("", "2001:db8::99", "ff02::1:ff00:99")
    assert not found


def test_hlim_param():
    from common import packets as P
    from scapy.layers.inet6 import IPv6
    assert P.build_echo("2001:db8::2", "2001:db8::1", 1, 1, hlim=1)[IPv6].hlim == 1
    assert P.build_echo("2001:db8::2", "2001:db8::1", 1, 1)[IPv6].hlim == 64


def test_dry_runs_never_transmit(capsys):
    m3 = _load("RFC-4443-conformance")
    m61 = _load("RFC-4861-conformance")
    m62 = _load("RFC-4862-conformance")
    m01 = _load("RFC-8201-conformance")
    assert m3.main(["--interface", "lo", "--source", "2001:db8::2", "--target", "2001:db8::1",
                    "--dry-run"]) == 0
    assert m61.main(["--interface", "lo", "--source", "2001:db8::2", "--target", "2001:db8::1",
                     "--dry-run"]) == 0
    assert m62.main(["--interface", "lo", "--source", "2001:db8::2", "--target", "2001:db8::1",
                     "--dry-run"]) == 0
    assert m01.main(["--interface", "lo", "--source", "2001:db8::2", "--target", "2001:db8::1",
                     "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "SKIPPED" in out
