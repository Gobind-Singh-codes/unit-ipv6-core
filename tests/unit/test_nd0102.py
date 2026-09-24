"""ND-01 variants + ND-02 route-state tests. Pure (no network, no subprocess)."""


def mod():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "RFC4861", "/root/unit-RFCv6/RFC-4861-conformance.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = mod()

IP_OUT = """2: host0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet6 fe80::7446:4ff:fe34:5702/64 scope link
       valid_lft forever preferred_lft forever
    inet6 fd:33:33:33:7446:4ff:fe34:5702/64 scope global
"""


def test_bpf_both():
    b = M.bpf_both("2001:db8::2", "2001:db8::1")
    assert "2001:db8::2" in b and "2001:db8::1" in b and b.startswith("ip6")


def test_parse_own_ll():
    assert M.parse_own_ll(IP_OUT) == "fe80::7446:4ff:fe34:5702"
    import pytest
    with pytest.raises(ValueError):
        M.parse_own_ll("2: host0: <UP> mtu 1500\n    inet addr:1.2.3.4\n")
    # tentative addresses are skipped
    tent = IP_OUT.replace("scope link\n", "scope link tentative\n", 1)
    import pytest as _p
    with _p.raises(ValueError):
        M.parse_own_ll(tent + "    inet6 2001:db8::9/64 scope global\n")


def test_routes_changed_table():
    pre = "2001:db8:100::/64 dev eth0 proto ra metric 1024\n"
    same, marker = M.routes_changed(pre, pre, "2001:db8:dead")
    assert (same, marker) == (False, False)
    post = pre + "2001:db8:dead::/48 dev eth0 proto ra metric 1024\n"
    changed, hit = M.routes_changed(pre, post, "2001:db8:dead")
    assert (changed, hit) == (True, True)
    churn = pre + "fe80::/64 dev eth0 proto kernel metric 256\n"
    changed, hit = M.routes_changed(pre, churn, "2001:db8:dead")
    assert (changed, hit) == (True, False)


def test_routes_changed_ignores_expires():
    pre = ("2401:4900::/64 dev wan proto ra metric 1024 expires 86281sec pref medium\n"
           "default via fe80::1 dev wan proto ra metric 1024 expires 1681sec pref medium\n")
    post = pre.replace("86281sec", "86275sec").replace("1681sec", "1675sec")
    changed, hit = M.routes_changed(pre, post, "2001:db8:dead")
    assert (changed, hit) == (False, False)


def test_build_nd_ra_prefix():
    from common import packets as P
    from scapy.layers.inet6 import ICMPv6NDOptPrefixInfo
    # NOTE: must use the module constant verbatim -- a bare "2001:db8:dead"
    # without "::" makes Scapy treat it as a hostname and attempt DNS.
    pkt = P.build_nd("RA", "2001:db8::2", "ff02::1", hlim=254,
                     prefix=M.BOGUS_PREFIX, plen=M.BOGUS_PLEN)
    from scapy.layers.inet6 import IPv6
    assert pkt[IPv6].hlim == 254
    assert pkt[ICMPv6NDOptPrefixInfo].prefix == M.BOGUS_PREFIX
    assert pkt[ICMPv6NDOptPrefixInfo].prefixlen == M.BOGUS_PLEN
    assert M.BOGUS_PREFIX == "2001:db8:dead::" and M.BOGUS_PLEN == 48
    assert M.BOGUS_MARKER in M.BOGUS_PREFIX
