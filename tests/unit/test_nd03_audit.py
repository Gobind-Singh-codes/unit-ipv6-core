"""ND-03 pre-flight audit tests. Pure (no network, no subprocess)."""


def mod():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "RFC4861", "/root/unit-RFCv6/RFC-4861-conformance.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = mod()

CLEAN = """net.ipv6.conf.wan_300.forwarding = 0
net.ipv6.conf.wan_300.accept_ra = 1
net.ipv6.conf.wan_300.send_ra = 0
"""

FW = """net.ipv6.conf.end1_33.forwarding = 1
net.ipv6.conf.end1_33.accept_ra = 1
"""

NORADVD = "root 123 1 0 ... [r]advd\n---\n"
RADVD_HIT = "root 123 1 0 ... /usr/sbin/radvd\n---\n/etc/radvd.conf:end1_33: yes\n"


def test_clean_iface_no_contradiction():
    a = M.audit_ra_config(CLEAN, NORADVD, "wan_300")
    assert a["contradiction"] is False and a["reasons"] == []
    assert a["values"]["forwarding"] == "0"


def test_forwarding_alone_is_not_contradiction():
    # A router forwards on all interfaces; that says nothing about advertising.
    a = M.audit_ra_config(FW, NORADVD, "end1_33")
    assert a["contradiction"] is False and a["reasons"] == []
    assert a["values"]["forwarding"] == "1"


def test_send_ra_present_and_on():
    out = ("net.ipv6.conf.x.forwarding = 0\n"
           "net.ipv6.conf.x.accept_ra = 0\n"
           "net.ipv6.conf.x.send_ra = 1\n")
    a = M.audit_ra_config(out, NORADVD, "x")
    assert a["contradiction"] is True
    assert any("send_ra=1" in r for r in a["reasons"])


def test_send_ra_absent_is_neutral():
    out = "net.ipv6.conf.x.forwarding = 0\nnet.ipv6.conf.x.accept_ra = 0\n"
    a = M.audit_ra_config(out, NORADVD, "x")
    assert a["values"]["send_ra"] == "absent"
    assert a["contradiction"] is False


def test_accept_ra_never_contradiction():
    # accept_ra governs receiving (WAN side); must not condemn a sender claim.
    out = ("net.ipv6.conf.x.forwarding = 0\n"
           "net.ipv6.conf.x.accept_ra = 2\n")
    a = M.audit_ra_config(out, NORADVD, "x")
    assert a["contradiction"] is False


def test_radvd_config_hit_is_contradiction():
    a = M.audit_ra_config(CLEAN.replace("wan_300", "end1_33"), RADVD_HIT, "end1_33")
    assert a["contradiction"] is True
    assert any("radvd" in r for r in a["reasons"])


def test_radvd_self_match_ignored():
    # Lab replay: the only line naming the iface is our own invoking shell.
    out = ("root 3695 1 0 ... /usr/sbin/radvd --logmethod stderr_clean\n"
           "root 145136 145134 0 ... bash -c ps -ef | grep '[r]advd'; echo ---; "
           "grep -H 'end1_45' /etc/radvd.conf 2>/dev/null\n---\n")
    a = M.audit_ra_config(CLEAN.replace("wan_300", "end1_45"), out, "end1_45")
    assert a["radvd_manages"] is False
    assert a["contradiction"] is False


def test_parse_addrs_and_attribute():
    sample = """13: wan_300: <BROADCAST,MULTICAST,UP> mtu 1500
    inet6 fd:33:33:33::1/64 scope global
    inet6 fe80::d038:b2ff:fe49:b10e/64 scope link
17: end1_33: <BROADCAST,MULTICAST,UP> mtu 1500
    inet6 fe80::1/64 scope link
"""
    table = M.parse_dut_addrs(sample)
    assert table["fe80::d038:b2ff:fe49:b10e"] == "wan_300"
    assert M.attribute_ra("fe80::d038:b2ff:fe49:b10e", table) == "wan_300"
    assert M.attribute_ra("FE80::D038:B2FF:FE49:B10E", table) == "wan_300"
    assert M.attribute_ra("fe80::9", table) is None


def test_refusal_text():
    a = M.audit_ra_config(FW, NORADVD, "end1_33")
    t = M.refusal_text(a)
    assert "Are you sure you want to continue?" in t
    assert "end1_33" in t and "--force" in t
    assert "RECEIVING" in t  # accept_ra meaning spelled out


def test_nd03_dry_run_shows_audit(capsys):
    assert M.main(["--interface", "lo", "--source", "2001:db8::2",
                   "--target", "2001:db8::1", "--dry-run", "--tests", "ND-03",
                   "--non-adv-iface", "wan_300", "--whitebox",
                   "--whitebox-tunnel", "ssh dut"]) == 0
    out = capsys.readouterr().out
    assert "wan_300" in out and "sysctl" in out and "SKIPPED" in out
