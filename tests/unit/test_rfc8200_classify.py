"""RFC 8200 classifier tests. Fixtures replay the 2026-09-23 lab run (fd::1 DUT)."""


def mod():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "RFC8200", "/root/unit-RFCv6/RFC-8200-conformance.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = mod()


def test_bpf_covers_both_directions():
    b = M.bpf_for("2001:db8::2", "2001:db8::1")
    assert "2001:db8::2" in b and "2001:db8::1" in b and b.startswith("ip6")


def test_positive_reply_is_pass():
    v, k, d, dev = M.classify("IP-01", ["Ether / IPv6 / ICMPv6 Echo Reply"], [],
                              True, "auto", "", False)
    assert (v, k) == ("PASS", "DIRECTLY_OBSERVED") and dev == ""


def test_positive_error_is_fail_lab_replay():
    # IP-01-002 lab: Param Problem Code 2 ptr 50 on valid DestOpt(PadN)
    v, k, d, dev = M.classify("IP-01", [], [(4, 2, 50, "ICMP6, parameter problem")],
                              True, "auto", "IP-01-001", False)
    assert v == "FAIL" and "Type 4 Code 2 ptr 50" in dev
    # IP-05 lab: Code 0 ptr 66 on valid RH0 packet
    v, k, d, dev = M.classify("IP-05", [], [(4, 0, 66, "ICMP6, parameter problem")],
                              True, "auto", "IP-01-001", False)
    assert v == "FAIL" and "instead of processing" in dev


def test_positive_silence_gating():
    # auto + tx + liveness -> FAIL
    v, _, _, _ = M.classify("IP-01", [], [], True, "auto", "IP-01-001", False)
    assert v == "FAIL"
    # auto without liveness -> INCONCLUSIVE (no false FAIL on first test)
    v, _, _, _ = M.classify("IP-01", [], [], True, "auto", "", False)
    assert v == "INCONCLUSIVE"
    # strict stays conservative even with proof available
    v, _, _, _ = M.classify("IP-01", [], [], True, "strict", "IP-01-001", False)
    assert v == "INCONCLUSIVE"
    # direct needs only tx
    v, _, _, _ = M.classify("IP-05", [], [], True, "direct", "", False)
    assert v == "FAIL"


def test_ip02_logic():
    v, _, _, _ = M.classify("IP-02", [], [(4, 2, 44, "param problem")],
                            True, "auto", "IP-01-001", False)
    assert v == "PASS"
    v, _, _, dev = M.classify("IP-02", [], [(4, 0, 40, "param problem")],
                              True, "auto", "IP-01-001", False)
    assert v == "FAIL" and "required Parameter Problem Code 2" in dev
    v, _, _, _ = M.classify("IP-04", [], [], True, "auto", "IP-01-001", False)
    assert v == "FAIL"
    v, _, _, _ = M.classify("IP-04", [], [], False, "auto", "IP-01-001", False)
    assert v == "INCONCLUSIVE"


def test_ip03_logic():
    v, _, _, _ = M.classify("IP-03", [], [(4, 2, 1, "x")], True, "auto", "", False)
    assert v == "FAIL"
    v, k, _, _ = M.classify("IP-03", [], [], True, "auto", "", True)
    assert (v, k) == ("PASS", "INFERRED")
    v, _, _, _ = M.classify("IP-03", [], [], True, "auto", "IP-01-001", False)
    assert v == "PASS"
    v, _, _, _ = M.classify("IP-03", [], [], False, "strict", "", False)
    assert v == "INCONCLUSIVE"
