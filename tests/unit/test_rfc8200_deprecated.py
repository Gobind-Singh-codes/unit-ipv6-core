
"""RFC 8200 deprecated-header (RH Type 0) interpretation tests."""


def mod():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "RFC8200", "/root/unit-RFCv6/RFC-8200-conformance.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = mod()


def test_deprecated_error_is_pass_with_attempt_wording():
    # IP-01-102 lab replay: Code 0 ptr 74 on H->R (RH Type 0)
    v, k, d, dev, interp = M.classify(
        "IP-01", [], [(4, 0, 74, "ICMP6, parameter problem")],
        True, "auto", "IP-01-001", False, True)
    assert v == "PASS" and dev == ""
    assert "attempted processing" in d and "Type 4 Code 0 ptr 74" in d
    assert "RFC 5095" in interp


def test_deprecated_silence_proven_is_pass():
    v, k, d, dev, interp = M.classify(
        "IP-05", [], [], True, "auto", "IP-01-001", False, True)
    assert v == "PASS" and "5095" in interp


def test_deprecated_echo_is_pass_with_tension_note():
    v, k, d, dev, interp = M.classify(
        "IP-01", ["Ether / IPv6 / ICMPv6 Echo Reply"], [], True, "auto", "", False, True)
    assert v == "PASS" and "tension" in interp


def test_deprecated_silence_unproven_stays_inconclusive():
    v, _, _, _, interp = M.classify(
        "IP-01", [], [], False, "auto", "", False, True)
    assert v == "INCONCLUSIVE" and interp == ""


def test_routing_builder_type_locked_to_zero():
    from common import packets as P
    from scapy.layers.inet6 import IPv6ExtHdrRouting
    pkt = P.build_echo("2001:db8::2", "2001:db8::1", 1, 1, ["R"])
    assert pkt[IPv6ExtHdrRouting].type == 0
    assert P.ROUTING_HDR_TYPE == 0 and "R" in P.DEPRECATED_SYMBOLS
