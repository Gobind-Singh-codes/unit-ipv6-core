"""White-box transport + PMTU decision tests. run_check uses echo/sleep only."""
from types import SimpleNamespace

from common import whitebox as WB


def args(**kw):
    base = dict(whitebox=False, whitebox_tunnel="", whitebox_timeout=10.0,
                pmtu_remote_cmd="")
    base.update(kw)
    return SimpleNamespace(**base)


def test_run_check_echo():
    r = WB.run_check("echo", "pmtu=1500", 5.0)
    assert r["rc"] == 0 and "pmtu=1500" in r["stdout"] and not r["timed_out"]
    assert WB.parse_first_int(r["stdout"]) == 1500


def test_run_check_timeout():
    r = WB.run_check("sleep", "5", 0.1)
    assert r["timed_out"] and r["rc"] == -1


def test_validate_loud_errors():
    e = WB.validate(args(whitebox=True))
    assert e and "--whitebox-tunnel" in e and "Example:" in e
    e = WB.validate(args(whitebox=True, whitebox_tunnel="ssh dut"))
    assert e and "--pmtu-remote-cmd" in e and "Example:" in e
    e = WB.validate(args(whitebox=True, whitebox_tunnel="ssh dut"),
                    remote_required=False)
    assert e is None
    e = WB.validate(args(pmtu_remote_cmd="ip route"))
    assert e and "--whitebox" in e
    e = WB.validate(args(whitebox_tunnel="ssh dut"))
    assert e and "--whitebox" in e
    assert WB.validate(args()) is None
    assert WB.validate(args(whitebox=True, whitebox_tunnel="ssh dut",
                            pmtu_remote_cmd="show")) is None


def test_default_remote_cmd():
    cmd = WB.default_pmtu_remote_cmd("fd:33:33:33::9")
    assert "fd:33:33:33::9" in cmd and "cache" in cmd and "python3" in cmd


def test_parse_first_int():
    assert WB.parse_first_int("pmtu=1280") == 1280
    assert WB.parse_first_int("no numbers") is None
    assert WB.parse_first_int("") is None


def test_decide_pmtu_table():
    assert WB.decide_pmtu(None, 1280)[0] == "ERROR"
    assert WB.decide_pmtu(1500, None)[0] == "ERROR"
    v, d, _ = WB.decide_pmtu(1500, 1000)
    assert v == "FAIL" and "1000" in d
    v, d, _ = WB.decide_pmtu(1500, 1500)
    assert v == "PASS" and "unchanged" in d
    v, _, dev = WB.decide_pmtu(1500, 1400)
    assert v == "PASS" and "1400" in dev or "1500" in dev


def test_require_cache_fails_closed():
    assert WB.cache_hit({"stdout": "1500 cache dev eth0"}) is True
    assert WB.cache_hit({"stdout": "1500\n"}) is False
    v, _, dev = WB.decide_pmtu(1500, 1500, False, False, True)
    assert v == "ERROR" and "cache" in dev
    v, _, _ = WB.decide_pmtu(1500, 1500, True, True, True)
    assert v == "PASS"
    # without the flag, fallbacks still pass as before
    v, _, _ = WB.decide_pmtu(1500, 1500, False, False, False)
    assert v == "PASS"
