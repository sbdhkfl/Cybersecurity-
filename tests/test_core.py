import argparse

import pytest

from sentinelkit.cli import estimate_password, parse_ports


def test_parse_ports_accepts_unique_valid_ports():
    assert parse_ports("22,80,443,80") == [22, 80, 443]


@pytest.mark.parametrize("value", ["0", "65536", "abc", ",".join(str(port) for port in range(1, 130))])
def test_parse_ports_rejects_invalid_values(value):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ports(value)


def test_password_heuristic_flags_short_password():
    rating, suggestions = estimate_password("abc")
    assert rating == "Needs improvement"
    assert any("12 characters" in item for item in suggestions)


def test_password_heuristic_accepts_long_varied_password():
    rating, suggestions = estimate_password("A-long-example!9284")
    assert rating == "Good heuristic result"
    assert suggestions == []
