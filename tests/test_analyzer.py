import pytest

from phishing_analyzer import analyze_url


def test_normal_https_url_is_low_risk():
    result = analyze_url("https://github.com/openai")
    assert result.risk == "LOW"
    assert result.score == 0


def test_ip_login_url_is_high_risk():
    result = analyze_url("http://192.0.2.10/login/verify-account")
    assert result.risk == "HIGH"
    assert {finding.rule for finding in result.findings} >= {
        "no_https", "ip_address", "suspicious_words"
    }


def test_shortened_url_is_medium_risk():
    result = analyze_url("https://bit.ly/example")
    assert result.risk == "MEDIUM"
    assert any(finding.rule == "shortener" for finding in result.findings)


def test_missing_scheme_is_normalized():
    result = analyze_url("example.com")
    assert result.normalized_url == "http://example.com"
    assert result.score == 15


@pytest.mark.parametrize("value", ["", "   ", "https:///missing-host"])
def test_invalid_urls_raise_value_error(value):
    with pytest.raises(ValueError):
        analyze_url(value)
