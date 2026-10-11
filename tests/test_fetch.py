from unittest.mock import patch

import requests
import requests_mock as requests_mock_lib

from header_check.fetch import fetch_url


def test_successful_fetch_returns_headers_and_final_url(requests_mock):
    requests_mock.get(
        "https://example.com/",
        headers={"Strict-Transport-Security": "max-age=1", "X-Content-Type-Options": "nosniff"},
        status_code=200,
    )
    result = fetch_url("https://example.com/", requests.Session())
    assert result.error is None
    assert result.status_code == 200
    assert result.final_url == "https://example.com/"
    assert result.headers["strict-transport-security"] == "max-age=1"
    assert result.headers["x-content-type-options"] == "nosniff"


def test_redirect_chain_resolves_final_url(requests_mock):
    requests_mock.get(
        "http://example.com/",
        status_code=301,
        headers={"Location": "https://example.com/"},
    )
    requests_mock.get("https://example.com/", status_code=200, headers={})
    result = fetch_url("http://example.com/", requests.Session())
    assert result.error is None
    assert result.final_url == "https://example.com/"


def test_connection_error_is_reported(requests_mock):
    requests_mock.get("https://bad.example.com/", exc=requests.exceptions.ConnectionError)
    result = fetch_url("https://bad.example.com/", requests.Session())
    assert result.error_type == "connection"
    assert result.error is not None
    assert result.final_url is None


def test_ssl_error_is_reported(requests_mock):
    requests_mock.get("https://bad-ssl.example.com/", exc=requests.exceptions.SSLError)
    result = fetch_url("https://bad-ssl.example.com/", requests.Session())
    assert result.error_type == "ssl"
    assert result.error is not None


def test_timeout_is_reported(requests_mock):
    requests_mock.get("https://slow.example.com/", exc=requests.exceptions.Timeout)
    result = fetch_url("https://slow.example.com/", requests.Session(), timeout=5.0)
    assert result.error_type == "timeout"
    assert result.error is not None


def test_non_2xx_status_is_not_treated_as_error(requests_mock):
    requests_mock.get("https://example.com/missing", status_code=404, headers={})
    result = fetch_url("https://example.com/missing", requests.Session())
    assert result.error is None
    assert result.status_code == 404


def test_timeout_param_passed_to_session_get():
    session = requests.Session()
    with requests_mock_lib.Mocker(session=session) as m:
        m.get("https://example.com/", status_code=200, headers={})
        with patch.object(session, "get", wraps=session.get) as spy:
            fetch_url("https://example.com/", session, timeout=3.5)
    assert spy.call_args.kwargs["timeout"] == 3.5
