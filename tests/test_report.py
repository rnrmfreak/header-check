import json

from header_check.fetch import FetchResult
from header_check.report import UrlReport, build_url_report, exit_code_for, render_json, render_table
from header_check.rules import CheckResult, Status


def test_build_url_report_success_runs_rules(good_headers):
    fetch_result = FetchResult(
        requested_url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        headers={k.lower(): v for k, v in good_headers.items()},
    )
    report = build_url_report(fetch_result)
    assert report.error is None
    assert len(report.checks) == len(good_headers) + 2  # + Server + X-Powered-By rules


def test_build_url_report_error_has_no_checks():
    fetch_result = FetchResult(
        requested_url="https://bad.example.com",
        final_url=None,
        status_code=None,
        error="Tidak dapat terhubung ke server.",
        error_type="connection",
    )
    report = build_url_report(fetch_result)
    assert report.checks == []
    assert report.error == "Tidak dapat terhubung ke server."
    assert report.error_type == "connection"


def test_render_table_includes_header_rows():
    report = UrlReport(
        url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        error=None,
        error_type=None,
        checks=[CheckResult("Strict-Transport-Security", Status.PASS, "Header hadir.")],
    )
    table = render_table([report])
    assert "Strict-Transport-Security" in table
    assert "PASS" in table
    assert "Header hadir." in table


def test_render_table_shows_error_block():
    report = UrlReport(
        url="https://bad.example.com",
        final_url=None,
        status_code=None,
        error="Tidak dapat terhubung ke server.",
        error_type="connection",
        checks=[],
    )
    table = render_table([report])
    assert "ERROR: Tidak dapat terhubung ke server." in table


def test_render_json_matches_schema():
    report = UrlReport(
        url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        error=None,
        error_type=None,
        checks=[CheckResult("Strict-Transport-Security", Status.PASS, "Header hadir.")],
    )
    data = json.loads(render_json([report]))
    assert data == [
        {
            "url": "https://example.com",
            "final_url": "https://example.com/",
            "status_code": 200,
            "error": None,
            "error_type": None,
            "checks": [
                {"name": "Strict-Transport-Security", "status": "PASS", "remark": "Header hadir."}
            ],
        }
    ]


def test_exit_code_zero_when_all_pass_or_warn():
    report = UrlReport(
        url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        error=None,
        error_type=None,
        checks=[
            CheckResult("A", Status.PASS, "ok"),
            CheckResult("Server", Status.WARN, "warn"),
        ],
    )
    assert exit_code_for([report]) == 0


def test_exit_code_one_when_any_fail():
    pass_report = UrlReport(
        url="https://good.example.com",
        final_url="https://good.example.com/",
        status_code=200,
        error=None,
        error_type=None,
        checks=[CheckResult("A", Status.PASS, "ok")],
    )
    fail_report = UrlReport(
        url="https://bad.example.com",
        final_url="https://bad.example.com/",
        status_code=200,
        error=None,
        error_type=None,
        checks=[CheckResult("A", Status.FAIL, "missing")],
    )
    assert exit_code_for([pass_report, fail_report]) == 1


def test_exit_code_one_when_fetch_error_present():
    pass_report = UrlReport(
        url="https://good.example.com",
        final_url="https://good.example.com/",
        status_code=200,
        error=None,
        error_type=None,
        checks=[CheckResult("A", Status.PASS, "ok")],
    )
    error_report = UrlReport(
        url="https://bad.example.com",
        final_url=None,
        status_code=None,
        error="Tidak dapat terhubung ke server.",
        error_type="connection",
        checks=[],
    )
    assert exit_code_for([pass_report, error_report]) == 1
