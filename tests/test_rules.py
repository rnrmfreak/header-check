from header_check.rules import REGISTRY, Status, evaluate

REQUIRED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def test_all_good_headers_pass(good_headers):
    results = evaluate(good_headers)
    statuses = {result.name: result.status for result in results}
    for name in REQUIRED_HEADERS + ["X-Frame-Options"]:
        assert statuses[name] == Status.PASS
    assert statuses["Server"] == Status.PASS
    assert statuses["X-Powered-By"] == Status.PASS


def test_evaluate_returns_one_result_per_rule(good_headers):
    results = evaluate(good_headers)
    assert [r.name for r in results] == [rule.name for rule in REGISTRY]


def test_missing_required_header_fails(good_headers):
    for header in REQUIRED_HEADERS:
        headers = dict(good_headers)
        del headers[header]
        results = {r.name: r.status for r in evaluate(headers)}
        assert results[header] == Status.FAIL, f"{header} should FAIL when missing"


def test_nosniff_case_insensitive_pass(good_headers):
    headers = dict(good_headers)
    headers["X-Content-Type-Options"] = "NOSNIFF"
    results = {r.name: r.status for r in evaluate(headers)}
    assert results["X-Content-Type-Options"] == Status.PASS


def test_nosniff_wrong_value_fails(good_headers):
    headers = dict(good_headers)
    headers["X-Content-Type-Options"] = "sniff"
    results = {r.name: r.status for r in evaluate(headers)}
    assert results["X-Content-Type-Options"] == Status.FAIL


def test_nosniff_trailing_garbage_fails(good_headers):
    headers = dict(good_headers)
    headers["X-Content-Type-Options"] = "nosniff; foo"
    results = {r.name: r.status for r in evaluate(headers)}
    assert results["X-Content-Type-Options"] == Status.FAIL


def test_xfo_present_without_csp_passes():
    headers = {"X-Frame-Options": "DENY"}
    results = {r.name: r.status for r in evaluate(headers)}
    assert results["X-Frame-Options"] == Status.PASS


def test_xfo_missing_but_csp_has_frame_ancestors_passes():
    headers = {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'"}
    results = {r.name: r.status for r in evaluate(headers)}
    assert results["X-Frame-Options"] == Status.PASS
    remark = next(r.remark for r in evaluate(headers) if r.name == "X-Frame-Options")
    assert "frame-ancestors" in remark


def test_xfo_missing_and_csp_without_frame_ancestors_fails():
    headers = {"Content-Security-Policy": "default-src 'self'"}
    results = {r.name: r.status for r in evaluate(headers)}
    assert results["X-Frame-Options"] == Status.FAIL


def test_xfo_and_csp_both_missing_fails():
    results = {r.name: r.status for r in evaluate({})}
    assert results["X-Frame-Options"] == Status.FAIL


def test_server_with_version_warns():
    headers = {"Server": "Apache/2.4.41"}
    results = {r.name: (r.status, r.remark) for r in evaluate(headers)}
    status, remark = results["Server"]
    assert status == Status.WARN
    assert "versi" in remark.lower()


def test_server_without_version_warns():
    headers = {"Server": "Apache"}
    results = {r.name: (r.status, r.remark) for r in evaluate(headers)}
    status, remark = results["Server"]
    assert status == Status.WARN
    assert "tanpa versi" in remark.lower()


def test_server_missing_passes():
    results = {r.name: r.status for r in evaluate({})}
    assert results["Server"] == Status.PASS


def test_x_powered_by_with_version_warns():
    headers = {"X-Powered-By": "PHP/7.4.3"}
    results = {r.name: r.status for r in evaluate(headers)}
    assert results["X-Powered-By"] == Status.WARN


def test_x_powered_by_missing_passes():
    results = {r.name: r.status for r in evaluate({})}
    assert results["X-Powered-By"] == Status.PASS


def test_sengaja_gagal():
    assert 1 + 1 == 3

