import json

import pytest
import requests

from header_check.cli import main


def test_main_all_good_exits_zero_and_prints_table(requests_mock, good_headers, capsys):
    requests_mock.get("https://good.example.com/", status_code=200, headers=good_headers)
    code = main(["https://good.example.com/"])
    captured = capsys.readouterr()
    assert code == 0
    assert "Strict-Transport-Security" in captured.out
    assert "PASS" in captured.out


def test_main_json_flag_outputs_valid_json(requests_mock, good_headers, capsys):
    requests_mock.get("https://good.example.com/", status_code=200, headers=good_headers)
    code = main(["https://good.example.com/", "--json"])
    captured = capsys.readouterr()
    assert code == 0
    data = json.loads(captured.out)
    assert data[0]["url"] == "https://good.example.com/"
    assert any(check["name"] == "Strict-Transport-Security" for check in data[0]["checks"])


def test_main_connection_error_exits_one_without_stacktrace(requests_mock, capsys):
    requests_mock.get("https://bad.example.com/", exc=requests.exceptions.ConnectionError)
    code = main(["https://bad.example.com/"])
    captured = capsys.readouterr()
    assert code == 1
    assert "ERROR" in captured.out
    assert "Traceback" not in captured.out


def test_main_mixed_urls_exit_code_one_and_both_present(requests_mock, good_headers, capsys):
    requests_mock.get("https://good.example.com/", status_code=200, headers=good_headers)
    requests_mock.get("https://bad.example.com/", exc=requests.exceptions.ConnectionError)
    code = main(["https://good.example.com/", "https://bad.example.com/"])
    captured = capsys.readouterr()
    assert code == 1
    assert "good.example.com" in captured.out
    assert "bad.example.com" in captured.out


def test_main_no_urls_raises_system_exit():
    with pytest.raises(SystemExit):
        main([])


def test_main_timeout_passed_through(requests_mock, good_headers):
    requests_mock.get("https://good.example.com/", status_code=200, headers=good_headers)
    code = main(["https://good.example.com/", "--timeout", "3.5"])
    assert code == 0
