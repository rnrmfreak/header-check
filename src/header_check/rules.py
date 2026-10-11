from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

_VERSION_PATTERN = re.compile(r"/\s*\d|\d+\.\d+")
_FRAME_ANCESTORS_PATTERN = re.compile(r"frame-ancestors", re.IGNORECASE)


class Status(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class CheckResult:
    name: str
    status: Status
    remark: str


@dataclass
class Rule:
    name: str
    check: Callable[[dict[str, str]], CheckResult]


def _check_presence(header_name: str, display_name: str) -> Callable[[dict[str, str]], CheckResult]:
    def _check(headers: dict[str, str]) -> CheckResult:
        if header_name in headers:
            return CheckResult(display_name, Status.PASS, "Header hadir.")
        return CheckResult(display_name, Status.FAIL, f"Header {display_name} tidak ditemukan.")

    return _check


def _check_nosniff(headers: dict[str, str]) -> CheckResult:
    display_name = "X-Content-Type-Options"
    value = headers.get("x-content-type-options")
    if value is None:
        return CheckResult(display_name, Status.FAIL, "Header tidak ditemukan.")
    if value.strip().lower() == "nosniff":
        return CheckResult(display_name, Status.PASS, "Nilai 'nosniff' sudah benar.")
    return CheckResult(
        display_name,
        Status.FAIL,
        f"Nilai tidak valid: '{value}' (harus tepat 'nosniff').",
    )


def _check_frame_protection(headers: dict[str, str]) -> CheckResult:
    display_name = "X-Frame-Options"
    xfo = headers.get("x-frame-options")
    csp = headers.get("content-security-policy", "")
    if xfo is not None:
        return CheckResult(display_name, Status.PASS, f"Header hadir ({xfo}).")
    if _FRAME_ANCESTORS_PATTERN.search(csp):
        return CheckResult(
            display_name,
            Status.PASS,
            "Tidak ada X-Frame-Options, tapi CSP memiliki 'frame-ancestors'.",
        )
    return CheckResult(
        display_name,
        Status.FAIL,
        "Tidak ada X-Frame-Options maupun CSP 'frame-ancestors'.",
    )


def _check_disclosure(header_name: str, display_name: str) -> Callable[[dict[str, str]], CheckResult]:
    def _check(headers: dict[str, str]) -> CheckResult:
        value = headers.get(header_name)
        if value is None:
            return CheckResult(display_name, Status.PASS, "Header tidak ditemukan (baik).")
        if _VERSION_PATTERN.search(value):
            return CheckResult(display_name, Status.WARN, f"Header mengungkap versi: '{value}'.")
        return CheckResult(
            display_name,
            Status.WARN,
            f"Header hadir tapi tanpa versi terdeteksi: '{value}'.",
        )

    return _check


REGISTRY: list[Rule] = [
    Rule("Strict-Transport-Security", _check_presence("strict-transport-security", "Strict-Transport-Security")),
    Rule("Content-Security-Policy", _check_presence("content-security-policy", "Content-Security-Policy")),
    Rule("X-Content-Type-Options", _check_nosniff),
    Rule("Referrer-Policy", _check_presence("referrer-policy", "Referrer-Policy")),
    Rule("Permissions-Policy", _check_presence("permissions-policy", "Permissions-Policy")),
    Rule("X-Frame-Options", _check_frame_protection),
    Rule("Server", _check_disclosure("server", "Server")),
    Rule("X-Powered-By", _check_disclosure("x-powered-by", "X-Powered-By")),
]


def evaluate(headers: dict[str, str]) -> list[CheckResult]:
    lowered = {key.lower(): value for key, value in headers.items()}
    return [rule.check(lowered) for rule in REGISTRY]
