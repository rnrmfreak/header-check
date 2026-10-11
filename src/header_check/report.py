from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from .fetch import FetchResult
from .rules import CheckResult, Status, evaluate


@dataclass
class UrlReport:
    url: str
    final_url: str | None
    status_code: int | None
    error: str | None
    error_type: str | None
    checks: list[CheckResult] = field(default_factory=list)


def build_url_report(fetch_result: FetchResult) -> UrlReport:
    if fetch_result.error is not None:
        return UrlReport(
            url=fetch_result.requested_url,
            final_url=fetch_result.final_url,
            status_code=fetch_result.status_code,
            error=fetch_result.error,
            error_type=fetch_result.error_type,
            checks=[],
        )
    return UrlReport(
        url=fetch_result.requested_url,
        final_url=fetch_result.final_url,
        status_code=fetch_result.status_code,
        error=None,
        error_type=None,
        checks=evaluate(fetch_result.headers),
    )


def render_table(reports: list[UrlReport]) -> str:
    lines: list[str] = []
    for report in reports:
        lines.append(f"URL: {report.url}  (final: {report.final_url})")
        lines.append("-" * 60)
        if report.error is not None:
            lines.append(f"ERROR: {report.error}")
        else:
            lines.append(f"{'HEADER':<32}{'STATUS':<9}REMARK")
            for check in report.checks:
                lines.append(f"{check.name:<32}{check.status.value:<9}{check.remark}")
        lines.append("")
    return "\n".join(lines).rstrip("\n")


def render_json(reports: list[UrlReport]) -> str:
    payload = []
    for report in reports:
        payload.append(
            {
                "url": report.url,
                "final_url": report.final_url,
                "status_code": report.status_code,
                "error": report.error,
                "error_type": report.error_type,
                "checks": [asdict(check) for check in report.checks],
            }
        )
    return json.dumps(payload, indent=2)


def exit_code_for(reports: list[UrlReport]) -> int:
    for report in reports:
        if report.error is not None:
            return 1
        if any(check.status == Status.FAIL for check in report.checks):
            return 1
    return 0
