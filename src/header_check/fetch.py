from __future__ import annotations

from dataclasses import dataclass, field

import requests


@dataclass
class FetchResult:
    requested_url: str
    final_url: str | None
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    error_type: str | None = None


def fetch_url(url: str, session: requests.Session, timeout: float = 10.0) -> FetchResult:
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.SSLError:
        return FetchResult(
            requested_url=url,
            final_url=None,
            status_code=None,
            error="Gagal verifikasi SSL/TLS.",
            error_type="ssl",
        )
    except requests.exceptions.Timeout:
        return FetchResult(
            requested_url=url,
            final_url=None,
            status_code=None,
            error=f"Request timeout setelah {timeout}s.",
            error_type="timeout",
        )
    except requests.exceptions.ConnectionError:
        return FetchResult(
            requested_url=url,
            final_url=None,
            status_code=None,
            error="Tidak dapat terhubung ke server.",
            error_type="connection",
        )
    except requests.exceptions.RequestException as exc:
        return FetchResult(
            requested_url=url,
            final_url=None,
            status_code=None,
            error=f"Request gagal: {exc}",
            error_type="request",
        )

    headers = {key.lower(): value for key, value in response.headers.items()}
    return FetchResult(
        requested_url=url,
        final_url=response.url,
        status_code=response.status_code,
        headers=headers,
    )
