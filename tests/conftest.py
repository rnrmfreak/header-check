import pytest


@pytest.fixture
def good_headers() -> dict[str, str]:
    return {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "X-Frame-Options": "DENY",
    }
