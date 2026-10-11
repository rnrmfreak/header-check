from __future__ import annotations

import argparse
import sys

import requests

from .fetch import fetch_url
from .report import build_url_report, exit_code_for, render_json, render_table


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="header-check",
        description="Periksa header keamanan HTTP pada satu atau beberapa URL.",
    )
    parser.add_argument("urls", nargs="+", metavar="URL", help="Satu atau lebih URL untuk diperiksa.")
    parser.add_argument("--json", action="store_true", help="Tampilkan hasil sebagai JSON.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout request dalam detik (default: 10).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    session = requests.Session()
    reports = [
        build_url_report(fetch_url(url, session, timeout=args.timeout)) for url in args.urls
    ]
    output = render_json(reports) if args.json else render_table(reports)
    print(output)
    return exit_code_for(reports)


if __name__ == "__main__":
    sys.exit(main())
