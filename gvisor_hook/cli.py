from __future__ import annotations

import argparse
import asyncio
import sys

from .broker import serve
from .launcher import launch


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m gvisor_hook")
    subparsers = parser.add_subparsers(dest="command", required=True)

    launch_parser = subparsers.add_parser("launch", help="launch an agent inside gVisor")
    launch_parser.add_argument("--workdir", required=True)
    launch_parser.add_argument("--agent-cmd", default="interpreter")
    launch_parser.add_argument("--web-port", type=int, default=8080)
    launch_parser.add_argument("--decision-timeout", type=float, default=30.0)
    launch_parser.add_argument("--runsc-bin", default=None)
    launch_parser.add_argument("--config-mount", default=None)
    launch_parser.add_argument("--python-site-packages", default=None)

    serve_parser = subparsers.add_parser("serve", help=argparse.SUPPRESS)
    serve_parser.add_argument("--socket-path", required=True)
    serve_parser.add_argument("--web-port", type=int, required=True)
    serve_parser.add_argument("--decision-timeout", type=float, default=30.0)
    serve_parser.add_argument("--bind-host", default=None)
    serve_parser.add_argument("--http-socket-path", default=None)
    serve_parser.add_argument("--tcp-host", default="127.0.0.1")
    serve_parser.add_argument("--tcp-port", type=int, default=None)
    serve_parser.add_argument("--event-log-path", default=None)
    serve_parser.add_argument("--decision-dir", default=None)
    serve_parser.add_argument("--llm-log-path", default=None)
    serve_parser.add_argument("--llm-proxy-url", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "launch":
        return launch(args)
    if args.command == "serve":
        asyncio.run(serve(args))
        return 0
    parser.error(f"unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
