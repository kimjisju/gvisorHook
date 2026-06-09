from __future__ import annotations

import argparse
import asyncio
import sys

from .broker import serve
from .launcher import launch
from .reason_pipeline import replay_reason_pipeline_session


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m gvisor_hook")
    subparsers = parser.add_subparsers(dest="command", required=True)

    launch_parser = subparsers.add_parser("launch", help="launch an agent inside gVisor")
    launch_parser.add_argument(
        "--agent-cmd",
        default=None,
        help='Command to run inside the sandbox. If it contains spaces, it will be shell-split '
        '(e.g. --agent-cmd "codex exec --json \\"say hi\\"" or --agent-cmd "python3 -c \\"print(123)\\"").',
    )
    launch_parser.add_argument(
        "--prompt",
        default=None,
        help="Convenience prompt for Codex non-interactive mode. Used only when --agent-cmd is not provided.",
    )
    launch_parser.add_argument(
        "--codex-model",
        default=None,
        help='Codex model name (passed to "codex exec --model ..."). Used only when --agent-cmd is not provided.',
    )
    launch_parser.add_argument(
        "--codex-no-json",
        action="store_true",
        help='Disable passing "--json" to codex exec. Used only when --agent-cmd is not provided.',
    )
    launch_parser.add_argument("--workdir", required=True)
    launch_parser.add_argument("--web-port", type=int, default=8080)
    launch_parser.add_argument("--decision-timeout", type=float, default=30.0)
    launch_parser.add_argument("--runsc-bin", default=None)
    launch_parser.add_argument(
        "--runsc-strace",
        action="store_true",
        help="Enable gVisor runsc syscall tracing (writes into the runsc debug log).",
    )
    launch_parser.add_argument(
        "--runsc-strace-syscalls",
        default="",
        help='Comma-separated list of syscalls to trace (requires --runsc-strace). Empty means "all".',
    )
    launch_parser.add_argument("--dataset-root", default=None)
    launch_parser.add_argument("--no-plan-mode", action="store_true")
    launch_parser.add_argument(
        "--reason-pipeline-dir",
        default=None,
        help=(
            "Path to reason_pipeline. If omitted, third_party/reason_pipeline is used when present."
        ),
    )
    launch_parser.add_argument(
        "--no-reason-pipeline",
        action="store_true",
        help="Disable running reason_pipeline for each syscall event.",
    )
    launch_parser.add_argument(
        "--reason-pipeline-max-concurrency",
        type=int,
        default=1,
        help="Maximum number of concurrent reason_pipeline subprocesses. Default: 1.",
    )
    launch_parser.add_argument(
        "--proxy-mode",
        choices=("all", "off"),
        default="all",
        help=(
            "LLM traffic proxying mode. 'all' sets HTTP(S)/ALL_PROXY inside the sandbox so all "
            "traffic is captured by mitmproxy, and 'off' disables mitm routing."
        ),
    )
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
    serve_parser.add_argument("--db-path", default=None)
    serve_parser.add_argument("--reason-pipeline-dir", default=None)
    serve_parser.add_argument("--reason-pipeline-agent-name", default="agent")
    serve_parser.add_argument("--reason-pipeline-event-dir", default=None)
    serve_parser.add_argument("--reason-pipeline-output-dir", default=None)
    serve_parser.add_argument("--reason-pipeline-log-path", default=None)
    serve_parser.add_argument("--reason-pipeline-db-path", default=None)
    serve_parser.add_argument("--reason-pipeline-max-concurrency", type=int, default=1)

    replay_parser = subparsers.add_parser(
        "replay-reason-pipeline",
        help="reprocess a dataset session's reason-pipeline-events into reason-pipeline-results",
    )
    replay_parser.add_argument("session_path", help="Dataset session directory containing reason-pipeline-events")
    replay_parser.add_argument(
        "--reason-pipeline-dir",
        default=None,
        help="Path to reason_pipeline. If omitted, third_party/reason_pipeline is used.",
    )
    replay_parser.add_argument(
        "--clear-results",
        action="store_true",
        help="Delete existing JSON files in reason-pipeline-results before replaying.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "launch":
        return launch(args)
    if args.command == "serve":
        asyncio.run(serve(args))
        return 0
    if args.command == "replay-reason-pipeline":
        from pathlib import Path

        result = asyncio.run(
            replay_reason_pipeline_session(
                Path(args.session_path),
                pipeline_dir=Path(args.reason_pipeline_dir) if args.reason_pipeline_dir else None,
                clear_results=args.clear_results,
            )
        )
        print(f"Session: {result.session_root}")
        print(f"Events: {result.event_count}")
        print(f"Succeeded: {result.success_count}")
        print(f"Failed: {result.failure_count}")
        print(f"Results: {result.output_dir}")
        print(f"Replay log: {result.log_path}")
        return 1 if result.failure_count else 0
    parser.error(f"unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
