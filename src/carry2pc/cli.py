"""Command-line interface for protocol verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from carry2pc.config import ConfigError, load_config
from carry2pc.evaluation import run_evaluation_matrix
from carry2pc.verification import check_expected_vector, run_verification


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="carry2pc")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify", help="run bounded exhaustive verification")
    verify.add_argument("--config", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)
    verify.add_argument(
        "--expect",
        type=Path,
        help="optional JSON vector containing deterministic semantic expectations",
    )

    evaluate = subparsers.add_parser(
        "evaluate-matrix", help="run the declared deterministic evaluation matrix"
    )
    evaluate.add_argument("--config", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "evaluate-matrix":
            metrics = run_evaluation_matrix(
                config,
                args.output,
                config_path=args.config,
            )
            print(
                json.dumps(
                    {
                        "artifact_status": metrics["artifact_status"],
                        "configuration_cells": metrics["configuration_cells"],
                        "total_exhaustive_runs": metrics["total_exhaustive_runs"],
                        "all_runs_bounded_complete": metrics[
                            "all_runs_bounded_complete"
                        ],
                        "passed": metrics["passed"],
                        "output": str(args.output),
                    },
                    sort_keys=True,
                )
            )
            return 0 if metrics["passed"] else 1
        if args.command == "verify":
            summary = run_verification(config, args.output)
            if args.expect is not None:
                check_expected_vector(summary, args.expect)
            print(
                json.dumps(
                    {
                        "artifact_class": summary["artifact_class"],
                        "passed": summary["passed"],
                        "runtime_seconds": summary["runtime_seconds"],
                        "states_explored": summary["compliant"]["states_explored"],
                        "output": str(args.output),
                    },
                    sort_keys=True,
                )
            )
            return 0 if summary["passed"] else 1
        raise ConfigError(f"unsupported command: {args.command}")
    except (ConfigError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
