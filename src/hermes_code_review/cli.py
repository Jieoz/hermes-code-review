from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from . import plugin, signing


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hermes-code-review")
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review-git", help="Review the staged immutable Git candidate")
    review.add_argument("--repo", required=True)
    review.add_argument("--requirements", required=True)
    review.add_argument("--evidence", required=True)
    review.add_argument("--timeout", type=int, default=240)

    verify = sub.add_parser("verify-receipt", help="Verify a signed review result")
    verify.add_argument("result")
    verify.add_argument("--key-file", required=True)

    sub.add_parser("status", help="Show the fixed reviewer route without credentials")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "review-git":
        result = json.loads(plugin.review_git_candidate({
            "repo": args.repo,
            "requirements": args.requirements,
            "evidence": args.evidence,
            "timeout": args.timeout,
        }))
        print(json.dumps(result, sort_keys=True))
        status = result.get("status")
        if status == "PASS" and result.get("safe_to_commit") is True:
            return 0
        if status == "BLOCKED":
            return 2
        return 3
    if args.command == "verify-receipt":
        result = json.loads(Path(args.result).read_text(encoding="utf-8"))
        valid = signing.verify_result(result, Path(args.key_file))
        print(json.dumps({"valid": valid}))
        return 0 if valid else 4
    result = json.loads(plugin.code_review_status({}))
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == "READY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
