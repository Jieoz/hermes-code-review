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

    sub.add_parser("status", help="Show fixed-route local readiness without credentials or a network probe")
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
        status = result.get("status")
        signature_valid = False
        if status == "PASS":
            try:
                signature_valid = signing.verify_result(result, plugin.SIGNING_KEY)
            except (ValueError, OSError):
                signature_valid = False
        print(json.dumps(result, sort_keys=True))
        if status == "PASS" and signature_valid and (result.get("verdict") or {}).get("safe_to_commit") is True:
            return 0
        if status == "BLOCKED":
            return 2
        return 3
    if args.command == "verify-receipt":
        result = json.loads(Path(args.result).read_text(encoding="utf-8"))
        try:
            valid = signing.verify_result(result, Path(args.key_file))
        except (ValueError, OSError):
            valid = False
        print(json.dumps({"valid": valid}))
        return 0 if valid else 4
    result = json.loads(plugin.code_review_status({}))
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == "READY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
