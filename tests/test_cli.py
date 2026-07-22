from __future__ import annotations

import json


def test_cli_review_exit_codes(monkeypatch, capsys, tmp_path):
    from hermes_code_review import cli
    monkeypatch.setattr(cli.plugin, "review_git_candidate", lambda args: json.dumps({"status": "PASS", "safe_to_commit": True}))
    assert cli.main(["review-git", "--repo", str(tmp_path), "--requirements", "r", "--evidence", "e"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"
    monkeypatch.setattr(cli.plugin, "review_git_candidate", lambda args: json.dumps({"status": "BLOCKED", "safe_to_commit": False}))
    assert cli.main(["review-git", "--repo", str(tmp_path), "--requirements", "r", "--evidence", "e"]) == 2


def test_cli_verifies_signed_receipt(capsys, tmp_path):
    from hermes_code_review import cli, signing
    key = tmp_path / "key"
    signing.create_signing_key(key)
    result = signing.sign_result({"receipt": {"x": 1}, "verdict": {"passed": True}}, key)
    result_file = tmp_path / "result.json"
    result_file.write_text(json.dumps(result))
    assert cli.main(["verify-receipt", str(result_file), "--key-file", str(key)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True


def test_cli_rejects_infra_result(monkeypatch, tmp_path):
    from hermes_code_review import cli
    monkeypatch.setattr(cli.plugin, "review_git_candidate", lambda args: json.dumps({"status": "INFRA_FAILED", "safe_to_commit": False}))
    assert cli.main(["review-git", "--repo", str(tmp_path), "--requirements", "r", "--evidence", "e"]) == 3
