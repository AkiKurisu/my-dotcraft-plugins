from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    from audit import audit, compare_baseline
finally:
    sys.path.pop(0)


CURRENT = "11111111-1111-4111-8111-111111111111"
RETIRED = "22222222-2222-4222-8222-222222222222"
INDEPENDENT = "33333333-3333-4333-8333-333333333333"
CURRENT_ORG = "44444444-4444-4444-8444-444444444444"
RETIRED_ORG = "55555555-5555-4555-8555-555555555555"
SESSION_ONE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SESSION_TWO = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
SESSION_3P = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


class AuditFixtureTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="claude-guard-fixture-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name) / "home"
        self.cli = self.home / ".claude"
        self.desktop = self.home / "AppData/Local/Claude-Data/package"
        self.projects = self.cli / "projects/fixture-project"
        self.current_bucket = (
            self.desktop / "claude-code-sessions" / CURRENT / CURRENT_ORG
        )
        self.retired_bucket = (
            self.desktop / "claude-code-sessions" / RETIRED / RETIRED_ORG
        )
        self.write_json(self.home / ".claude.json", {
            "oauthAccount": {
                "accountUuid": CURRENT,
                "organizationUuid": CURRENT_ORG,
                "emailAddress": "current@example.invalid",
            },
        })
        self.write_json(self.desktop / "config.json", {
            "lastKnownAccountUuid": CURRENT,
        })
        self.write_json(self.desktop / "ccd-session-presets.json", {
            "byAccount": {CURRENT: {}, RETIRED: {}},
        })
        self.write_json(self.desktop / "ant-device-registry.json", {
            CURRENT: {"device": "fixture-current"},
            RETIRED: {"device": "fixture-retired"},
        })
        self.current_index = self.current_bucket / "session.json"
        self.write_json(self.current_index, {"cliSessionId": SESSION_ONE})
        self.write_json(self.retired_bucket / "session.json", {
            "cliSessionId": "retired-fixture-session",
        })
        self.transcript = self.projects / f"{SESSION_ONE}.jsonl"
        self.write_json(self.transcript, {
            "type": "attachment",
            "sessionId": SESSION_ONE,
            "ownerAccountUuid": RETIRED,
            "ownerOrganizationUuid": RETIRED_ORG,
            "attachment": {
                "organizationUuid": RETIRED_ORG,
                "context": {"userEmail": "retired@example.invalid"},
            },
            "message": {"role": "user", "content": "Fictional retained work."},
        })

    @staticmethod
    def write_bytes(path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def write_json(self, path, value):
        return self.write_bytes(path, (json.dumps(value) + "\n").encode("utf-8"))

    def snapshot(self):
        return {
            path.relative_to(self.home).as_posix(): (
                path.read_bytes() if path.is_file() else None
            )
            for path in self.home.rglob("*")
        }

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_current_indexes_preserve_old_owner_work_and_audit_is_read_only(self):
        second_index = self.write_json(
            self.current_bucket / f"{SESSION_TWO}.json",
            {"sessionId": SESSION_TWO},
        )
        second_transcript = self.write_json(
            self.projects / f"{SESSION_TWO}.jsonl",
            {"ownerAccountUuid": CURRENT, "sessionId": SESSION_TWO,
             "message": {"role": "assistant", "content": "Another fictional result."}},
        )
        attachment = self.write_bytes(
            self.projects / SESSION_ONE / "tool-results/result.txt",
            b"Fictional attachment\r\n",
        )
        checkpoint = self.write_bytes(
            self.cli / "file-history" / SESSION_ONE / "checkpoint",
            b"Fictional checkpoint\x00",
        )
        memory = self.write_bytes(
            self.projects / "memory/MEMORY.md", b"Shared fictional project memory.\n",
        )
        for name in ("archived-sessions.idx", "deleted_marker"):
            self.write_bytes(self.retired_bucket / name, b"Fictional retired marker.\n")
        expected_hashes = {
            self.digest(path) for path in (
                self.current_index, second_index, self.transcript, second_transcript,
                attachment, checkpoint, memory,
            )
        }
        before = self.snapshot()

        report = audit(self.home)

        with self.subTest("audit leaves every fixture path and byte unchanged"):
            self.assertEqual(before, self.snapshot())
        with self.subTest("current index protects an exclusively old-owner transcript"):
            self.assertIn(self.digest(self.transcript), report["protected"].values())
        with self.subTest("each current session and its work has a distinct protected key"):
            self.assertCountEqual(expected_hashes, report["protected"].values())
        with self.subTest("retained transcript still reports old identity metadata"):
            identities = [
                finding for finding in report["findings"]
                if finding["kind"] == "preserved_session_identity"
            ]
            self.assertEqual(1, len(identities))
            self.assertTrue(identities[0]["path"].endswith(".jsonl"))
            self.assertEqual(1, identities[0]["retired_owner_records"])
            self.assertTrue({
                "ownerAccountUuid", "ownerOrganizationUuid",
                "attachment.organizationUuid", "attachment.context.userEmail",
            }.issubset(identities[0]["fields"]))
        with self.subTest("retired bucket includes indexes and extensionless markers"):
            retired_files = [
                finding["path"].rsplit("/", 1)[-1]
                for finding in report["findings"]
                if finding["kind"] == "retired_account_file"
            ]
            self.assertCountEqual(
                ["session.json", "archived-sessions.idx", "deleted_marker"],
                retired_files,
            )
        self.assertEqual([], report["errors"])
        self.assertEqual([], report["skipped"])

    def test_independent_3p_bucket_is_not_retired_and_credentials_are_redacted(self):
        self.write_bytes(
            self.home / "AppData/Local/Claude-3p/ant-did",
            base64.b64encode(INDEPENDENT.encode("ascii")),
        )
        independent_index = self.write_json(
            self.desktop / "claude-code-sessions" / INDEPENDENT
            / CURRENT_ORG / "session.json",
            {"cliSessionId": SESSION_3P},
        )
        independent_transcript = self.write_json(
            self.projects / f"{SESSION_3P}.jsonl",
            {"ownerAccountUuid": INDEPENDENT, "sessionId": SESSION_3P,
             "message": {"content": "Independent fictional work."}},
        )
        secrets = (
            "fixture-claude-access-secret", "fixture-claude-refresh-secret",
            "fixture-mcp-access-secret", "fixture-mcp-refresh-secret",
        )
        self.write_json(self.cli / ".credentials.json", {
            "claudeAiOauth": {"accessToken": secrets[0], "refreshToken": secrets[1]},
            "mcpOAuth": {
                "fixture-mcp-one": {"accessToken": secrets[2]},
                "fixture-mcp-two": {"refreshToken": secrets[3]},
            },
        })

        report = audit(self.home)

        self.assertEqual(1, report["independent_3p_identities"])
        self.assertEqual(1, report["noncurrent_account_hints"])
        independent_labels = [
            path for path, digest in report["protected"].items()
            if digest == self.digest(independent_index)
        ]
        self.assertEqual(1, len(independent_labels))
        independent_label = independent_labels[0]
        self.assertIn(self.digest(independent_transcript), report["protected"].values())
        self.assertFalse(any(
            finding["path"] == independent_label for finding in report["findings"]
        ))
        self.assertEqual({
            "claude_oauth_present": True,
            "oauth_owner_verified": False,
            "mcp_authorizations": 2,
        }, report["credentials"])
        self.assertEqual(hashlib.sha256(CURRENT.encode()).hexdigest(),
                         report["current_account_fingerprint"])
        serialized = json.dumps(report)
        for secret in secrets:
            self.assertNotIn(secret, serialized)
        self.assertNotRegex(
            serialized, r"(?i)[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
        )
        self.assertNotIn("current@example.invalid", serialized)
        self.assertNotIn("retired@example.invalid", serialized)
        self.assertEqual([], report["errors"])

    def test_baseline_detects_modified_retained_transcript(self):
        baseline = audit(self.home)
        self.assertEqual({
            "matches": True, "same_current_account": True,
            "missing": [], "changed": [],
        }, compare_baseline(audit(self.home), baseline))
        transcript_label = next(
            path for path in baseline["protected"] if path.endswith(".jsonl")
        )
        record = json.loads(self.transcript.read_text(encoding="utf-8"))
        record["message"]["content"] = "Fictional body changed after baseline."
        self.write_json(self.transcript, record)

        comparison = compare_baseline(audit(self.home), baseline)

        self.assertEqual({
            "matches": False, "same_current_account": True,
            "missing": [], "changed": [transcript_label],
        }, comparison)

    def test_baseline_detects_missing_retained_transcript(self):
        baseline = audit(self.home)
        transcript_label = next(
            path for path in baseline["protected"] if path.endswith(".jsonl")
        )
        self.transcript.unlink()

        comparison = compare_baseline(audit(self.home), baseline)

        self.assertEqual({
            "matches": False, "same_current_account": True,
            "missing": [transcript_label], "changed": [],
        }, comparison)

    def test_corrupt_json_is_reported_as_an_error(self):
        baseline = audit(self.home)
        index_label = next(
            path for path, digest in baseline["protected"].items()
            if digest == self.digest(self.current_index)
        )
        for path, label in (
            (self.home / ".claude.json", "<home>/.claude.json"),
            (self.current_index, index_label),
        ):
            with self.subTest(file=path.name):
                original = path.read_bytes()
                try:
                    path.write_bytes(b'{"fixture": invalid-json\n')

                    report = audit(self.home)

                    self.assertIn({"path": label, "kind": "unreadable_json"},
                                  report["errors"])
                finally:
                    path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
