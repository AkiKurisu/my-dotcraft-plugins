from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import os
from pathlib import Path

from inventory import Inventory, UUID


def inspect_transcript(inv: Inventory, path: Path) -> dict:
    owners, sessions, metadata = set(), set(), set()
    old_owner_records = 0
    marker_found = False
    try:
        with path.open("rb") as stream:
            for line in stream:
                account_markers = [value.encode() for value in inv.retired]
                org_markers = [value.encode() for value in inv.retired_orgs]
                matched = any(value in line for value in account_markers + org_markers)
                marker_found |= matched
                if not matched and not any(key in line for key in (
                    b'"ownerAccountUuid"', b'"accountUuid"', b'"attachment"'
                )):
                    continue
                try:
                    record = json.loads(line)
                except (ValueError, UnicodeError):
                    inv.errors.append({"path": path, "kind": "unreadable_transcript_record"})
                    continue
                if not isinstance(record, dict):
                    continue
                owner = record.get("ownerAccountUuid")
                if isinstance(owner, str) and UUID.fullmatch(owner):
                    owners.add(owner)
                    if owner != inv.current and owner not in inv.synthetic:
                        inv.retired.add(owner)
                        old_owner_records += 1
                        metadata.add("ownerAccountUuid")
                        organization = record.get("ownerOrganizationUuid")
                        if isinstance(organization, str) and organization not in inv.current_orgs:
                            inv.retired_orgs.add(organization)
                            metadata.add("ownerOrganizationUuid")
                if isinstance(record.get("sessionId"), str):
                    sessions.add(record["sessionId"])
                attachment = record.get("attachment")
                if isinstance(attachment, dict):
                    if attachment.get("organizationUuid") in inv.retired_orgs:
                        metadata.add("attachment.organizationUuid")
                    context = attachment.get("context")
                    email = context.get("userEmail") if isinstance(context, dict) else None
                    if email and inv.email and email != inv.email:
                        metadata.add("attachment.context.userEmail")
                if matched and record.get("type") == "api-request-blob":
                    metadata.add("api-request-blob")
                elif matched and record.get("type") != "attachment":
                    metadata.add("saved_content_reference")
    except OSError:
        inv.errors.append({"path": path, "kind": "unreadable_transcript"})
    return {"path": path, "owners": owners, "sessions": sessions,
            "old_owner_records": old_owner_records, "fields": sorted(metadata),
            "old_marker_found": marker_found}


def collect_histories(inv: Inventory) -> dict:
    projects = inv.files(inv.cli / "projects")
    transcripts = [inspect_transcript(inv, p) for p in projects if p.suffix == ".jsonl"]
    for record in transcripts:
        if inv.current and inv.current in record["owners"]:
            inv.session_ids.add(record["path"].stem)
            inv.session_ids.update(record["sessions"])
    unknown = preserved = 0
    for path in projects:
        parts = set(path.relative_to(inv.cli / "projects").parts)
        protected = bool(inv.session_ids.intersection(parts | {path.stem}))
        if protected or "memory" in parts:
            inv.protect(path)
            preserved += 1
    for record in transcripts:
        path = record["path"]
        protected = inv.label(path) in inv.protected
        if not protected:
            unknown += 1
        if record["fields"] or record["old_marker_found"]:
            inv.findings.append({
                "path": path,
                "kind": "preserved_session_identity" if protected else "discardable_session_identity",
                "fields": record["fields"],
                "retired_owner_records": record["old_owner_records"],
            })
    checkpoints = 0
    for path in inv.files(inv.cli / "file-history"):
        bucket = path.relative_to(inv.cli / "file-history").parts[0]
        if bucket in inv.session_ids:
            inv.protect(path)
            checkpoints += 1
    return {
        "transcripts": len(transcripts),
        "protected_project_files": preserved,
        "discardable_or_unattributed_transcripts": unknown,
        "protected_checkpoint_files": checkpoints,
    }


def collect_residuals(inv: Inventory) -> dict:
    for path in inv.account_files:
        inv.findings.append({"path": path, "kind": "retired_account_file"})
    candidates = {inv.config_path}
    for root in (inv.cli, *inv.desktops):
        if not root.is_dir():
            continue
        for path in root.iterdir():
            if path.is_file() and not inv.linked(path) and (
                path.suffix == ".json" or ".json.tmp" in path.name
            ):
                candidates.add(path)
    for path in inv.home.glob(".claude.json.*"):
        if path.is_file() and not inv.linked(path):
            candidates.add(path)
    roots = [
        inv.cli / name for name in ("backups", "cache", "state", "telemetry",
                                    "shell-snapshots", "paste-cache", "session-env", "sessions")
    ]
    roots += [inv.local / "claude-cli-nodejs" / "Cache", inv.local / "Claude" / "logs"]
    roots += [root / name for root in inv.desktops for name in ("logs", "sentry")]
    for root in roots:
        candidates.update(inv.files(root))
    for path in sorted(candidates):
        if not path.is_file() or inv.linked(path):
            continue
        hits = inv.identity_hits(path)
        if hits and any(hits.values()):
            inv.findings.append({"path": path, "kind": "identity_reference", **hits})
    stores = []
    for root in inv.desktops:
        for name in ("Local Storage", "Session Storage", "IndexedDB"):
            directory = root / name
            files = inv.files(directory)
            stores.append({"path": inv.label(directory), "exists": directory.exists(),
                           "files": len(files)})
            for path in files:
                hits = inv.identity_hits(path)
                if hits and any(hits.values()):
                    inv.findings.append({"path": path, "kind": "mixed_storage_identity", **hits})
    return {"identity_files_scanned": len(candidates), "mixed_stores": stores}


def compare_baseline(report: dict, baseline: dict) -> dict:
    before, after = baseline["protected"], report["protected"]
    missing = sorted(set(before) - set(after))
    changed = sorted(path for path in before.keys() & after.keys()
                     if before[path] != after[path])
    same_account = baseline["current_account_fingerprint"] == report["current_account_fingerprint"]
    return {"matches": same_account and not missing and not changed,
            "same_current_account": same_account, "missing": missing, "changed": changed}


def audit(home: Path, config_dir: Path | None = None,
          desktop_roots: list[Path] | None = None, current: str | None = None) -> dict:
    inv = Inventory(home, config_dir, desktop_roots, current)
    history = collect_histories(inv)
    residuals = collect_residuals(inv)
    credentials = inv.object(inv.cli / ".credentials.json")
    consistency = []
    for root in inv.desktops:
        saved = inv.object(root / "config.json").get("lastKnownAccountUuid")
        if saved and saved not in inv.synthetic:
            consistency.append(saved == inv.current)
    return {
        "version": 1,
        "current_account_fingerprint": (
            hashlib.sha256(inv.current.encode()).hexdigest() if inv.current else None
        ),
        "saved_desktop_identities_match": all(consistency) if consistency else None,
        "noncurrent_account_hints": len(inv.retired),
        "independent_3p_identities": len(inv.synthetic),
        "credentials": {
            "claude_oauth_present": bool(credentials.get("claudeAiOauth")),
            "oauth_owner_verified": False,
            "mcp_authorizations": len(credentials.get("mcpOAuth", {})),
        },
        "history": history,
        "stores": residuals,
        "findings": inv.issues(inv.findings),
        "protected": dict(sorted(inv.protected.items())),
        "errors": inv.issues(inv.errors),
        "skipped": inv.issues(inv.skipped),
        "coverage": "Local Windows Code/Desktop roots only; no Cookie decryption or remote audit.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only, offline Claude file audit.")
    parser.add_argument("--home", type=Path)
    parser.add_argument("--config-dir", type=Path)
    parser.add_argument("--desktop-root", type=Path, action="append", default=[])
    parser.add_argument("--current-account", help="Explicit local account UUID to preserve.")
    parser.add_argument("--baseline", type=Path, help="Previously saved audit JSON; read only.")
    args = parser.parse_args()
    config_dir = args.config_dir
    if config_dir is None and args.home is None and os.environ.get("CLAUDE_CONFIG_DIR"):
        config_dir = Path(os.environ["CLAUDE_CONFIG_DIR"])
    report = audit(args.home or Path.home(), config_dir, args.desktop_root, args.current_account)
    if args.baseline:
        try:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8-sig"))
            if baseline.get("version") != 1:
                raise ValueError("Unsupported audit baseline")
            report["verification"] = compare_baseline(report, baseline)
        except (OSError, ValueError, KeyError, TypeError):
            report["verification"] = {"matches": False, "error": "invalid_or_unreadable_baseline"}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["errors"]:
        return 2
    return 1 if not report.get("verification", {}).get("matches", True) else 0


if __name__ == "__main__":
    raise SystemExit(main())
