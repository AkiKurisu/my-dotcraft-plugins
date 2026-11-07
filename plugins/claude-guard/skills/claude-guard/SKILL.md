---
name: claude-guard
description: Audit and remove local Claude Code and Claude Desktop account traces on Windows while preserving current conversations, indexes, checkpoints, and work.
---

# Claude Guard

## Operating rules

- Use local file tools or Python/Node scripts. Keep Claude CLI, Desktop, and browsers closed; make no network requests or authentication calls.
- For read-only requests, print results without creating or changing files.
- Redact account identifiers and email addresses; omit credentials and conversation text from reports.
- Reuse the user's confirmed current account, history-discard policy, backup choice, and storage-reset authorization.

## 1. Inventory

Read the [storage map](references/storage-map.md), then run:

```powershell
python -B "<skill-dir>/scripts/audit.py" --home "<user-home>"
```

The helper reads files and prints JSON. Its default home is the current OS user's directory. `--config-dir` selects another Code configuration root; repeated `--desktop-root` arguments add standard Desktop roots.

Inspect these report sections:

- Saved account consistency and account/organization references.
- All retired account index files, including `.idx`, deletion markers, and extensionless files.
- Protection hashes for current and independent 3P conversations, attachments, indexes, checkpoints, and project memory.
- Old owner fields, identity attachments, and request snapshots inside retained conversations.
- Identifier matches in Local/Session Storage, scan errors, skipped paths, and unattributed transcript counts.

OAuth ownership is reported as unverified. A decoded 3P `ant-did` identifies an independent local profile.

## 2. Clean

Follow the [cleanup steps](references/cleanup.md) within the confirmed scope.

Preserve current conversation bodies and work. Remove old identity metadata separately from retained transcripts. Apply the user's discard and backup choices to old and unattributed history.

Reset authorized `Local Storage` and `Session Storage` directories as complete stores. Preserve saved conversation files, Cookies, Desktop authentication configuration, and work products.

## 3. Verify

Run the audit again, using a prior audit JSON when available:

```powershell
python -B "<skill-dir>/scripts/audit.py" --home "<user-home>" --baseline "<baseline.json>"
```

Compare retained file hashes. For intentional metadata edits, compare message bodies, message IDs, parent relationships, and attachment files separately.

Report removed items, retained conversation integrity, remaining traces, and scan errors. A read-only verification reports findings without applying changes.
