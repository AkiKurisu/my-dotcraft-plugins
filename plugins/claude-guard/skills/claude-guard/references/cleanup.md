# Local cleanup

## Preserve

1. Confirm the current account from the user's choice and saved local identity. Resolve conflicting local identities with the user.
2. Link current Desktop indexes to transcripts, subagents, tool results, attachments, and checkpoints. Include independently indexed 3P conversations.
3. Record protection hashes for retained files. Preserve shared project memory, source code, Cowork outputs, and external work folders.

## Clean

1. Remove retired account/organization cache entries and nested Desktop preferences. Preserve current account metadata, MCP configuration, project state, and registration values.
2. Remove old configuration copies, temporary files, failed events, logs, and organization model catalogs.
3. Traverse every retired account directory file, including archived indexes, deletion markers, and extensionless files.
4. Delete old and unattributed history according to the user's discard policy. Follow index references to bodies and checkpoints, then remove empty directories.
5. In retained transcripts, remove old identity fields and regenerable identity attachments/request snapshots. Preserve message bodies, message IDs, parent relationships, tool results, and attachment files.
6. Apply the user's credential-removal choice to `claudeAiOauth` separately from `mcpOAuth`. Compare MCP authorization values unchanged.
7. Reset authorized standard Desktop `Local Storage` and `Session Storage` directories. Preserve Cookies, `Local State`, Desktop OAuth configuration, and saved conversations elsewhere.
8. Preserve source folders, Git history, shared machine identifiers, and encryption material. Limit deletion to the identified file roots, without following links.

Apply the confirmed backup policy. Direct deletion without backups creates no history copies or archives. Keep read-only audit results in memory or stdout; save baseline JSON only with write authorization.

## Verify

- Compare hashes for unmodified protection files.
- For sanitized transcripts, compare message bodies, message relationships, and attachments; record expected hash changes.
- Rescan old account directories, configuration copies, organization caches, failed queues, and mixed stores.
- Inspect retained transcripts for old owners, identity context, and request snapshots.
- Compare MCP values and current Desktop authentication files.
- List remaining files, fields, scan errors, and locked targets. Report credential removal as requiring the user's own sign-in.
