# Storage map

Resolve existing paths from the selected user home and installation roots.

| Scope | Location | What to inspect |
|---|---|---|
| Code identity and caches | `~/.claude.json`, custom root's `.claude.json` | Account metadata, account/organization caches, project state, and MCP configuration share one file |
| Code credentials | `<config-root>/.credentials.json` | Separate Claude OAuth from MCP authorizations |
| Configuration copies | Home `.claude.json.backup*`, temporary/corrupt copies, `<config-root>/backups/` | Inspect identity references throughout each copy |
| Code conversations | `<config-root>/projects/` | JSONL transcripts, subagents, tool results, session memory; preserve shared project `memory/` separately |
| Command history and checkpoints | `history.jsonl`, `file-history/` | Associate with retained transcripts by session ID |
| Code runtime history | `telemetry/`, `shell-snapshots/`, `paste-cache/`, `session-env/`, `sessions/` | Failed events, historical environments, and temporary state |
| Code caches | `cache/`, `state/`, `%LOCALAPPDATA%/claude-cli-nodejs/Cache/` | Organization model catalogs, identity caches, debug logs |
| Standard Desktop | `%LOCALAPPDATA%/Claude-Data/<package-family>/` | Current Windows data root |
| Older Desktop | `%APPDATA%/Claude/`, `%LOCALAPPDATA%/Packages/<Claude-family>/LocalCache/Roaming/Claude/` | Existing packaged and migrated data roots |
| Independent 3P mode | `%LOCALAPPDATA%/Claude-3p/` | `ant-did` is a generated identity; assess independent configuration and work separately |
| Desktop conversation indexes | `claude-code-sessions/<account>/<org>/` | Link `cliSessionId`/`sessionId` to bodies; include archived indexes, deletion markers, and extensionless files |
| Desktop work | `local-agent-mode-sessions/`, `git-worktrees.json`, external work folders | Preserve user outputs, attachments, and source code |
| Desktop identity preferences | `ccd-session-presets.json`, `claude_desktop_config.json`, `ant-device-registry.json`, `config.json` | Remove account-scoped entries while preserving current authentication, registration values, and required settings |
| Desktop statistics and caches | `plan-usage-history.json`, organization extension caches, `sentry/`, logs | Inspect account and organization references |
| Embedded web state | `Local Storage/`, `Session Storage/`, `IndexedDB/` | Identity hints, analytics queues, navigation, and UI preferences |
| Separate authentication storage | `Network/Cookies`, `Local State`, OAuth caches in Desktop `config.json` | Preserve during web-state resets |

## Additional entry points

Inspect local configuration and registration metadata for alternate roots, editor environments, shell startup entries, account switchers, synchronization, scheduled tasks, WSL, and remote configurations. Report variable names and paths.

The helper covers local Windows Code/Desktop roots and explicitly supplied roots. Cookie decryption, encrypted OAuth, full browser profiles, WSL, and remote machines are outside its scan scope.
