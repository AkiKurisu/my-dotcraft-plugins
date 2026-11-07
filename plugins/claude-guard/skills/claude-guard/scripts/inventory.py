from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path

UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)
UUID_TEXT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)


class Inventory:
    def __init__(self, home: Path, config_dir: Path | None = None,
                 desktop_roots: list[Path] | None = None, current: str | None = None):
        self.home = home.resolve()
        self.cli = (config_dir or self.home / ".claude").resolve()
        self.errors: list[dict] = []
        self.skipped: list[dict] = []
        candidate = self.cli / ".claude.json"
        self.config_path = (
            candidate if self.cli != self.home / ".claude" and candidate.is_file()
            else self.home / ".claude.json"
        )
        self.config = self.object(self.config_path)
        account = self.config.get("oauthAccount", {})
        self.current = current or account.get("accountUuid")
        self.email = account.get("emailAddress")
        self.org = account.get("organizationUuid")
        self.local = self.home / "AppData" / "Local"
        self.roaming = self.home / "AppData" / "Roaming"
        self.third_party = [
            self.local / "Claude-3p", self.roaming / "Claude-3p"
        ]
        self.synthetic: set[str] = set()
        for root in self.third_party:
            device = root / "ant-did"
            if device.is_file():
                try:
                    value = base64.b64decode(device.read_bytes()).decode().strip()
                    if UUID.fullmatch(value):
                        self.synthetic.add(value)
                except (OSError, ValueError, UnicodeError):
                    self.errors.append({"path": device, "kind": "unreadable_device_id"})
        roots = [self.roaming / "Claude"]
        roots += self.directories(self.local / "Claude-Data")
        for package in self.directories(self.local / "Packages"):
            if package.name.lower().startswith("claude"):
                roots.append(package / "LocalCache" / "Roaming" / "Claude")
        roots += desktop_roots or []
        self.desktops = list(dict.fromkeys(p for p in roots if p.is_dir()))
        self.retired: set[str] = set()
        self.retired_orgs: set[str] = set()
        self.current_orgs = {self.org} if self.org else set()
        self.indexes: list[tuple[Path, str, dict]] = []
        self.account_files: list[Path] = []
        self.session_ids: set[str] = set()
        self.protected: dict[str, str] = {}
        self.findings: list[dict] = []
        if not self.current:
            self.errors.append({"path": self.config_path, "kind": "current_account_missing"})
        self.collect_accounts()

    @staticmethod
    def linked(path: Path) -> bool:
        try:
            return path.is_symlink() or bool(
                getattr(path.lstat(), "st_file_attributes", 0) & 0x400
            )
        except OSError:
            return False

    def directories(self, root: Path) -> list[Path]:
        if not root.exists():
            return []
        if self.linked(root):
            self.skipped.append({"path": root, "kind": "linked_directory"})
            return []
        try:
            return [p for p in root.iterdir() if p.is_dir() and not self.linked(p)]
        except OSError:
            self.errors.append({"path": root, "kind": "unreadable_directory"})
            return []

    def files(self, root: Path) -> list[Path]:
        if not root.exists():
            return []
        if self.linked(root):
            self.skipped.append({"path": root, "kind": "linked_directory"})
            return []
        result = []

        def failed(error):
            self.errors.append({"path": Path(error.filename or root), "kind": "unreadable_directory"})

        for directory, dirs, names in os.walk(root, followlinks=False, onerror=failed):
            dirs[:] = [d for d in dirs if not self.linked(Path(directory) / d)]
            result.extend(Path(directory) / n for n in names
                          if not self.linked(Path(directory) / n))
        return result

    def object(self, path: Path) -> dict:
        data = self.json(path)
        return data if isinstance(data, dict) else {}

    def json(self, path: Path):
        if not path.exists():
            return {}
        if self.linked(path):
            self.skipped.append({"path": path, "kind": "linked_file"})
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError, UnicodeError):
            self.errors.append({"path": path, "kind": "unreadable_json"})
            return {}

    def collect_accounts(self):
        for root in self.desktops:
            saved = self.object(root / "config.json").get("lastKnownAccountUuid")
            if saved and self.current and saved != self.current and saved not in self.synthetic:
                self.findings.append({"path": root / "config.json",
                                      "kind": "desktop_saved_identity_differs"})
            candidates = set(self.object(root / "ant-device-registry.json"))
            candidates.update(self.object(root / "ccd-session-presets.json").get("byAccount", {}))
            index_root = root / "claude-code-sessions"
            candidates.update(p.name for p in self.directories(index_root))
            self.retired.update(x for x in candidates if UUID.fullmatch(x)
                                and x != self.current and x not in self.synthetic)
            for bucket in self.directories(index_root):
                owner = "current" if self.current and bucket.name == self.current else (
                    "independent3p" if bucket.name in self.synthetic else "retired"
                    if bucket.name in self.retired else "unattributed"
                )
                for organization in self.directories(bucket):
                    if UUID.fullmatch(organization.name):
                        if owner == "current":
                            self.current_orgs.add(organization.name)
                        elif owner == "retired":
                            self.retired_orgs.add(organization.name)
                for path in self.files(bucket):
                    if owner == "retired":
                        self.account_files.append(path)
                    elif owner in ("current", "independent3p"):
                        self.protect(path)
                    if path.suffix == ".json":
                        record = self.object(path)
                        self.indexes.append((path, owner, record))
                        if owner in ("current", "independent3p"):
                            self.session_ids.update(
                                v for k in ("cliSessionId", "sessionId")
                                if isinstance(v := record.get(k), str)
                            )
        for root in self.third_party:
            for path in self.files(root / "claude-code-sessions"):
                if path.suffix == ".json":
                    record = self.object(path)
                    self.session_ids.update(
                        v for k in ("cliSessionId", "sessionId")
                        if isinstance(v := record.get(k), str)
                    )
        self.retired_orgs -= self.current_orgs

    def label(self, path: Path) -> str:
        text = str(path)
        for root, name in ((self.home, "<home>"), (self.cli, "<config>")):
            try:
                text = f"{name}/{path.relative_to(root).as_posix()}"
                break
            except ValueError:
                pass
        text = text.replace(self.current, "<current-account>") if self.current else text
        for value in self.retired:
            text = text.replace(value, f"<retired-{hashlib.sha256(value.encode()).hexdigest()[:8]}>")
        text = UUID_TEXT.sub(
            lambda match: f"<id-{hashlib.sha256(match[0].encode()).hexdigest()[:12]}>", text
        )
        text = re.sub(r"sk-[A-Za-z0-9_-]+", "<credential>", text)
        return re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "<email>", text)

    def protect(self, path: Path):
        try:
            if self.linked(path):
                self.skipped.append({"path": path, "kind": "linked_file"})
                return
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            self.protected[self.label(path)] = digest.hexdigest()
        except OSError:
            self.errors.append({"path": path, "kind": "unreadable_protected_file"})

    def identity_hits(self, path: Path) -> dict | None:
        try:
            if path.stat().st_size > 64 * 1024 * 1024:
                self.skipped.append({"path": path, "kind": "large_binary_or_cache"})
                return None
            raw = path.read_bytes()
            accounts = sum(value.encode() in raw for value in self.retired)
            orgs = sum(value.encode() in raw for value in self.retired_orgs)
            return {"accounts": accounts, "organizations": orgs}
        except OSError:
            self.errors.append({"path": path, "kind": "unreadable_file"})
            return None

    def issues(self, values: list[dict]) -> list[dict]:
        return [{**v, "path": self.label(v["path"])} for v in values]
