"""
ControlClaw egress proxy — mitmproxy addon.

Implements the security-critical core of the two-box architecture
(docs/plans/mitm-box-security-rollout.md):

  1. Per-tenant egress *rules* (allow / block / require_permission), priority-ordered.
  2. Domain-scoped *credential swap*: the agent box only ever holds `__PLACEHOLDER`s;
     this proxy injects the real secret, and ONLY on requests whose post-TLS host
     matches the credential's match_domain (so a leaked placeholder can't exfiltrate
     a secret off-domain).
  3. Redacted traffic logging: the swapped secret is scrubbed back to its placeholder
     before anything is logged.

v1 loads rules/credentials from JSON files (hot-reloaded on mtime change). On real
boxes these come from the box-key-decrypted store (later parts). Tenant identity is
resolved by source for now; mTLS client-cert identity is a later part.

Dev-only escape hatches (must be OFF in production — enforced server-side at provisioning):
  MITM_DEV_LOG_SECRETS=1        -> do NOT redact secrets from logs (debug swaps).
  MITM_DEV_ALLOW_PLAINTEXT_STORE=1 -> read plaintext secrets from credentials.json.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any

import logging

from mitmproxy import http

log = logging.getLogger("mitm")


# ----- config loading (hot-reloadable) --------------------------------------

RULES_PATH = os.environ.get("MITM_RULES_PATH", "/config/rules.json")
CREDS_PATH = os.environ.get("MITM_CREDENTIALS_PATH", "/config/credentials.json")
GRANTS_PATH = os.environ.get("MITM_GRANTS_PATH", "/config/grants.json")
PENDING_PATH = os.environ.get("MITM_PENDING_PATH", "/config/pending.jsonl")
PERMISSION_TTL = int(os.environ.get("MITM_PERMISSION_TTL", "300"))
LOG_PATH = os.environ.get("MITM_LOG_FILE", "")  # append JSONL here if set
TENANT = os.environ.get("MITM_TENANT", "unknown")

DEV_LOG_SECRETS = os.environ.get("MITM_DEV_LOG_SECRETS") == "1"

DEFAULT_LOCATIONS = ["header:authorization", "header:x-api-key", "header:private-token"]
BLOCK_STATUS = 403
PERMISSION_STATUS = 451


class _Cache:
    def __init__(self, path: str):
        self.path = path
        self.mtime = -1.0
        self.data: list[dict[str, Any]] = []

    def get(self) -> list[dict[str, Any]]:
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return self.data
        if mtime != self.mtime:
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    self.data = json.load(fh)
                self.mtime = mtime
                log.info(f"[mitm] reloaded {self.path} ({len(self.data)} entries)")
            except (OSError, json.JSONDecodeError) as exc:
                log.warning(f"[mitm] failed to load {self.path}: {exc}")
        return self.data


_rules = _Cache(RULES_PATH)
_creds = _Cache(CREDS_PATH)


class _DictCache:
    """Like _Cache but for a JSON object (grants map), hot-reloaded on mtime."""

    def __init__(self, path: str):
        self.path = path
        self.mtime = -1.0
        self.data: dict[str, Any] = {}

    def get(self) -> dict[str, Any]:
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return self.data
        if mtime != self.mtime:
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    self.data = json.load(fh)
                self.mtime = mtime
            except (OSError, json.JSONDecodeError):
                self.data = {}
        return self.data


_grants = _DictCache(GRANTS_PATH)
# permission_ids already recorded as pending this process — avoid duplicate prompts.
_pending_seen: set[str] = set()


def permission_scope(method: str, host: str, path: str) -> str:
    """Stable scope key (query stripped) — a grant unblocks exactly this triple."""
    return f"{method} {host}{path.split('?', 1)[0]}"


def permission_id_for(scope: str) -> str:
    return "perm_" + hashlib.sha256(scope.encode("utf-8")).hexdigest()[:32]


def grant_active(permission_id: str) -> bool:
    grant = _grants.get().get(permission_id)
    if not grant:
        return False
    try:
        return float(grant.get("expires_at", 0)) > time.time()
    except (TypeError, ValueError):
        return False


def record_pending(permission_id: str, record: dict[str, Any]) -> None:
    if permission_id in _pending_seen:
        return
    _pending_seen.add(permission_id)
    try:
        with open(PENDING_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:
        log.warning(f"[mitm] pending write failed: {exc}")


# ----- helpers --------------------------------------------------------------

def host_matches(pattern: str, host: str) -> bool:
    """Exact, full-wildcard (*), or suffix-wildcard (*.example.com) host match."""
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host.lower() == pattern.lower()


def match_rule(host: str, method: str, path: str) -> dict[str, Any] | None:
    """First matching rule by ascending priority; None means default-allow."""
    rules = sorted(_rules.get(), key=lambda r: r.get("priority", 1000))
    for rule in rules:
        if not host_matches(rule.get("match_domain", "*"), host):
            continue
        rm = rule.get("match_method")
        if rm and rm.upper() != method.upper():
            continue
        mp = rule.get("match_path")
        if mp and mp not in path:
            continue
        return rule
    return None


def credentials_for(host: str) -> list[dict[str, Any]]:
    return [c for c in _creds.get() if host_matches(c.get("match_domain", ""), host)]


def _secret_value(cred: dict[str, Any]) -> str | None:
    """Resolve the real secret from the credentials config.

    By design the proxy is the ONE place secrets are plaintext at runtime (it must see
    them to inject them; there is no TEE — the guarantee is containment + detection). On
    real boxes the mitm-agent decrypts the box-key/master-password store and writes this
    config to a RAM-only tmpfs; ControlClaw and the box disk only ever hold ciphertext.
    The proxy therefore trusts `secret` here directly — the security boundary is WHERE the
    file lives (agent-written tmpfs) and that it came from the encrypted store, enforced at
    provisioning, not in proxy code.
    """
    return cred.get("secret")


# ----- swap -----------------------------------------------------------------

def apply_swaps(flow: http.HTTPFlow) -> list[tuple[str, str]]:
    """Replace placeholders with real secrets, domain-scoped. Returns
    [(secret, placeholder)] pairs applied, for later log redaction."""
    host = flow.request.pretty_host
    applied: list[tuple[str, str]] = []

    for cred in credentials_for(host):
        placeholder = cred.get("placeholder")
        secret = _secret_value(cred)
        if not placeholder or not secret:
            continue
        locations = cred.get("locations") or DEFAULT_LOCATIONS
        hit = False

        for loc in locations:
            if loc.startswith("header:"):
                name = loc.split(":", 1)[1]
                for hname in list(flow.request.headers.keys()):
                    if hname.lower() == name.lower():
                        val = flow.request.headers[hname]
                        if placeholder in val:
                            flow.request.headers[hname] = val.replace(placeholder, secret)
                            hit = True
            elif loc == "query":
                for k in list(flow.request.query.keys()):
                    if placeholder in flow.request.query[k]:
                        flow.request.query[k] = flow.request.query[k].replace(placeholder, secret)
                        hit = True
            elif loc == "body":
                try:
                    text = flow.request.get_text(strict=False) or ""
                except ValueError:
                    text = ""
                if placeholder in text:
                    flow.request.set_text(text.replace(placeholder, secret))
                    hit = True

        if hit:
            applied.append((secret, placeholder))
            log.info(f"[mitm] swapped {placeholder} for host={host} (tenant={TENANT})")

    return applied


def redact(text: str, applied: list[tuple[str, str]]) -> str:
    if DEV_LOG_SECRETS:
        return text
    for secret, placeholder in applied:
        if secret:
            text = text.replace(secret, placeholder)
    return text


def _log(record: dict[str, Any]) -> None:
    line = json.dumps(record, ensure_ascii=False)
    log.info(f"[mitm] {line}")
    if LOG_PATH:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            log.warning(f"[mitm] log write failed: {exc}")


# ----- hooks ----------------------------------------------------------------

def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    method = flow.request.method
    path = flow.request.path

    rule = match_rule(host, method, path)
    effect = (rule or {}).get("effect", "allow")
    flow.metadata["cc_effect"] = effect
    flow.metadata["cc_rule"] = (rule or {}).get("name") or (rule or {}).get("match_domain")

    if effect == "block":
        flow.response = http.Response.make(
            BLOCK_STATUS,
            json.dumps({"error": "blocked_by_policy", "host": host, "tenant": TENANT}),
            {"Content-Type": "application/json"},
        )
        _log({"ts": time.time(), "tenant": TENANT, "host": host, "method": method,
              "path": path, "effect": "block", "status": BLOCK_STATUS})
        return

    if effect == "require_permission":
        scope = permission_scope(method, host, path)
        pid = permission_id_for(scope)
        if grant_active(pid):
            # Human approved this exact scope and it hasn't expired — let it through (and swap).
            effect = "allow"
            flow.metadata["cc_effect"] = "allow"
            flow.metadata["cc_granted"] = pid
        else:
            record_pending(pid, {
                "ts": time.time(), "tenant": TENANT, "permission_id": pid,
                "scope": scope, "host": host, "method": method, "path": path.split("?", 1)[0],
            })
            flow.response = http.Response.make(
                PERMISSION_STATUS,
                json.dumps({
                    "permission_id": pid, "reason": "require_permission",
                    "summary": scope, "expires_at": int(time.time()) + PERMISSION_TTL,
                }),
                {"Content-Type": "application/json"},
            )
            _log({"ts": time.time(), "tenant": TENANT, "host": host, "method": method,
                  "path": path, "effect": "require_permission", "permission_id": pid,
                  "status": PERMISSION_STATUS})
            return

    # allow -> swap credentials in
    applied = apply_swaps(flow)
    flow.metadata["cc_applied"] = applied
    redacted_auth = redact(flow.request.headers.get("authorization", ""), applied)
    _log({"ts": time.time(), "tenant": TENANT, "host": host, "method": method,
          "path": path, "effect": "allow", "swapped": [p for _, p in applied],
          "authorization": redacted_auth})


def response(flow: http.HTTPFlow) -> None:
    if flow.metadata.get("cc_effect") not in (None, "allow"):
        return
    applied = flow.metadata.get("cc_applied", [])
    _log({"ts": time.time(), "tenant": TENANT, "host": flow.request.pretty_host,
          "method": flow.request.method, "path": flow.request.path,
          "effect": "allow", "status": flow.response.status_code,
          "swapped": [p for _, p in applied]})
