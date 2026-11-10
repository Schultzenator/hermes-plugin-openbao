"""OpenBao / HashiCorp Vault secret source for Hermes Agent.

The plugin deliberately uses only the Python standard library for transport. Hermes
owns environment application, precedence, provenance, and the startup timeout; this
module only resolves configured ``bao://`` references into a FetchResult.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    get_source_environment,
    is_valid_env_name,
)


_REF_RE = re.compile(r"^bao://(?P<mount>[A-Za-z0-9_-]+)/(?P<path>[^#]+?)(?:#(?P<key>[A-Za-z0-9_.-]+))?$")
_DEFAULT_ADDR = "http://127.0.0.1:8200"
_DEFAULT_TOKEN_ENV = "HERMES_OPENBAO_TOKEN"
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def _clean_addr(value: Any) -> str:
    addr = str(value or _DEFAULT_ADDR).strip().rstrip("/")
    parsed = urllib.parse.urlparse(addr)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("vault_addr must be an http(s) URL")
    return addr


def _parse_ref(ref: Any) -> tuple[str, str, str | None] | None:
    if not isinstance(ref, str):
        return None
    match = _REF_RE.fullmatch(ref.strip())
    if not match:
        return None
    path = match.group("path").strip("/")
    if not path or ".." in path.split("/"):
        return None
    return match.group("mount"), path, match.group("key")


def _extract_value(payload: dict[str, Any], key: str | None, version: str) -> str:
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("response has no data object")
    if version == "2":
        data = data.get("data")
        if not isinstance(data, dict):
            raise ValueError("KV v2 response has no nested data object")
    if key is None:
        if len(data) != 1:
            raise ValueError("reference needs #key when a secret contains multiple fields")
        value = next(iter(data.values()))
    else:
        if key not in data:
            raise KeyError(key)
        value = data[key]
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ValueError("secret value is empty")
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    return str(value)


class OpenBaoSource(SecretSource):
    """Mapped ``bao://mount/path#key`` references backed by the Vault API."""

    name = "openbao"
    label = "OpenBao / HashiCorp Vault"
    shape = "mapped"
    scheme = "bao"
    token_env_key = "token_env"
    default_token_env = _DEFAULT_TOKEN_ENV

    def config_schema(self) -> dict[str, dict[str, Any]]:
        return {
            "enabled": {"description": "Enable this source", "default": False},
            "env": {"description": "Map ENV_VAR names to bao://mount/path#key references", "default": {}},
            "vault_addr": {"description": "OpenBao/Vault HTTP(S) address", "default": _DEFAULT_ADDR},
            "kv_mount": {"description": "Optional mount prefix used only as a documentation default", "default": "kv"},
            "namespace": {"description": "Optional Vault Enterprise namespace", "default": ""},
            "version": {"description": "KV API version: auto, 1, or 2", "default": "auto"},
            "token_env": {"description": "Bootstrap token environment variable", "default": _DEFAULT_TOKEN_ENV},
            "timeout_seconds": {"description": "Per-request timeout in seconds", "default": 10},
            "override_existing": {"description": "Resolved values overwrite .env/shell values", "default": False},
        }

    def protected_env_vars(self, cfg: dict) -> frozenset[str]:
        return frozenset({self.token_env(cfg)})

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        cfg = cfg if isinstance(cfg, dict) else {}
        result = FetchResult()
        env_map = cfg.get("env")
        if not isinstance(env_map, dict) or not env_map:
            return result.fail("secrets.openbao.enabled is true but the env: map is empty", ErrorKind.NOT_CONFIGURED)

        try:
            addr = _clean_addr(cfg.get("vault_addr"))
        except ValueError as exc:
            return result.fail(str(exc), ErrorKind.REF_INVALID)
        version = str(cfg.get("version", "auto") or "auto").lower()
        if version not in {"auto", "1", "2"}:
            return result.fail("version must be auto, 1, or 2", ErrorKind.REF_INVALID)
        try:
            timeout = float(cfg.get("timeout_seconds", 10))
        except (TypeError, ValueError):
            timeout = 10.0
        timeout = max(0.1, min(timeout, 120.0))
        namespace = str(cfg.get("namespace", "") or "").strip()

        valid: list[tuple[str, str, tuple[str, str, str | None]]] = []
        for name, ref in env_map.items():
            parsed = _parse_ref(ref)
            if not is_valid_env_name(str(name)):
                result.warnings.append(f"Skipping invalid environment name {name!r}")
            elif parsed is None:
                result.warnings.append(f"Skipping invalid OpenBao reference for {name!r}")
            else:
                valid.append((str(name), str(ref).strip(), parsed))
        if not valid:
            return result.fail("No valid bao:// references configured", ErrorKind.REF_INVALID)

        source_env = get_source_environment()
        token_env = self.token_env(cfg)
        token = str(source_env.get(token_env, "") or "").strip()
        if not token:
            return result.fail(f"{token_env} is not set", ErrorKind.NOT_CONFIGURED)

        for name, ref, (mount, path, key) in valid:
            try:
                payload, used_version = self._read(addr, mount, path, token, namespace, version, timeout)
                result.secrets[name] = _extract_value(payload, key, used_version)
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    return result.fail(f"OpenBao rejected the token (HTTP {exc.code})", ErrorKind.AUTH_FAILED)
                if exc.code == 404:
                    result.warnings.append(f"Secret reference not found: {ref}")
                    continue
                result.warnings.append(f"OpenBao returned HTTP {exc.code} for {ref}")
            except urllib.error.URLError as exc:
                return result.fail(f"Unable to reach OpenBao: {exc.reason}", ErrorKind.NETWORK)
            except TimeoutError:
                return result.fail("OpenBao request timed out", ErrorKind.TIMEOUT)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                result.warnings.append(f"Could not resolve {ref}: {exc}")

        if not result.secrets and not result.warnings:
            return result.fail("OpenBao returned no secrets", ErrorKind.EMPTY_VALUE)
        return result

    @staticmethod
    def _read(addr: str, mount: str, path: str, token: str, namespace: str,
              version: str, timeout: float) -> tuple[dict[str, Any], str]:
        headers = {"X-Vault-Token": token, "Accept": "application/json"}
        if namespace:
            headers["X-Vault-Namespace"] = namespace
        versions = [version] if version != "auto" else ["2", "1"]
        last_404: urllib.error.HTTPError | None = None
        for candidate in versions:
            suffix = f"data/{path}" if candidate == "2" else path
            url = f"{addr}/v1/{urllib.parse.quote(mount, safe='')}/{urllib.parse.quote(suffix, safe='/')}"
            request = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_RESPONSE_BYTES:
                    raise ValueError("response exceeds 4 MiB limit")
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("response is not a JSON object")
                return payload, candidate
            except urllib.error.HTTPError as exc:
                if exc.code == 404 and version == "auto" and candidate == "2":
                    last_404 = exc
                    continue
                raise
        assert last_404 is not None
        raise last_404


def register(ctx: Any) -> None:
    ctx.register_secret_source(OpenBaoSource())


__all__ = ["OpenBaoSource", "register"]
