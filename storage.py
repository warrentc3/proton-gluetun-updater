"""
Persistence layer: filter configuration and server list cache.

_Config is the YAML serialisation shape — it belongs to storage, not the domain
model layer. All file I/O for config.yaml and the serverlist cache lives here.
"""
import dataclasses
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import yaml

from transform import transform, _validate_servers_json


# ---------------------------------------------------------------------------
# Filter configuration
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class _Config:
    """
    Filter and mode configuration, persisted to config.yaml.

    This is the YAML serialisation shape for the user's choices. It is a
    storage artefact, not a domain model — its fields are the persisted
    representation of what the user has configured.
    """
    ip6: str = "exclude"          # include | exclude | only
    secure_core: str = "include"  # include | exclude | only
    tor: str = "include"          # include | exclude | only
    free_tier: str = "include"    # include | exclude | only
    gluetun_json: str = "none"    # none | replace | update
    auto_fetch: str = "off"       # off | on


_FILTER_DEFAULTS: dict[str, str] = {
    "ip6": "exclude",
    "secure_core": "include",
    "tor": "include",
    "free_tier": "include",
    "gluetun_json": "none",
    "auto_fetch": "off",
}

_FILTER_CHOICES: dict[str, tuple[str, ...]] = {
    "ip6": ("include", "exclude", "only"),
    "secure_core": ("include", "exclude", "only"),
    "tor": ("include", "exclude", "only"),
    "free_tier": ("include", "exclude", "only"),
    "gluetun_json": ("none", "replace", "update"),
    "auto_fetch": ("off", "on"),
}

_CACHE_MAX_AGE_SECONDS = 12 * 3600  # 12 hours


# ---------------------------------------------------------------------------
# Atomic file write
# ---------------------------------------------------------------------------

def _atomic_write(path: str, content: str) -> None:
    """Write content to path atomically via a temp file + os.replace()."""
    dir_path = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

def _save_filter_config(config_file: Path, values: dict) -> None:
    """Write filter values to config.yaml with a human-readable header comment."""
    header = (
        "# ProtonVPN Gluetun Updater — filter configuration\n"
        "# ip6, secure_core, tor, free_tier: include | exclude | only\n"
        "# gluetun_json: none | replace | update\n"
        "# auto_fetch: off (run once, fetch manually) | on (recurring fetch with session keep-alive)\n"
    )
    with open(config_file, "w", encoding="utf-8") as f:
        f.write(header)
        yaml.dump(values, f, default_flow_style=False, sort_keys=True, allow_unicode=True)


def _load_or_create_filter_config(cache_dir: Path, env_defaults: dict) -> dict:
    """
    Load STORAGE_FILEPATH/proton/config.yaml. If it does not exist, create it
    seeded from env_defaults (parsed from environment variables). Invalid or
    missing keys are filled from _FILTER_DEFAULTS and the file is rewritten.
    Returns a fully-validated dict of filter values.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    config_file = cache_dir / "config.yaml"

    if not config_file.exists():
        values = {k: env_defaults.get(k, _FILTER_DEFAULTS[k]) for k in _FILTER_DEFAULTS}
        _save_filter_config(config_file, values)
        print(f"Created filter config: {config_file}", file=sys.stderr)
        return values

    try:
        with open(config_file, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Warning: Could not read {config_file}: {e} — using defaults.", file=sys.stderr)
        return dict(_FILTER_DEFAULTS)

    values: dict[str, str] = {}
    needs_rewrite = False
    for key, default in _FILTER_DEFAULTS.items():
        raw_val = str(raw.get(key, default)).lower()
        if raw_val not in _FILTER_CHOICES[key]:
            print(
                f"Warning: Invalid config.yaml value for '{key}': '{raw_val}'. "
                f"Using '{default}'.",
                file=sys.stderr,
            )
            raw_val = default
            needs_rewrite = True
        values[key] = raw_val

    # Remove unknown keys from the file
    if needs_rewrite or set(raw.keys()) - set(_FILTER_DEFAULTS):
        _save_filter_config(config_file, values)

    return values


# ---------------------------------------------------------------------------
# Server list cache
# ---------------------------------------------------------------------------

def _load_cached_api(storage_path: str) -> tuple[dict, Path] | None:
    """
    Return (api_data, path) for the most-recent serverlist.*.json that is
    younger than _CACHE_MAX_AGE_SECONDS, or None if no such file exists.
    """
    cache_dir = Path(storage_path) / "proton"
    candidates = sorted(cache_dir.glob("serverlist.*.json"), reverse=True)
    now = time.time()
    for path in candidates:
        try:
            ts = int(path.stem.split(".", 1)[1])
        except (IndexError, ValueError):
            continue
        age = now - ts
        if age < _CACHE_MAX_AGE_SECONDS:
            return json.loads(path.read_text(encoding="utf-8")), path
    return None


def _load_latest_api_cache(storage_path: str) -> tuple[dict, Path] | None:
    """
    Return (api_data, path) for the most-recent serverlist.*.json, regardless
    of age. Used when re-applying filter config without fetching fresh data.
    """
    cache_dir = Path(storage_path) / "proton"
    candidates = sorted(cache_dir.glob("serverlist.*.json"), reverse=True)
    for path in candidates:
        try:
            int(path.stem.split(".", 1)[1])  # validate timestamp in filename
        except (IndexError, ValueError):
            continue
        try:
            return json.loads(path.read_text(encoding="utf-8")), path
        except Exception:
            continue
    return None


def _save_api_cache(api_data: dict, storage_path: str) -> None:
    """
    Save the raw API response to STORAGE_FILEPATH/proton/, keeping the
    three most recent files named by epoch timestamp (oldest deleted).
    """
    cache_dir = Path(storage_path) / "proton"
    cache_dir.mkdir(parents=True, exist_ok=True)

    epoch_time = int(time.time())
    dest = cache_dir / f"serverlist.{epoch_time}.json"
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(api_data, f, indent=2)
    print(f"Saved API response to {dest}", file=sys.stderr)

    # Rotate: keep only the 3 most recent files
    existing = sorted(cache_dir.glob("serverlist.*.json"))
    for old in existing[:-3]:
        old.unlink()
        print(f"Rotated out old cache file {old.name}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Reprocess from cache
# ---------------------------------------------------------------------------

def _reprocess_from_cache(
    storage_path: str,
    config: "_Config",
    status: "object | None" = None,
) -> bool:
    """
    Load the most-recent cached server list (ignoring age), re-run transform
    with config, write output files, and update status stats.
    Returns True on success, False when no cache file is available.
    """
    cached = _load_latest_api_cache(storage_path)
    if cached is None:
        return False
    api_data, cache_path = cached
    result, transform_stats = transform(
        api_data,
        ipv6_filter=config.ip6,
        secure_core_filter=config.secure_core,
        tor_filter=config.tor,
        free_tier_filter=config.free_tier,
    )
    output = json.dumps(result, indent=2)
    count = len(result["protonvpn"]["servers"])
    output_file = os.path.join(storage_path, "servers-proton.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    _atomic_write(output_file, output)
    print(f"Apply: {count} server entries written to {output_file} (from {cache_path.name})", file=sys.stderr)
    if config.gluetun_json in ("replace", "update"):
        servers_json_file = os.path.join(storage_path, "servers.json")
        if config.gluetun_json == "replace":
            _validate_servers_json(result, "servers-proton.json output")
            _atomic_write(servers_json_file, output)
            print(f"Apply: replaced {servers_json_file}", file=sys.stderr)
        else:  # update
            try:
                with open(servers_json_file, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except FileNotFoundError:
                existing = {"version": 1}
            except json.JSONDecodeError as exc:
                print(f"Apply: could not parse {servers_json_file}: {exc} — creating fresh.", file=sys.stderr)
                existing = {"version": 1}
            _validate_servers_json(existing, f"existing {servers_json_file}")
            _validate_servers_json(result, "servers-proton.json output")
            existing["protonvpn"] = result["protonvpn"]
            merged = json.dumps(existing, indent=2)
            _validate_servers_json(json.loads(merged), f"merged {servers_json_file}")
            _atomic_write(servers_json_file, merged)
            print(f"Apply: updated protonvpn servers in {servers_json_file}", file=sys.stderr)
    if status is not None:
        status.last_server_count = count
        status.last_stats = transform_stats
    return True
