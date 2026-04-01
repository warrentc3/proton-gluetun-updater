#!/usr/bin/env python3
"""
Fetch the Proton VPN server list and export it in Gluetun custom
provider format (servers-proton.json).

Authenticates directly against the Proton API using SRP.

Environment variables:
    PROTON_USERNAME   Proton account username (or use Docker secret: proton_username)
    PROTON_PASSWORD   Proton account password (or use Docker secret: proton_password)
    STORAGE_FILEPATH  Storage directory path (required, output file: servers-proton.json). Can also be set to a file path (e.g. /gluetun/servers.json) — the parent directory is inferred automatically.
    IP6               IPv6 address behavior: include (add IPv6 IPs when available), exclude (default, strip IPv6 from output), or only (filter to servers with IPv6 and include their IPs). IPv6 data is always fetched from the API.
    SECURE_CORE       Filter secure_core servers: include (default), exclude, or only
    TOR               Filter TOR servers: include (default), exclude, or only
    FREE_TIER         Filter free tier servers: include (default), exclude, or only
    REPLACE_GLUETUN_SERVERS_JSON  Deprecated. Use GLUETUN_SERVERS_JSON=replace instead.
    GLUETUN_SERVERS_JSON  How to update Gluetun's servers.json: none (default, don't touch it), replace (overwrite entirely with ProtonVPN-only content), or update (merge ProtonVPN servers into existing file, preserving all other providers)
    WEB_HOST          Web dashboard bind address (default: 127.0.0.1 for localhost-only; use 0.0.0.0 to expose publicly)
    WEB_PORT          Web dashboard port (default: 8080)
    DEFER_AUTH        Skip authentication on startup — go straight to idle with the dashboard serving. Auth happens on first manual Fetch Now. Useful for testing Dockerfile changes, dependency updates, or dashboard tweaks without hitting the Proton API. Set to 1/true/yes to enable. (default: off)
"""
import asyncio
import json
import os
import random
import signal
import sys
import time
from pathlib import Path

from proton.session.exceptions import ProtonAPIAuthenticationNeeded

from protonvpn import (
    _TfaBroker,
    _TfaTimeoutError,
    _authenticate,
    _fetch_server_list,
    _read_secret,
)
from state import _Status, _TfaState
from storage import (
    _CACHE_MAX_AGE_SECONDS,
    _Config,
    _atomic_write,
    _load_cached_api,
    _load_or_create_filter_config,
    _save_api_cache,
)
from transform import _validate_servers_json, transform
from web import _start_web_server


async def run_update(
    session,
    storage_path,
    ipv6_filter,
    secure_core_filter,
    tor_filter,
    free_tier_filter,
    gluetun_json_mode,
    *,
    status: _Status | None = None,
    broker: _TfaBroker | None = None,
    force_fetch: bool = False,
    stop_event: asyncio.Event | None = None,
    tfa_timeout: float = 900,
):
    """Execute a single update cycle."""
    if status is not None:
        status.state = "running"
        status.last_error = None
        status.next_run_time = None

    cached = _load_cached_api(storage_path)
    fetched_fresh = False
    if cached is not None and not force_fetch:
        api_data, cache_path = cached
        age_min = int((time.time() - int(cache_path.stem.split(".", 1)[1])) / 60)
        print(f"Using cached server list ({age_min} min old): {cache_path.name}", file=sys.stderr)
    else:
        if force_fetch:
            print("Force-fetch requested — bypassing cache.", file=sys.stderr)
        api_data = await _fetch_server_list(
            session, broker=broker, status=status,
            stop_event=stop_event, tfa_timeout=tfa_timeout,
        )
        _save_api_cache(api_data, storage_path)
        fetched_fresh = True

    result, transform_stats = transform(
        api_data,
        ipv6_filter=ipv6_filter,
        secure_core_filter=secure_core_filter,
        tor_filter=tor_filter,
        free_tier_filter=free_tier_filter,
    )

    output = json.dumps(result, indent=2)
    count = len(result["protonvpn"]["servers"])

    output_file = os.path.join(storage_path, "servers-proton.json")

    filters = []
    if secure_core_filter != "include":
        filters.append(f"secure_core={secure_core_filter}")
    if tor_filter != "include":
        filters.append(f"tor={tor_filter}")
    if free_tier_filter != "include":
        filters.append(f"free_tier={free_tier_filter}")
    if ipv6_filter != "exclude":
        filters.append(f"ipv6={ipv6_filter}")
    filter_info = f" ({', '.join(filters)})" if filters else ""

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    _atomic_write(output_file, output)
    print(f"\n{count} server entries written to {output_file}{filter_info}", file=sys.stderr)

    if gluetun_json_mode in ("replace", "update"):
        servers_json_file = os.path.join(storage_path, "servers.json")
        if gluetun_json_mode == "replace":
            _validate_servers_json(result, "servers-proton.json output")
            _atomic_write(servers_json_file, output)
            print(f"Replaced {servers_json_file} with servers-proton.json content", file=sys.stderr)
        else:  # update
            try:
                with open(servers_json_file, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except FileNotFoundError:
                existing = {"version": 1}
            except json.JSONDecodeError as e:
                print(f"Warning: Could not parse existing {servers_json_file}: {e}. Creating fresh.", file=sys.stderr)
                existing = {"version": 1}
            _validate_servers_json(existing, f"existing {servers_json_file}")
            _validate_servers_json(result, "servers-proton.json output")
            existing["protonvpn"] = result["protonvpn"]
            merged = json.dumps(existing, indent=2)
            _validate_servers_json(json.loads(merged), f"merged {servers_json_file}")
            _atomic_write(servers_json_file, merged)
            print(f"Updated protonvpn servers in {servers_json_file}", file=sys.stderr)

    if status is not None:
        if fetched_fresh:
            status.last_run_time = time.time()
            status.run_count += 1
        status.last_server_count = count
        status.last_stats = transform_stats


async def _wait_for_wakeup(
    stop_event: asyncio.Event,
    force_fetch: asyncio.Event,
    timeout: float | None = None,
) -> None:
    """
    Wait until stop_event or force_fetch fires, or timeout expires.
    If timeout is None, wait indefinitely (idle mode).
    Polls every 30 s so the event loop stays responsive.
    """
    deadline = time.time() + timeout if timeout is not None else None
    while not stop_event.is_set() and not force_fetch.is_set():
        if deadline is not None:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            wait_time = min(remaining, 30)
        else:
            wait_time = 30
        wait_tasks = [
            asyncio.create_task(stop_event.wait()),
            asyncio.create_task(force_fetch.wait()),
        ]
        done, pending = await asyncio.wait(
            wait_tasks,
            timeout=wait_time,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if done:
            break


async def main():
    # Resolve credentials without interactive prompts (env var → Docker secret)
    username = os.environ.get("PROTON_USERNAME") or _read_secret("proton_username")
    password = os.environ.get("PROTON_PASSWORD") or _read_secret("proton_password")

    # Parse STORAGE_FILEPATH (directory for output file) - REQUIRED
    storage_path = os.environ.get("STORAGE_FILEPATH")
    if not storage_path:
        print("Error: STORAGE_FILEPATH environment variable is required.", file=sys.stderr)
        sys.exit(1)

    # If STORAGE_FILEPATH points to a file (e.g. /gluetun/servers.json), infer the
    # parent directory so the updater works correctly when mounted in the same stack
    # as Gluetun without requiring the user to strip the filename from the path.
    _storage_p = Path(storage_path)
    if _storage_p.suffix:
        _inferred = str(_storage_p.parent)
        print(
            f"Info: STORAGE_FILEPATH='{storage_path}' looks like a file path — "
            f"using parent directory '{_inferred}' as storage path.",
            file=sys.stderr,
        )
        storage_path = _inferred

    # Build seed defaults from env vars (applied only when config.yaml does not yet exist)
    _three_way = ("include", "exclude", "only")

    def _env_three(env_name: str, default: str) -> str:
        v = os.environ.get(env_name, default).lower()
        return v if v in _three_way else default

    gluetun_json_env = os.environ.get("GLUETUN_SERVERS_JSON", "").lower()
    if not gluetun_json_env:
        legacy = os.environ.get("REPLACE_GLUETUN_SERVERS_JSON", "false").lower()
        gluetun_json_seed = "replace" if legacy in ("1", "true", "yes") else "none"
        if gluetun_json_seed == "replace":
            print("Warning: REPLACE_GLUETUN_SERVERS_JSON is deprecated. Use GLUETUN_SERVERS_JSON=replace instead.", file=sys.stderr)
    else:
        if gluetun_json_env not in ("none", "replace", "update"):
            print(f"Warning: Invalid GLUETUN_SERVERS_JSON value '{gluetun_json_env}'. Using 'none'.", file=sys.stderr)
        gluetun_json_seed = gluetun_json_env if gluetun_json_env in ("none", "replace", "update") else "none"

    auto_fetch_env = os.environ.get("AUTO_FETCH", "off").lower()
    if auto_fetch_env not in ("off", "on"):
        print(f"Warning: Invalid AUTO_FETCH value '{auto_fetch_env}'. Using 'off'.", file=sys.stderr)
        auto_fetch_env = "off"

    env_defaults = {
        "ip6": _env_three("IP6", "exclude"),
        "secure_core": _env_three("SECURE_CORE", "include"),
        "tor": _env_three("TOR", "include"),
        "free_tier": _env_three("FREE_TIER", "include"),
        "gluetun_json": gluetun_json_seed,
        "auto_fetch": auto_fetch_env,
    }

    # Load (or create) the persistent filter config from STORAGE_FILEPATH/proton/config.yaml
    cache_dir = Path(storage_path) / "proton"
    filter_config = _load_or_create_filter_config(cache_dir, env_defaults)

    ipv6_filter = filter_config["ip6"]
    secure_core_filter = filter_config["secure_core"]
    tor_filter = filter_config["tor"]
    free_tier_filter = filter_config["free_tier"]
    gluetun_json_mode = filter_config["gluetun_json"]

    # Parse WEB_HOST (default 127.0.0.1 for security)
    web_host = os.environ.get("WEB_HOST", "127.0.0.1")

    # Parse WEB_PORT (default 8080)
    web_port_env = os.environ.get("WEB_PORT", "8080")
    try:
        web_port = int(web_port_env)
    except ValueError:
        print(f"Warning: Invalid WEB_PORT value '{web_port_env}'. Using 8080.", file=sys.stderr)
        web_port = 8080

    defer_auth = os.environ.get("DEFER_AUTH", "").lower() in ("1", "true", "yes")

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    runtime = _Status(
        config=_Config(
            ip6=ipv6_filter,
            secure_core=secure_core_filter,
            tor=tor_filter,
            free_tier=free_tier_filter,
            gluetun_json=gluetun_json_mode,
            auto_fetch=filter_config["auto_fetch"],
        ),
        cache_dir=cache_dir,
    )
    broker = _TfaBroker()
    web_server = await _start_web_server(web_host, web_port, runtime, broker)

    # Check credentials now that the web server is up so errors are visible on the dashboard
    if not defer_auth:
        _missing = []
        if not username:
            _missing.append("PROTON_USERNAME (env var or Docker secret: proton_username)")
        if not password:
            _missing.append("PROTON_PASSWORD (env var or Docker secret: proton_password)")
        if _missing:
            msg = (
                "\u26a0 Missing required credentials: " + ", ".join(_missing) + ". "
                "Restart the container after setting these environment variables or Docker secrets."
            )
            print(f"Error: {msg}", file=sys.stderr)
            runtime.state = "error"
            runtime.last_error = msg
            runtime.configuration_error = True
            await stop_event.wait()
            runtime.state = "shutting_down"
            web_server.close()
            await web_server.wait_closed()
            return

    if defer_auth:
        session = None
        runtime.state = "idle"
        runtime.next_run_time = None
        print("DEFER_AUTH: skipping startup authentication — use Fetch Now to connect.", file=sys.stderr)
    else:
        runtime.state = "authenticating"
        try:
            session = await _authenticate(username, password)
        except Exception as auth_err:
            runtime.state = "error"
            runtime.last_error = f"Authentication failed: {auth_err}"
            runtime.configuration_error = True
            await stop_event.wait()
            runtime.state = "shutting_down"
            web_server.close()
            await web_server.wait_closed()
            return

    first_run = True
    try:
        while not stop_event.is_set():
            force = runtime.force_fetch.is_set()
            runtime.force_fetch.clear()

            # Deferred auth: authenticate on first manual trigger
            if force and session is None:
                if not username or not password:
                    runtime.state = "error"
                    runtime.last_error = (
                        "Missing credentials \u2014 set PROTON_USERNAME and "
                        "PROTON_PASSWORD, then restart."
                    )
                    runtime.configuration_error = True
                    continue
                runtime.state = "authenticating"
                try:
                    session = await _authenticate(username, password)
                except Exception as auth_err:
                    runtime.state = "error"
                    runtime.last_error = f"Authentication failed: {auth_err}"
                    runtime.tfa.reauth_failures += 1
                    print(f"Error: deferred authentication failed: {auth_err}", file=sys.stderr)
                    await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=300)
                    continue
                runtime.tfa.reauth_failures = 0
                print("Deferred authentication successful.", file=sys.stderr)
                # Fall through to normal force-fetch handling

            # Still waiting for first Fetch Now (deferred auth not yet triggered)
            if session is None:
                runtime.state = "idle"
                runtime.next_run_time = None
                await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=None)
                continue

            # When 2FA intervention is needed and this is an auto-fetch cycle
            # (not a manual "Fetch Now"), skip the fetch entirely — don't
            # repeatedly create and abandon partial sessions on Proton's infra.
            if (
                runtime.tfa.needs_intervention
                and runtime.config.auto_fetch == "on"
                and not force
            ):
                print(
                    "Skipping scheduled fetch: re-auth requires 2FA, "
                    "manual intervention needed. Use 'Fetch Now'.",
                    file=sys.stderr,
                )
            elif force and runtime.tfa.needs_intervention:
                # User clicked "Fetch Now" — clear intervention flag, fresh auth
                # with the generous startup-style 2FA window (15 min).
                runtime.tfa.needs_intervention = False
                runtime.state = "authenticating"
                try:
                    await session.async_logout()
                except Exception:
                    pass
                try:
                    session = await _authenticate(username, password)
                except Exception as auth_err:
                    runtime.state = "error"
                    runtime.last_error = f"Re-authentication failed: {auth_err}"
                    runtime.tfa.reauth_failures += 1
                    print(f"Error: re-authentication failed: {auth_err}", file=sys.stderr)
                    await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=300)
                    continue
                runtime.tfa.reauth_failures = 0
                try:
                    await run_update(
                        session, storage_path,
                        runtime.config.ip6, runtime.config.secure_core,
                        runtime.config.tor, runtime.config.free_tier,
                        runtime.config.gluetun_json,
                        status=runtime, broker=broker,
                        force_fetch=True,
                        stop_event=stop_event,
                        tfa_timeout=900,  # 15 min — user is actively intervening
                    )
                except _TfaTimeoutError as tfa_err:
                    runtime.state = "error"
                    runtime.last_error = str(tfa_err)
                    runtime.tfa.needs_intervention = True
                    runtime.tfa.reauth_failures += 1
                    print(f"2FA timeout: {tfa_err}", file=sys.stderr)
                    await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=300)
                    continue
                except Exception as e:
                    runtime.state = "error"
                    runtime.last_error = str(e)
                    print(f"\nError during update: {e}", file=sys.stderr)
                    await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=300)
                    continue
            # On the very first iteration, skip the update if the cached server
            # list is still fresh (< 12 h). The user can trigger a fetch manually
            # via the "Fetch Now" button. After the first sleep we always fetch.
            elif first_run and not force and (cached_result := _load_cached_api(storage_path)) is not None:
                cache_ts = int(cached_result[1].stem.split(".", 1)[1])
                age_min = int((time.time() - cache_ts) / 60)
                print(
                    f"Startup: cache is {age_min} min old (< 12 h) — skipping initial fetch. "
                    "Use 'Fetch Now' to pull a fresh server list.",
                    file=sys.stderr,
                )
                # Populate last-run stats from the cached API data + existing output file
                output_file = os.path.join(storage_path, "servers-proton.json")
                try:
                    _, startup_stats = transform(
                        cached_result[0],
                        ipv6_filter=runtime.config.ip6,
                        secure_core_filter=runtime.config.secure_core,
                        tor_filter=runtime.config.tor,
                        free_tier_filter=runtime.config.free_tier,
                    )
                    with open(output_file, encoding="utf-8") as _f:
                        _existing = json.load(_f)
                    runtime.last_server_count = len(_existing.get("protonvpn", {}).get("servers", []))
                    runtime.last_stats = startup_stats
                    runtime.last_run_time = float(cache_ts)
                except Exception as _e:
                    print(f"Startup: could not populate stats from cache: {_e}", file=sys.stderr)
                first_run = False
            else:
                _tfa_timeout = 900 if first_run else 300  # 15 min startup, 5 min re-auth
                first_run = False
                try:
                    await run_update(
                        session, storage_path,
                        runtime.config.ip6, runtime.config.secure_core,
                        runtime.config.tor, runtime.config.free_tier,
                        runtime.config.gluetun_json,
                        status=runtime, broker=broker,
                        force_fetch=force,
                        stop_event=stop_event,
                        tfa_timeout=_tfa_timeout,
                    )
                except ProtonAPIAuthenticationNeeded:
                    print(
                        "\nSession expired (refresh token invalid). "
                        "Re-authenticating...",
                        file=sys.stderr,
                    )
                    runtime.state = "authenticating"
                    try:
                        await session.async_logout()
                    except Exception:
                        pass
                    try:
                        session = await _authenticate(username, password)
                    except Exception as auth_err:
                        runtime.state = "error"
                        runtime.last_error = f"Re-authentication failed: {auth_err}"
                        runtime.tfa.reauth_failures += 1
                        print(f"Error: re-authentication failed: {auth_err}", file=sys.stderr)
                        print("Waiting 5 minutes before retry...", file=sys.stderr)
                        await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=300)
                        continue
                    runtime.tfa.reauth_failures = 0
                    print("Re-authentication successful. Retrying fetch...", file=sys.stderr)
                    try:
                        await run_update(
                            session, storage_path,
                            runtime.config.ip6, runtime.config.secure_core,
                            runtime.config.tor, runtime.config.free_tier,
                            runtime.config.gluetun_json,
                            status=runtime, broker=broker,
                            force_fetch=True,
                            stop_event=stop_event,
                            tfa_timeout=300,  # 5 min — re-auth context, nobody's watching
                        )
                    except _TfaTimeoutError as tfa_err:
                        runtime.state = "error"
                        runtime.last_error = str(tfa_err)
                        runtime.tfa.needs_intervention = True
                        runtime.tfa.reauth_failures += 1
                        print(f"2FA timeout during re-auth: {tfa_err}", file=sys.stderr)
                        await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=300)
                        continue
                    except Exception as retry_err:
                        runtime.state = "error"
                        runtime.last_error = str(retry_err)
                        print(f"\nError during retry: {retry_err}", file=sys.stderr)
                        await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=300)
                        continue
                except _TfaTimeoutError as tfa_err:
                    runtime.state = "error"
                    runtime.last_error = str(tfa_err)
                    runtime.tfa.needs_intervention = True
                    runtime.tfa.reauth_failures += 1
                    print(f"2FA timeout: {tfa_err}", file=sys.stderr)
                    await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=300)
                    continue
                except Exception as e:
                    runtime.state = "error"
                    runtime.last_error = str(e)
                    print(f"\nError during update: {e}", file=sys.stderr)
                    print("Waiting 5 minutes before retry...", file=sys.stderr)
                    await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=300)
                    continue

            if stop_event.is_set():
                break

            # --- Mode-aware post-fetch behavior ---
            if runtime.config.auto_fetch == "off":
                # Run-once mode: sit idle until user triggers "Fetch Now" or stop
                runtime.state = "idle"
                runtime.next_run_time = None
                print("\nIdle — use 'Fetch Now' to update.", file=sys.stderr)
                await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=None)
            else:
                # Auto-fetch mode: sleep until next scheduled fetch
                cached_for_sleep = _load_cached_api(storage_path)
                if cached_for_sleep is not None:
                    cache_ts = int(cached_for_sleep[1].stem.split(".", 1)[1])
                    cache_expires_in = _CACHE_MAX_AGE_SECONDS - (time.time() - cache_ts)
                    sleep_seconds = max(60, cache_expires_in) + random.uniform(0, 4 * 3600)
                else:
                    sleep_hours = random.uniform(12, 36)
                    sleep_seconds = sleep_hours * 3600
                next_run_time = time.time() + sleep_seconds
                next_run_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_run_time))

                runtime.state = "sleeping"
                runtime.next_run_time = next_run_time
                print(f"\nSleeping {sleep_seconds/3600:.2f} h. Next run at {next_run_str}", file=sys.stderr)
                await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=sleep_seconds)
    finally:
        runtime.state = "shutting_down"
        web_server.close()
        await web_server.wait_closed()
        if session is not None:
            try:
                await session.async_logout()
            except Exception:
                pass  # best-effort cleanup

    print("\nShutdown signal received, exiting...", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
