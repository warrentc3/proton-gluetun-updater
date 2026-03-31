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
import dataclasses
import json
import os
import random
import re
import signal
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs

import yaml

from proton.session import Session
from proton.session.exceptions import ProtonAPI2FANeeded, ProtonAPIAuthenticationNeeded

APP_VERSION = "linux-vpn-cli@4.15.2"
USER_AGENT = "ProtonVPN/4.15.2 (Linux)"
LOGICALS_ENDPOINT = "/vpn/v1/logicals?SecureCoreFilter=all&WithIpV6=1"

# Feature bitmask (from proton.vpn.session.servers.types.ServerFeatureEnum)
SECURE_CORE = 1 << 0  # 1
TOR = 1 << 1          # 2
P2P = 1 << 2          # 4
STREAMING = 1 << 3    # 8
IPV6 = 1 << 4         # 16 — defined for documentation; IPv6 filtering uses EntryIPv6 field directly

# Load country names from external file
def load_country_names() -> dict:
    """Load country code to name mapping from countries.json."""
    script_dir = Path(__file__).parent
    countries_file = script_dir / "countries.json"
    
    try:
        with open(countries_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: countries.json not found at {countries_file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in countries.json: {e}", file=sys.stderr)
        sys.exit(1)

COUNTRY_NAMES = load_country_names()


def country_name(code: str) -> str:
    """Convert country code to full name with fallback."""
    name = COUNTRY_NAMES.get(code)
    if not name:
        print(f"Warning: Unknown country code: {code}", file=sys.stderr)
        return code
    return name


def parse_country_from_name(server_name: str, is_secure_core: bool) -> str:
    """
    Parse the exit country code from a server name and return the full country name.

    For Secure Core servers, the name format is CC-CC#N (entry-exit), where the
    first code is the hosting/entry country and the second is the exit country.
    The exit country is returned so Gluetun routes traffic correctly.

    Examples:
        Normal:       "US-NY#1" -> "US" -> "United States"
        Secure Core:  "IS-US#1" -> "US" -> "United States" (entry in Iceland, exit via US)
    """
    if is_secure_core:
        # Secure core: CC-CC#N format, take second CC (exit country)
        match = re.match(r'^[A-Z]{2}-([A-Z]{2})', server_name)
        if match:
            return country_name(match.group(1))
    else:
        # Normal server: CC#N format, take first CC
        match = re.match(r'^([A-Z]{2})', server_name)
        if match:
            return country_name(match.group(1))
    
    # Fallback - this shouldn't happen with valid ProtonVPN data
    print(f"Warning: Could not parse country from server name: {server_name}", file=sys.stderr)
    return server_name


def _read_secret(name: str) -> str | None:
    """Read a Docker secret from /run/secrets/<name>, returning None if absent."""
    try:
        with open(f"/run/secrets/{name}", encoding="utf-8") as f:
            value = f.read().strip()
        return value or None
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Runtime state, TFA broker, and web dashboard
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class _Config:
    """Mutable filter configuration (persisted to config.yaml)."""
    ip6: str = "exclude"
    secure_core: str = "include"
    tor: str = "include"
    free_tier: str = "include"
    gluetun_json: str = "none"  # none|replace|update
    auto_fetch: str = "off"    # off|on


@dataclasses.dataclass
class _Status:
    """Mutable runtime state surfaced on the web dashboard."""
    config: _Config = dataclasses.field(default_factory=_Config)
    start_time: float = dataclasses.field(default_factory=time.time)
    state: str = "starting"     # starting|authenticating|running|sleeping|idle|waiting_tfa|error|shutting_down
    last_run_time: float | None = None
    next_run_time: float | None = None
    last_server_count: int | None = None
    last_error: str | None = None
    run_count: int = 0
    last_stats: dict | None = None
    tfa_required: bool | None = None  # None=unknown, False=not needed, True=was required
    configuration_error: bool = False
    cache_dir: Path | None = None  # set after STORAGE_FILEPATH is resolved
    force_fetch: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    reauth_failures: int = 0
    needs_tfa_intervention: bool = False


class _TfaBroker:
    """Bridges the web 2FA form submission to the asyncio authentication flow."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
        self.waiting: bool = False
        self.message: str = ""  # feedback shown on the web form after a bad code

    async def wait_for_code(self) -> str:
        """Block until a code is submitted via the web form."""
        self.waiting = True
        try:
            return await self._queue.get()
        finally:
            self.waiting = False

    def submit_code(self, code: str) -> bool:
        """Called from the HTTP handler. Returns False if not currently waiting."""
        if not self.waiting or self._queue.full():
            return False
        self.message = ""  # Clear error message when user submits a new code
        self._queue.put_nowait(code)
        return True


def _fmt_uptime(start: float) -> str:
    secs = int(time.time() - start)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s"


def _fmt_ts(ts: float | None) -> str | None:
    """Format a Unix timestamp as a human-readable local datetime string."""
    if ts is None:
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


_HTML_PAGE = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


async def _read_http_request(reader: asyncio.StreamReader):
    """Parse a minimal HTTP/1.x request. Returns (method, path, headers, body) or None."""
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=5)
        parts = line.decode(errors="replace").split()
        if len(parts) < 2:
            return None
        method, path = parts[0].upper(), parts[1]
        headers: dict[str, str] = {}
        while True:
            hline = await asyncio.wait_for(reader.readline(), timeout=5)
            if hline in (b"\r\n", b"\n", b""):
                break
            if b":" in hline:
                k, _, v = hline.decode(errors="replace").partition(":")
                headers[k.strip().lower()] = v.strip()
        body = b""
        if "content-length" in headers:
            length = min(int(headers["content-length"]), 512)  # cap to prevent DoS
            body = await asyncio.wait_for(reader.readexactly(length), timeout=5)
        return method, path, headers, body
    except Exception:
        return None


def _http_respond(writer: asyncio.StreamWriter, status: str, ctype: str, body: str | bytes) -> None:
    b = body.encode() if isinstance(body, str) else body
    writer.write(
        f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(b)}\r\nConnection: close\r\n\r\n".encode()
        + b
    )


async def _web_handler(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    runtime: _Status,
    broker: _TfaBroker,
) -> None:
    try:
        req = await _read_http_request(reader)
        if req is None:
            return
        method, path, _, body = req

        if method == "GET" and path in ("/", ""):
            _http_respond(writer, "200 OK", "text/html; charset=utf-8", _HTML_PAGE)

        elif method == "GET" and path == "/status":
            payload = json.dumps({
                "state": runtime.state,
                "uptime": _fmt_uptime(runtime.start_time),
                "last_run_time": runtime.last_run_time,
                "next_run_time": runtime.next_run_time,
                # Backward-compatible formatted fields
                "last_run": _fmt_ts(runtime.last_run_time),
                "next_run": _fmt_ts(runtime.next_run_time),
                "server_count": runtime.last_server_count,
                "run_count": runtime.run_count,
                "last_error": runtime.last_error,
                "tfa_waiting": broker.waiting,
                "tfa_required": runtime.tfa_required,
                "tfa_message": broker.message or None,
                "configuration_error": runtime.configuration_error,
                "stats": runtime.last_stats,
                "needs_tfa_intervention": runtime.needs_tfa_intervention,
                "reauth_failures": runtime.reauth_failures,
                "config": {
                    "ip6": runtime.config.ip6,
                    "secure_core": runtime.config.secure_core,
                    "tor": runtime.config.tor,
                    "free_tier": runtime.config.free_tier,
                    "gluetun_json": runtime.config.gluetun_json,
                    "auto_fetch": runtime.config.auto_fetch,
                },
            })
            _http_respond(writer, "200 OK", "application/json", payload)

        elif method == "POST" and path == "/config":
            form = parse_qs(body.decode(errors="replace"))
            def _fv(key: str) -> str:
                return (form.get(key) or [""])[0].strip().lower()
            # Support partial updates — keys absent from the form body keep their current value.
            # This allows the Auto Fetch card and the Filter card to submit independently.
            submitted = set(form.keys()) & set(_FILTER_CHOICES.keys())
            new_vals = {
                k: (_fv(k) if k in submitted else getattr(runtime.config, k))
                for k in _FILTER_CHOICES
            }
            errors = [
                f"'{k}' must be one of {_FILTER_CHOICES[k]}, got '{v}'"
                for k, v in new_vals.items()
                if k in submitted and v not in _FILTER_CHOICES[k]
            ]
            if errors:
                _http_respond(writer, "400 Bad Request", "text/plain", "; ".join(errors))
            elif runtime.cache_dir is None:
                _http_respond(writer, "503 Service Unavailable", "text/plain", "Storage path not yet initialised.")
            else:
                _save_filter_config(runtime.cache_dir / "config.yaml", new_vals)
                for k, v in new_vals.items():
                    setattr(runtime.config, k, v)
                _http_respond(writer, "200 OK", "application/json", '{"ok":true}')

        elif method == "POST" and path == "/reprocess":
            if runtime.cache_dir is None:
                _http_respond(writer, "503 Service Unavailable", "text/plain", "Storage path not yet initialised.")
            elif runtime.state in ("running", "authenticating", "waiting_tfa"):
                _http_respond(writer, "409 Conflict", "text/plain", "An update is already in progress.")
            else:
                storage_path_str = str(runtime.cache_dir.parent)
                try:
                    ok = _reprocess_from_cache(storage_path_str, runtime.config, runtime)
                    if ok:
                        _http_respond(writer, "200 OK", "application/json", '{"ok":true}')
                    else:
                        _http_respond(writer, "404 Not Found", "text/plain", "No cached server list found — use Fetch Now first.")
                except Exception as _rpe:
                    print(f"Reprocess error: {_rpe}", file=sys.stderr)
                    _http_respond(writer, "500 Internal Server Error", "text/plain", str(_rpe))

        elif method == "POST" and path == "/refresh":
            if runtime.state in ("sleeping", "idle", "error"):
                runtime.force_fetch.set()
                _http_respond(writer, "200 OK", "application/json", '{"ok":true}')
            elif runtime.state in ("running", "authenticating", "waiting_tfa"):
                _http_respond(writer, "409 Conflict", "text/plain", "An update is already in progress.")
            else:
                _http_respond(writer, "503 Service Unavailable", "text/plain", "Not ready yet.")

        elif method == "POST" and path == "/2fa":
            form = parse_qs(body.decode(errors="replace"))
            code = "".join((form.get("code") or [""])[0].split())  # strip whitespace
            if not re.fullmatch(r'\d{6,8}', code):
                _http_respond(writer, "400 Bad Request", "text/plain",
                              "Invalid 2FA code: must be 6–8 digits.")
            elif not broker.submit_code(code):
                _http_respond(writer, "400 Bad Request", "text/plain",
                              "Not currently waiting for a 2FA code.")
            else:
                _http_respond(writer, "200 OK", "application/json", '{"ok":true}')
        else:
            _http_respond(writer, "404 Not Found", "text/plain", "Not found")

    except Exception:
        pass
    finally:
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _start_web_server(host: str, port: int, runtime: _Status, broker: _TfaBroker) -> asyncio.Server:
    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _web_handler(reader, writer, runtime, broker)

    server = await asyncio.start_server(_handle, host, port)
    addr = server.sockets[0].getsockname()
    print(f"Web dashboard listening on http://{addr[0]}:{addr[1]}", file=sys.stderr)
    return server


async def _authenticate(username: str, password: str) -> Session:
    """
    Create a Session and perform initial password authentication.
    The caller is responsible for calling session.async_logout() when done.
    """
    session = Session(appversion=APP_VERSION, user_agent=USER_AGENT)
    print("Authenticating...", file=sys.stderr)
    success = await session.async_authenticate(username, password)
    if not success:
        raise ProtonAPIAuthenticationNeeded("Authentication failed — check credentials.")
    return session


class _TfaTimeoutError(Exception):
    """Raised when the 2FA code is not submitted within the allowed window."""


async def _fetch_server_list(
    session: Session,
    broker: _TfaBroker | None = None,
    status: _Status | None = None,
    stop_event: asyncio.Event | None = None,
    tfa_timeout: float = 900,  # seconds; 900 = 15 min (startup), caller passes 300 for re-auth
) -> dict:
    """
    Fetch the server list using an existing authenticated session.
    Handles a 2FA challenge the first time it is encountered (e.g. on the
    initial request after password-only authentication).  Subsequent calls
    on the same session skip 2FA because the session token is already valid.

    IPv6 data is always requested from the API regardless of IP6;
    the ipv6_filter is applied during transformation to include, exclude, or
    restrict output to servers with IPv6 addresses.

    When a broker is provided, 2FA codes are collected via the web form.
    A tfa_timeout limits how long we wait for a code — on timeout, the
    partial session is logged out (don't squat on Proton's infrastructure)
    and _TfaTimeoutError is raised.

    Without a broker (dev/interactive use), a TTY stdin prompt is used.
    """
    print("Fetching server list...", file=sys.stderr)
    try:
        result = await session.async_api_request(LOGICALS_ENDPOINT)
        if status is not None and status.tfa_required is None:
            status.tfa_required = False
        return result
    except ProtonAPI2FANeeded:
        if status is not None:
            status.tfa_required = True
        # Proton 2FA.Enabled bitmask: 1 = TOTP, 2 = FIDO2.
        # If the account has 2FA but TOTP is not enabled, our web form (TOTP-
        # only) can never satisfy the challenge — fail fast rather than looping
        # forever.  Access the private mangled attribute defensively so a future
        # library refactor degrades gracefully (we'd just fall through and let
        # submission attempts fail with "Invalid code").
        _tfa_info = getattr(session, '_Session__2FA', None) or {}
        _tfa_enabled_bits = _tfa_info.get('Enabled', 0)
        if _tfa_enabled_bits and not (_tfa_enabled_bits & 1):
            raise RuntimeError(
                "2FA is required but TOTP is not enabled on this account "
                "(FIDO2 / hardware-key only).  Only TOTP codes are supported."
            )
        if broker is not None:
            # Web dashboard path: loop until a valid code is submitted or timeout
            deadline = time.time() + tfa_timeout
            while True:
                if stop_event is not None and stop_event.is_set():
                    raise _TfaTimeoutError("Shutdown requested during 2FA wait.")
                if status is not None:
                    status.state = "waiting_tfa"
                remaining = deadline - time.time()
                if remaining <= 0:
                    print(
                        f"2FA timeout: no code submitted within {tfa_timeout/60:.0f} min. "
                        "Logging out partial session.",
                        file=sys.stderr,
                    )
                    try:
                        await session.async_logout()
                    except Exception:
                        pass
                    raise _TfaTimeoutError(
                        f"2FA code not submitted within {tfa_timeout/60:.0f} minutes."
                    )
                print(
                    f"Waiting for 2FA code via web dashboard "
                    f"({remaining/60:.0f} min remaining)...",
                    file=sys.stderr,
                )
                if stop_event is not None:
                    # Race broker against stop_event so SIGTERM exits immediately
                    broker_task = asyncio.ensure_future(broker.wait_for_code())
                    stop_task = asyncio.ensure_future(stop_event.wait())
                    done, pending = await asyncio.wait(
                        {broker_task, stop_task},
                        timeout=min(remaining, 30),
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for t in pending:
                        t.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
                    if stop_task in done:
                        raise _TfaTimeoutError("Shutdown requested during 2FA wait.")
                    if broker_task in done:
                        totp_code = broker_task.result()
                    else:
                        continue  # timeout — re-check deadline and stop_event
                else:
                    # No stop_event: only wait for broker with a timeout
                    try:
                        totp_code = await asyncio.wait_for(
                            broker.wait_for_code(),
                            timeout=min(remaining, 30),
                        )
                    except asyncio.TimeoutError:
                        continue  # re-check deadline
                success = await session.async_validate_2fa_code(totp_code)
                if success:
                    broker.message = ""  # Clear any previous error message
                    if status is not None:
                        status.state = "running"
                    print("2FA validated via web dashboard.", file=sys.stderr)
                    break
                broker.message = "Invalid code — please try again."
                print("Invalid 2FA code submitted via web dashboard. Waiting for retry.", file=sys.stderr)
        else:
            # Single-run mode: read from stdin if a TTY is attached, otherwise exit
            if not sys.stdin.isatty():
                print(
                    "Error: 2FA required. Use the web dashboard to submit your TOTP code interactively.",
                    file=sys.stderr,
                )
                sys.exit(1)
            print("2FA code: ", end="", file=sys.stderr, flush=True)
            totp_code = input()

            success = await session.async_validate_2fa_code(totp_code)
            if not success:
                print("Error: invalid 2FA code.", file=sys.stderr)
                sys.exit(1)

        print("Fetching server list...", file=sys.stderr)
        return await session.async_api_request(LOGICALS_ENDPOINT)


def transform(api_data: dict, ipv6_filter: str = "exclude", secure_core_filter: str = "include", tor_filter: str = "include", free_tier_filter: str = "include") -> tuple[dict, dict]:
    """
    Transform ProtonVPN API data to Gluetun custom-provider format.

    Applies the given filters (include/exclude/only), deduplicates physical servers,
    and returns a (gluetun_servers_dict, stats_payload_dict) tuple.
    """
    # Compute raw totals from API data before any filtering
    _all = api_data["LogicalServers"]
    total_logical = len(_all)
    total_physical = len(set(p["EntryIP"] for s in _all for p in s["Servers"]))
    total_ipv6 = sum(1 for s in _all if any(p.get("EntryIPv6") for p in s["Servers"]))
    total_tor = sum(1 for s in _all if s.get("Features", 0) & TOR)
    total_secure_core = sum(1 for s in _all if s.get("Features", 0) & SECURE_CORE)
    total_free = sum(1 for s in _all if s.get("Tier", 1) == 0)
    total_p2p = sum(1 for s in _all if s.get("Features", 0) & P2P)
    total_streaming = sum(1 for s in _all if s.get("Features", 0) & STREAMING)

    # Sort logical servers: secure_core first, then tor, then by country, city, and load
    logicals = sorted(
        _all,
        key=lambda s: (
            not bool(s.get("Features", 0) & SECURE_CORE),  # secure_core first
            not bool(s.get("Features", 0) & TOR),           # then tor
            parse_country_from_name(s["Name"], bool(s.get("Features", 0) & SECURE_CORE)),  # country alphabetically
            s.get("City", ""),                              # city alphabetically
            s.get("Load", 100)                              # load ascending (lower is better)
        )
    )

    # Apply secure_core filter
    if secure_core_filter == "only":
        logicals = [s for s in logicals if bool(s.get("Features", 0) & SECURE_CORE)]
    elif secure_core_filter == "exclude":
        logicals = [s for s in logicals if not bool(s.get("Features", 0) & SECURE_CORE)]

    # Apply TOR filter
    if tor_filter == "only":
        logicals = [s for s in logicals if bool(s.get("Features", 0) & TOR)]
    elif tor_filter == "exclude":
        logicals = [s for s in logicals if not bool(s.get("Features", 0) & TOR)]

    # Apply free tier filter
    if free_tier_filter == "only":
        logicals = [s for s in logicals if s.get("Tier", 1) == 0]
    elif free_tier_filter == "exclude":
        logicals = [s for s in logicals if s.get("Tier", 1) != 0]

    # Apply IPv6 filter
    if ipv6_filter == "only":
        logicals = [s for s in logicals if any(p.get("EntryIPv6") for p in s["Servers"])]

    servers = []
    seen_ips = {}  # Track IPs for non-secure_core deduplication
    stats = {
        'skipped_disabled': 0,
        'skipped_duplicate': 0,
        'out_physical': 0,
    }

    for logical in logicals:
        features = logical.get("Features", 0)
        tier = logical.get("Tier", 1)
        
        # Decode feature flags
        is_secure_core = bool(features & SECURE_CORE)
        is_tor = bool(features & TOR)
        is_p2p = bool(features & P2P)
        is_streaming = bool(features & STREAMING)
        is_free = (tier == 0)
        
        # Parse country from server name (critical for secure_core routing)
        country = parse_country_from_name(logical["Name"], is_secure_core)
        
        for physical in logical["Servers"]:
            # Skip disabled servers
            if physical.get("Status") == 0:
                stats['skipped_disabled'] += 1
                continue
            
            # Skip physical servers without IPv6 when ipv6_filter is "only"
            entry_ipv6 = physical.get("EntryIPv6")
            if ipv6_filter == "only" and not entry_ipv6:
                continue
            
            entry_ip = physical["EntryIP"]
            
            # Collect all IPs (IPv4 and optionally IPv6)
            ips = [entry_ip]
            if ipv6_filter in ("include", "only"):
                if entry_ipv6:
                    ips.append(entry_ipv6)
            
            # Deduplicate non-secure_core servers by IP
            if not is_secure_core:
                if entry_ip in seen_ips:
                    stats['skipped_duplicate'] += 1
                    continue
                seen_ips[entry_ip] = True
            
            # Track physical server output counts
            stats['out_physical'] += 1

            # Create OpenVPN entry (ordered by Server struct definition)
            # Only include feature flags when true
            ovpn_server = {
                "vpn": "openvpn",
                "country": country,
                "city": logical.get("City") or "",
                "server_name": logical["Name"],
                "hostname": physical["Domain"],
                "tcp": True,
                "udp": True,
            }
            if is_free:
                ovpn_server["free"] = True
            if is_streaming:
                ovpn_server["stream"] = True
            if is_secure_core:
                ovpn_server["secure_core"] = True
            if is_tor:
                ovpn_server["tor"] = True
            if is_p2p:
                ovpn_server["port_forward"] = True
            ovpn_server["ips"] = ips
            servers.append(ovpn_server)
            
            # Create Wireguard entry (if key present, ordered by Server struct definition)
            # Only include feature flags when true
            wg_key = physical.get("X25519PublicKey")
            if wg_key:
                wg_server = {
                    "vpn": "wireguard",
                    "country": country,
                    "city": logical.get("City") or "",
                    "server_name": logical["Name"],
                    "hostname": physical["Domain"],
                    "wgpubkey": wg_key,
                }
                if is_free:
                    wg_server["free"] = True
                if is_streaming:
                    wg_server["stream"] = True
                if is_secure_core:
                    wg_server["secure_core"] = True
                if is_tor:
                    wg_server["tor"] = True
                if is_p2p:
                    wg_server["port_forward"] = True
                wg_server["ips"] = ips
                servers.append(wg_server)

    # Compute output logical-level counts.
    # For each filtered category, "In Output" is 0 when that type was excluded,
    # otherwise count from the already-filtered logicals list.
    out_logical = len(logicals)
    out_ipv6 = (
        sum(1 for s in logicals if any(p.get("EntryIPv6") for p in s["Servers"]))
        if ipv6_filter in ("include", "only") else 0
    )
    out_tor = (
        sum(1 for s in logicals if s.get("Features", 0) & TOR)
        if tor_filter in ("include", "only") else 0
    )
    out_secure_core = (
        sum(1 for s in logicals if s.get("Features", 0) & SECURE_CORE)
        if secure_core_filter in ("include", "only") else 0
    )
    out_free = (
        sum(1 for s in logicals if s.get("Tier", 1) == 0)
        if free_tier_filter in ("include", "only") else 0
    )
    out_p2p = sum(1 for s in logicals if s.get("Features", 0) & P2P)
    out_streaming = sum(1 for s in logicals if s.get("Features", 0) & STREAMING)

    # Print statistics table
    rows = [
        ("Physical servers",    total_physical,    stats['out_physical']),
        ("Logical servers",     total_logical,     out_logical),
        ("Servers with IPv6",   total_ipv6,        out_ipv6),
        ("TOR servers",         total_tor,         out_tor),
        ("Secure core servers", total_secure_core, out_secure_core),
        ("Free servers",        total_free,        out_free),
        ("P2P servers",         total_p2p,         out_p2p),
        ("Streaming servers",   total_streaming,   out_streaming),
    ]
    lbl_w = max(len(r[0]) for r in rows)
    num_w = max(len(str(r[1])) for r in rows)
    print(f"\nTransformation statistics:", file=sys.stderr)
    print(f"  {'Category':{lbl_w}}  {'Total':>{num_w}}  In Output", file=sys.stderr)
    print(f"  {'-' * lbl_w}  {'-' * num_w}  {'-' * 9}", file=sys.stderr)
    for label, total_val, out_val in rows:
        print(f"  {label:{lbl_w}}  {total_val:>{num_w}}  {out_val}", file=sys.stderr)
    if stats['skipped_disabled']:
        print(f"\n  Note: {stats['skipped_disabled']} physical servers skipped (disabled)", file=sys.stderr)
    if stats['skipped_duplicate']:
        print(f"  Note: {stats['skipped_duplicate']} physical servers skipped (duplicate IP)", file=sys.stderr)

    stats_payload = {
        "rows": [{"label": label, "total": total_val, "out": out_val} for label, total_val, out_val in rows],
        "skipped_disabled": stats['skipped_disabled'],
        "skipped_duplicate": stats['skipped_duplicate'],
    }
    return {
        "version": 1,
        "protonvpn": {
            "version": 4,
            "timestamp": int(time.time()),
            "servers": servers,
        },
    }, stats_payload


def _validate_servers_json(data: dict, label: str) -> None:
    """
    Validate the structure of a Gluetun servers.json payload before writing.
    Raises ValueError with a descriptive message if the structure is invalid.

    Expected schema:
      {
        "version": <int>,
        "<provider>": {
          "version":   <int>,
          "timestamp": <int>,
          "servers":   <list>
        },
        ...
      }
    """
    if not isinstance(data, dict):
        raise ValueError(f"{label}: root must be a JSON object, got {type(data).__name__}")
    if "version" not in data:
        raise ValueError(f"{label}: missing required top-level 'version' field")
    if not isinstance(data["version"], int):
        raise ValueError(f"{label}: top-level 'version' must be an int, got {type(data['version']).__name__}")
    for key, val in data.items():
        if key == "version":
            continue
        if not isinstance(val, dict):
            raise ValueError(f"{label}: provider '{key}' must be an object, got {type(val).__name__}")
        for required_field, expected_type in (("version", int), ("timestamp", int), ("servers", list)):
            if required_field not in val:
                raise ValueError(f"{label}: provider '{key}' missing required field '{required_field}'")
            if not isinstance(val[required_field], expected_type):
                raise ValueError(
                    f"{label}: provider '{key}'.{required_field} must be "
                    f"{expected_type.__name__}, got {type(val[required_field]).__name__}"
                )


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
# Filter config — stored in STORAGE_FILEPATH/proton/config.yaml
# ---------------------------------------------------------------------------

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
    Load STORAGE_FILEPATH/proton/config.yaml.  If it does not exist, create it
    seeded from *env_defaults* (parsed from environment variables).  Invalid or
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


_CACHE_MAX_AGE_SECONDS = 12 * 3600  # 12 hours


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
    of age.  Used when re-applying filter config without fetching fresh data.
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


def _reprocess_from_cache(
    storage_path: str,
    config: "_Config",
    status: "_Status | None" = None,
) -> bool:
    """
    Load the most-recent cached server list (ignoring age), re-run transform
    with *config*, write output files, and update *status* stats.
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


async def run_update(
    session: Session,
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
    
    result, transform_stats = transform(api_data, ipv6_filter=ipv6_filter, secure_core_filter=secure_core_filter, tor_filter=tor_filter, free_tier_filter=free_tier_filter)

    output = json.dumps(result, indent=2)
    count = len(result["protonvpn"]["servers"])

    # Build output file path from storage directory
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

    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    _atomic_write(output_file, output)
    print(f"\n{count} server entries written to {output_file}{filter_info}", file=sys.stderr)

    # Optionally update or replace Gluetun's servers.json
    if gluetun_json_mode in ("replace", "update"):
        servers_json_file = os.path.join(storage_path, "servers.json")
        if gluetun_json_mode == "replace":
            _validate_servers_json(result, "servers-proton.json output")
            _atomic_write(servers_json_file, output)
            print(f"Replaced {servers_json_file} with servers-proton.json content", file=sys.stderr)
        else:  # update
            try:
                with open(servers_json_file, 'r', encoding='utf-8') as f:
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
                    runtime.reauth_failures += 1
                    print(f"Error: deferred authentication failed: {auth_err}", file=sys.stderr)
                    await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=300)
                    continue
                runtime.reauth_failures = 0
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
                runtime.needs_tfa_intervention
                and runtime.config.auto_fetch == "on"
                and not force
            ):
                print(
                    "Skipping scheduled fetch: re-auth requires 2FA, "
                    "manual intervention needed. Use 'Fetch Now'.",
                    file=sys.stderr,
                )
            elif force and runtime.needs_tfa_intervention:
                # User clicked "Fetch Now" — clear intervention flag, fresh auth
                # with the generous startup-style 2FA window (15 min).
                runtime.needs_tfa_intervention = False
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
                    runtime.reauth_failures += 1
                    print(f"Error: re-authentication failed: {auth_err}", file=sys.stderr)
                    await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=300)
                    continue
                runtime.reauth_failures = 0
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
                    runtime.needs_tfa_intervention = True
                    runtime.reauth_failures += 1
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
            # list is still fresh (< 12 h).  The user can trigger a fetch manually
            # via the "Fetch Now" button.  After the first sleep we always fetch.
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
                    # Best-effort logout of the expired session
                    try:
                        await session.async_logout()
                    except Exception:
                        pass
                    try:
                        session = await _authenticate(username, password)
                    except Exception as auth_err:
                        runtime.state = "error"
                        runtime.last_error = f"Re-authentication failed: {auth_err}"
                        runtime.reauth_failures += 1
                        print(f"Error: re-authentication failed: {auth_err}", file=sys.stderr)
                        print("Waiting 5 minutes before retry...", file=sys.stderr)
                        await _wait_for_wakeup(stop_event, runtime.force_fetch, timeout=300)
                        continue
                    runtime.reauth_failures = 0
                    print("Re-authentication successful. Retrying fetch...", file=sys.stderr)
                    # Retry the fetch with re-auth 2FA timeout (5 min)
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
                        runtime.needs_tfa_intervention = True
                        runtime.reauth_failures += 1
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
                    runtime.needs_tfa_intervention = True
                    runtime.reauth_failures += 1
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
                next_run_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(next_run_time))

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
