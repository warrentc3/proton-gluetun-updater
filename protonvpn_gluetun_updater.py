#!/usr/bin/env python3
"""
Fetch the Proton VPN server list and export it in Gluetun custom
provider format (servers-proton.json).

Authenticates directly against the Proton API using SRP.

IMPROVEMENTS over original version:
- Complete 194-country mapping (vs 70)
- Parse country from server name (critical for secure_core routing)
- Include ALL feature flags (free, secure_core, tor, stream, port_forward)
- Only include feature flags when true (cleaner JSON, matches Gluetun implementation)
- Fix Wireguard bug: no tcp/udp properties (only OpenVPN uses these)
- Physical server deduplication for non-secure_core servers
- Better statistics and verbose output

Environment variables:
    PROTON_USERNAME   Proton account username
    PROTON_PASSWORD   Proton account password
    PROTON_2FA        TOTP code (optional, only if 2FA is enabled)
    STORAGE_FILEPATH  Storage directory path (required, output file: servers-proton.json)
    MAX_LOAD          Max server load percentage to include (0-100, default: no filter)
    MAX_SERVERS       Limit to the N best servers after sorting and filtering (default: no limit)
    INCLUDE_IPV6      Retain IPv6 addresses in server entries (1/true/yes or 0/false/no, default: false; IPv6 data is always fetched but stripped from output when false)
    SECURE_CORE       Filter secure_core servers: include (default), exclude, or only
    TOR               Filter TOR servers: include (default), exclude, or only
    FREE_TIER         Filter free tier servers: include (default), exclude, or only
    REPLACE_GLUETUN_SERVERS_JSON  Replace servers.json with servers-proton.json (1/true/yes or 0/false/no, default: false)
    KEEP_RUNNING      Keep container running and execute at random intervals (1/true/yes or 0/false/no, default: false)
    WEB_PORT          Web dashboard port when KEEP_RUNNING=true (default: 8080; not started in single-run mode)
    DEBUG             Save raw API response to debug directory (1/true/yes or 0/false/no, default: false)
    DEBUG_DIR         Debug output directory (default: STORAGE_FILEPATH/debug when DEBUG=true and DEBUG_DIR is unset)
"""
import asyncio
import dataclasses
import getpass
import json
import os
import random
import re
import signal
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs

from proton.session import Session
from proton.session.exceptions import ProtonAPI2FANeeded

APP_VERSION = "linux-vpn-cli@4.15.2"
USER_AGENT = "ProtonVPN/4.15.2 (Linux)"
LOGICALS_ENDPOINT = "/vpn/v1/logicals?SecureCoreFilter=all&WithIpV6=1"

# Feature bitmask (from proton.vpn.session.servers.types.ServerFeatureEnum)
SECURE_CORE = 1 << 0  # 1
TOR = 1 << 1          # 2
P2P = 1 << 2          # 4
STREAMING = 1 << 3    # 8
IPV6 = 1 << 4         # 16

# Load country names from external file
def load_country_names() -> dict:
    """Load country code to name mapping from countries.json."""
    script_dir = Path(__file__).parent
    countries_file = script_dir / "countries.json"
    
    try:
        with open(countries_file, 'r') as f:
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


def get_credentials() -> tuple[str, str]:
    username = os.environ.get("PROTON_USERNAME")
    password = os.environ.get("PROTON_PASSWORD")

    if not username:
        print("Proton username: ", end="", file=sys.stderr, flush=True)
        username = input()
    if not password:
        password = getpass.getpass("Proton password: ", stream=sys.stderr)

    return username, password


# ---------------------------------------------------------------------------
# Runtime state, 2FA broker, and web dashboard
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class _Status:
    """Mutable runtime state surfaced on the web dashboard."""
    start_time: float = dataclasses.field(default_factory=time.time)
    state: str = "starting"     # starting|authenticating|running|sleeping|waiting_2fa|error|shutting_down
    last_run_time: float | None = None
    next_run_time: float | None = None
    last_server_count: int | None = None
    last_error: str | None = None
    run_count: int = 0


class _TwoFABroker:
    """Bridges the web 2FA form submission to the asyncio authentication flow."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
        self.waiting: bool = False
        self.message: str = ""  # feedback shown on the web form after a bad code

    async def wait_for_code(self) -> str:
        """Block until a code is submitted via the web form."""
        self.waiting = True
        self.message = ""
        try:
            return await self._queue.get()
        finally:
            self.waiting = False

    def submit_code(self, code: str) -> bool:
        """Called from the HTTP handler. Returns False if not currently waiting."""
        if not self.waiting or self._queue.full():
            return False
        self._queue.put_nowait(code)
        return True


def _fmt_ts(ts: float | None) -> str | None:
    if ts is None:
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _fmt_uptime(start: float) -> str:
    secs = int(time.time() - start)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s"


_HTML_PAGE = """\
<!DOCTYPE html><html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ProtonVPN Gluetun Updater</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#0f1117;color:#e2e8f0;font-family:system-ui,sans-serif;min-height:100vh;
         display:flex;flex-direction:column;align-items:center;padding:2rem 1rem}
    h1{font-size:1.4rem;font-weight:700;margin-bottom:.2rem}
    .sub{font-size:.8rem;color:#64748b;margin-bottom:1.5rem}
    .card{background:#1e2130;border:1px solid #2d3348;border-radius:10px;
          padding:1.5rem;width:100%;max-width:540px;margin-bottom:1rem}
    .badge{display:inline-block;padding:.2rem .75rem;border-radius:999px;font-size:.72rem;
           font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:1.2rem}
    .s-starting,.s-shutting_down{background:#1e293b;color:#94a3b8}
    .s-authenticating{background:#1e293b;color:#93c5fd;animation:pulse 1.2s ease-in-out infinite}
    .s-running{background:#14532d;color:#86efac;animation:pulse 1.2s ease-in-out infinite}
    .s-sleeping{background:#1e3a5f;color:#7dd3fc}
    .s-waiting_2fa{background:#451a03;color:#fdba74;animation:pulse 1s ease-in-out infinite}
    .s-error{background:#450a0a;color:#fca5a5}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:.8rem 2rem}
    .stat label{display:block;font-size:.68rem;color:#64748b;text-transform:uppercase;
                letter-spacing:.08em;margin-bottom:.2rem}
    .stat .val{font-size:.88rem;font-family:monospace;color:#e2e8f0}
    .err{margin-top:1rem;background:#1c0a0a;border:1px solid #7f1d1d;border-radius:6px;
         padding:.75rem;font-size:.78rem;color:#fca5a5;font-family:monospace;word-break:break-all}
    .tfa{background:#1e2130;border:1px solid #92400e;border-radius:10px;
         padding:1.5rem;width:100%;max-width:540px}
    .tfa h2{font-size:1rem;color:#fdba74;margin-bottom:.4rem}
    .tfa p{font-size:.8rem;color:#94a3b8;margin-bottom:.8rem}
    .tfa-msg{font-size:.78rem;color:#fca5a5;margin-bottom:.6rem}
    .tfa-form{display:flex;gap:.5rem}
    .tfa-in{flex:1;background:#0f1117;border:1px solid #475569;border-radius:6px;
            padding:.5rem .75rem;color:#e2e8f0;font-size:1.1rem;letter-spacing:.2em;
            text-align:center;font-family:monospace;outline:none}
    .tfa-in:focus{border-color:#f97316}
    .tfa-btn{background:#f97316;color:#fff;border:none;border-radius:6px;
             padding:.5rem 1.2rem;font-size:.9rem;font-weight:600;cursor:pointer}
    .tfa-btn:hover{background:#ea580c}
    footer{font-size:.7rem;color:#334155;margin-top:1.5rem}
  </style>
</head>
<body>
  <h1>ProtonVPN Gluetun Updater</h1>
  <p class="sub">Server list refresh service</p>
  <div class="card">
    <div id="badge" class="badge s-starting">starting</div>
    <div class="grid">
      <div class="stat"><label>Uptime</label><span class="val" id="uptime">&#x2014;</span></div>
      <div class="stat"><label>Total Runs</label><span class="val" id="run_count">&#x2014;</span></div>
      <div class="stat"><label>Last Run</label><span class="val" id="last_run">&#x2014;</span></div>
      <div class="stat"><label>Next Run</label><span class="val" id="next_run">&#x2014;</span></div>
      <div class="stat"><label>Servers Written</label><span class="val" id="server_count">&#x2014;</span></div>
    </div>
    <div id="err" class="err" style="display:none"></div>
  </div>
  <div class="tfa" id="tfa_card" style="display:none">
    <h2>&#x1F511; 2FA Required</h2>
    <p>Enter your 6-digit authenticator code to continue.</p>
    <div id="tfa_msg" class="tfa-msg" style="display:none"></div>
    <form class="tfa-form" method="POST" action="/2fa">
      <input class="tfa-in" type="text" name="code" maxlength="8" inputmode="numeric"
             pattern="[0-9 ]*" placeholder="000000" autocomplete="one-time-code" autofocus>
      <button class="tfa-btn" type="submit">Submit</button>
    </form>
  </div>
  <footer>Auto-refreshes every 10 s &mdash; last: <span id="ts">never</span></footer>
  <script>
    function set(id,v){var e=document.getElementById(id);if(e)e.textContent=v!=null?v:'\u2014';}
    async function refresh(){
      try{
        var r=await fetch('/status');if(!r.ok)return;
        var d=await r.json();
        var b=document.getElementById('badge');
        b.textContent=d.state.replace(/_/g,' ');
        b.className='badge s-'+d.state;
        set('uptime',d.uptime);set('run_count',d.run_count);
        set('last_run',d.last_run);set('next_run',d.next_run);
        set('server_count',d.server_count);
        var eb=document.getElementById('err');
        if(d.last_error){eb.style.display='block';eb.textContent=d.last_error;}
        else{eb.style.display='none';}
        document.getElementById('tfa_card').style.display=d.waiting_2fa?'block':'none';
        var tm=document.getElementById('tfa_msg');
        if(d.twofa_message){tm.style.display='block';tm.textContent=d.twofa_message;}
        else{tm.style.display='none';}
        set('ts',new Date().toLocaleTimeString());
      }catch(e){}
    }
    refresh();setInterval(refresh,10000);
  </script>
</body></html>
"""


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


def _http_redirect(writer: asyncio.StreamWriter, location: str) -> None:
    writer.write(
        f"HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()
    )


async def _web_handler(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    runtime: _Status,
    broker: _TwoFABroker,
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
                "last_run": _fmt_ts(runtime.last_run_time),
                "next_run": _fmt_ts(runtime.next_run_time),
                "server_count": runtime.last_server_count,
                "run_count": runtime.run_count,
                "last_error": runtime.last_error,
                "waiting_2fa": broker.waiting,
                "twofa_message": broker.message or None,
            })
            _http_respond(writer, "200 OK", "application/json", payload)

        elif method == "POST" and path == "/2fa":
            form = parse_qs(body.decode(errors="replace"))
            code = "".join((form.get("code") or [""])[0].split())  # strip whitespace
            if code and broker.submit_code(code):
                _http_redirect(writer, "/")
            else:
                _http_respond(writer, "400 Bad Request", "text/plain",
                              "Not currently waiting for a 2FA code.")
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


async def _start_web_server(port: int, runtime: _Status, broker: _TwoFABroker) -> asyncio.Server:
    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _web_handler(reader, writer, runtime, broker)

    server = await asyncio.start_server(_handle, "0.0.0.0", port)
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
        print("Error: authentication failed.", file=sys.stderr)
        sys.exit(1)
    return session


async def _fetch_server_list(
    session: Session,
    broker: _TwoFABroker | None = None,
    status: _Status | None = None,
) -> dict:
    """
    Fetch the server list using an existing authenticated session.
    Handles a 2FA challenge the first time it is encountered (e.g. on the
    initial request after password-only authentication).  Subsequent calls
    on the same session skip 2FA because the session token is already valid.

    IPv6 data is always requested from the API regardless of include_ipv6;
    the include_ipv6 flag is applied during transformation to filter the
    addresses out of the output when not wanted.

    When a broker is provided (KEEP_RUNNING + web dashboard), 2FA codes are
    collected via the web form and invalid codes prompt a retry instead of
    exiting.  Without a broker, the env var / stdin path is used.
    """
    print("Fetching server list...", file=sys.stderr)
    try:
        return await session.async_api_request(LOGICALS_ENDPOINT)
    except ProtonAPI2FANeeded:
        if broker is not None:
            # Web dashboard path: loop until a valid code is submitted
            while True:
                if status is not None:
                    status.state = "waiting_2fa"
                print("Waiting for 2FA code via web dashboard...", file=sys.stderr)
                totp_code = await broker.wait_for_code()
                success = await session.async_validate_2fa_code(totp_code)
                if success:
                    if status is not None:
                        status.state = "running"
                    print("2FA validated via web dashboard.", file=sys.stderr)
                    break
                broker.message = "Invalid code — please try again."
                print("Invalid 2FA code submitted via web dashboard. Waiting for retry.", file=sys.stderr)
        else:
            # stdin / env var path
            totp_code = os.environ.get("PROTON_2FA")
            if not totp_code:
                if not sys.stdin.isatty():
                    print("Error: 2FA required. Set the PROTON_2FA environment variable.", file=sys.stderr)
                    sys.exit(1)
                print("2FA code: ", end="", file=sys.stderr, flush=True)
                totp_code = input()

            success = await session.async_validate_2fa_code(totp_code)
            if not success:
                print("Error: invalid 2FA code.", file=sys.stderr)
                sys.exit(1)

        print("Fetching server list...", file=sys.stderr)
        return await session.async_api_request(LOGICALS_ENDPOINT)


def transform(api_data: dict, max_load: int | None = None, max_servers: int | None = None, include_ipv6: bool = False, secure_core_filter: str = "include", tor_filter: str = "include", free_tier_filter: str = "include") -> dict:
    """
    Transform ProtonVPN API data to Gluetun format.
    
    Improvements:
    - Parse country from server name (not ExitCountry)
    - Include all feature flags (free, secure_core, tor, stream, port_forward)
    - Only include feature flags when true
    - Fix Wireguard: no tcp/udp properties
    - Deduplicate physical servers for non-secure_core
    - Optional IPv6 address inclusion
    - Filtering by secure_core, TOR, and free tier (include/exclude/only)
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

    # Sort logical servers: secure_core first, then tor, then by country, city, and score
    logicals = sorted(
        _all,
        key=lambda s: (
            not bool(s.get("Features", 0) & SECURE_CORE),  # secure_core first
            not bool(s.get("Features", 0) & TOR),           # then tor
            parse_country_from_name(s["Name"], bool(s.get("Features", 0) & SECURE_CORE)),  # country alphabetically
            s.get("City", ""),                              # city alphabetically
            s.get("Score", float("inf"))                    # score ascending (lower is better)
        )
    )

    if max_load is not None:
        logicals = [s for s in logicals if s.get("Load", 100) <= max_load]

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

    if max_servers is not None:
        logicals = logicals[:max_servers]

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
            
            entry_ip = physical["EntryIP"]
            
            # Collect all IPs (IPv4 and optionally IPv6)
            ips = [entry_ip]
            if include_ipv6:
                entry_ipv6 = physical.get("EntryIPv6")
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

    # Compute output logical-level counts
    out_logical = len(logicals)
    out_ipv6 = sum(1 for s in logicals if any(p.get("EntryIPv6") for p in s["Servers"]))
    out_tor = sum(1 for s in logicals if s.get("Features", 0) & TOR)
    out_secure_core = sum(1 for s in logicals if s.get("Features", 0) & SECURE_CORE)
    out_free = sum(1 for s in logicals if s.get("Tier", 1) == 0)
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

    return {
        "version": 1,
        "protonvpn": {
            "version": 4,
            "timestamp": int(time.time()),
            "servers": servers,
        },
    }


def _atomic_write(path: str, content: str) -> None:
    """Write content to path atomically via a temp file + os.replace()."""
    dir_path = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


async def run_update(
    session: Session,
    storage_path,
    max_load,
    max_servers,
    include_ipv6,
    secure_core_filter,
    tor_filter,
    free_tier_filter,
    replace_gluetun_servers_json,
    debug,
    debug_dir,
    *,
    status: _Status | None = None,
    broker: _TwoFABroker | None = None,
):
    """Execute a single update cycle."""
    if status is not None:
        status.state = "running"
        status.last_error = None
        status.next_run_time = None
    api_data = await _fetch_server_list(session, broker=broker, status=status)
    
    # Save debug output if DEBUG=true
    if debug:
        epoch_time = int(time.time())
        debug_path = Path(debug_dir)
        debug_path.mkdir(parents=True, exist_ok=True)
        
        json_filename = f"serverlist.{epoch_time}.json"
        json_filepath = debug_path / json_filename
        tar_filename = f"serverlist.{epoch_time}.tar.gz"
        tar_filepath = debug_path / tar_filename
        
        # Write JSON file
        with open(json_filepath, 'w') as f:
            json.dump(api_data, f, indent=2)
        print(f"Debug: Saved raw API response to {json_filepath}", file=sys.stderr)
        
        # Compress to tar.gz
        with tarfile.open(tar_filepath, 'w:gz') as tar:
            tar.add(json_filepath, arcname=json_filename)
        print(f"Debug: Compressed to {tar_filepath}", file=sys.stderr)
        
        # Remove uncompressed JSON
        json_filepath.unlink()
        print(f"Debug: Removed uncompressed {json_filepath}", file=sys.stderr)
    
    result = transform(api_data, max_load=max_load, max_servers=max_servers, include_ipv6=include_ipv6, secure_core_filter=secure_core_filter, tor_filter=tor_filter, free_tier_filter=free_tier_filter)

    output = json.dumps(result, indent=2)
    count = len(result["protonvpn"]["servers"])

    # Build output file path from storage directory
    output_file = os.path.join(storage_path, "servers-proton.json")
    
    filters = []
    if max_load is not None:
        filters.append(f"max_load={max_load}%")
    if max_servers is not None:
        filters.append(f"max_servers={max_servers}")
    if secure_core_filter != "include":
        filters.append(f"secure_core={secure_core_filter}")
    if tor_filter != "include":
        filters.append(f"tor={tor_filter}")
    if free_tier_filter != "include":
        filters.append(f"free_tier={free_tier_filter}")
    filter_info = f" ({', '.join(filters)})" if filters else ""

    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    _atomic_write(output_file, output)
    print(f"\n{count} server entries written to {output_file}{filter_info}", file=sys.stderr)

    # Optionally replace servers.json with servers-proton.json
    if replace_gluetun_servers_json:
        servers_json_file = os.path.join(storage_path, "servers.json")
        _atomic_write(servers_json_file, output)
        print(f"Replaced {servers_json_file} with servers-proton.json content", file=sys.stderr)

    if status is not None:
        status.last_run_time = time.time()
        status.last_server_count = count
        status.run_count += 1


async def main():
    username, password = get_credentials()

    max_load_env = os.environ.get("MAX_LOAD")
    max_load = int(max_load_env) if max_load_env else None

    max_servers_env = os.environ.get("MAX_SERVERS")
    max_servers = int(max_servers_env) if max_servers_env else None

    # Parse INCLUDE_IPV6 (default: false)
    include_ipv6_env = os.environ.get("INCLUDE_IPV6", "false").lower()
    include_ipv6 = include_ipv6_env in ("1", "true", "yes")

    # Parse SECURE_CORE filter (default: include)
    secure_core_filter = os.environ.get("SECURE_CORE", "include").lower()
    if secure_core_filter not in ("include", "exclude", "only"):
        print(f"Warning: Invalid SECURE_CORE value '{secure_core_filter}'. Using 'include'.", file=sys.stderr)
        secure_core_filter = "include"

    # Parse TOR filter (default: include)
    tor_filter = os.environ.get("TOR", "include").lower()
    if tor_filter not in ("include", "exclude", "only"):
        print(f"Warning: Invalid TOR value '{tor_filter}'. Using 'include'.", file=sys.stderr)
        tor_filter = "include"

    # Parse FREE_TIER filter (default: include)
    free_tier_filter = os.environ.get("FREE_TIER", "include").lower()
    if free_tier_filter not in ("include", "exclude", "only"):
        print(f"Warning: Invalid FREE_TIER value '{free_tier_filter}'. Using 'include'.", file=sys.stderr)
        free_tier_filter = "include"

    # Parse REPLACE_GLUETUN_SERVERS_JSON (default: false)
    replace_gluetun_servers_json_env = os.environ.get("REPLACE_GLUETUN_SERVERS_JSON", "false").lower()
    replace_gluetun_servers_json = replace_gluetun_servers_json_env in ("1", "true", "yes")

    # Parse KEEP_RUNNING (default: false)
    keep_running_env = os.environ.get("KEEP_RUNNING", "false").lower()
    keep_running = keep_running_env in ("1", "true", "yes")

    # Parse STORAGE_FILEPATH (directory for output file) - REQUIRED
    storage_path = os.environ.get("STORAGE_FILEPATH")
    if not storage_path:
        print("Error: STORAGE_FILEPATH environment variable is required.", file=sys.stderr)
        sys.exit(1)

    # Parse DEBUG (default: false)
    debug_env = os.environ.get("DEBUG", "false").lower()
    debug = debug_env in ("1", "true", "yes")

    # Parse DEBUG_DIR (default: STORAGE_FILEPATH/debug)
    debug_dir = os.environ.get("DEBUG_DIR")
    if debug and not debug_dir:
        debug_dir = os.path.join(storage_path, "debug")

    if keep_running:
        # Parse WEB_PORT (only used in KEEP_RUNNING mode, default 8080)
        web_port_env = os.environ.get("WEB_PORT", "8080")
        try:
            web_port = int(web_port_env)
        except ValueError:
            print(f"Warning: Invalid WEB_PORT value '{web_port_env}'. Using 8080.", file=sys.stderr)
            web_port = 8080

        print("KEEP_RUNNING enabled: Will run at random intervals between 12-36 hours", file=sys.stderr)

        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop_event.set)

        runtime = _Status()
        broker = _TwoFABroker()
        web_server = await _start_web_server(web_port, runtime, broker)

        runtime.state = "authenticating"
        session = await _authenticate(username, password)
        try:
            while not stop_event.is_set():
                try:
                    await run_update(
                        session, storage_path, max_load, max_servers, include_ipv6,
                        secure_core_filter, tor_filter, free_tier_filter,
                        replace_gluetun_servers_json, debug, debug_dir,
                        status=runtime, broker=broker,
                    )
                except Exception as e:
                    runtime.state = "error"
                    runtime.last_error = str(e)
                    print(f"\nError during update: {e}", file=sys.stderr)
                    # Wait 5 minutes before retry, but still respond to stop signal
                    print("Waiting 5 minutes before retry...", file=sys.stderr)
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=300)
                    except asyncio.TimeoutError:
                        pass
                    continue

                if stop_event.is_set():
                    break

                # Calculate random sleep interval between 12 and 36 hours (in seconds)
                sleep_hours = random.uniform(12, 36)
                sleep_seconds = sleep_hours * 3600
                next_run_time = time.time() + sleep_seconds
                next_run_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(next_run_time))

                runtime.state = "sleeping"
                runtime.next_run_time = next_run_time
                print(f"\nSleeping for {sleep_hours:.2f} hours. Next run at {next_run_str}", file=sys.stderr)
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=sleep_seconds)
                except asyncio.TimeoutError:
                    pass  # Normal timeout, continue to next run
        finally:
            runtime.state = "shutting_down"
            web_server.close()
            await web_server.wait_closed()
            try:
                await session.async_logout()
            except Exception:
                pass  # best-effort cleanup

        print("\nShutdown signal received, exiting...", file=sys.stderr)
    else:
        # Run once and exit
        session = await _authenticate(username, password)
        try:
            await run_update(session, storage_path, max_load, max_servers, include_ipv6, secure_core_filter, tor_filter, free_tier_filter, replace_gluetun_servers_json, debug, debug_dir)
        finally:
            try:
                await session.async_logout()
            except Exception:
                pass  # best-effort cleanup; session may not be fully authenticated


if __name__ == "__main__":
    asyncio.run(main())
