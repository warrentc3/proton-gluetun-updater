"""
HTTP dashboard and control API.

Serves the web dashboard (index.html) and handles the REST control endpoints:
GET /status, POST /config, POST /reprocess, POST /refresh, POST /2fa.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

from storage import _FILTER_CHOICES, _reprocess_from_cache, _save_filter_config

if TYPE_CHECKING:
    from protonvpn import _TfaBroker
    from state import _Status

_HTML_PAGE = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


def _fmt_uptime(start: float) -> str:
    """Format elapsed seconds since start as h:m:s string."""
    secs = int(time.time() - start)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s"


def _fmt_ts(ts: float | None) -> str | None:
    """Format a Unix timestamp as a human-readable local datetime string."""
    if ts is None:
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


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
    """Write an HTTP/1.1 response."""
    b = body.encode() if isinstance(body, str) else body
    writer.write(
        f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(b)}\r\nConnection: close\r\n\r\n".encode()
        + b
    )


async def _web_handler(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    runtime: "_Status",
    broker: "_TfaBroker",
) -> None:
    """Dispatch incoming HTTP requests to the appropriate handler."""
    try:
        req = await _read_http_request(reader)
        if req is None:
            return
        method, path, _, body = req

        if method == "GET" and path == "/health":
            if runtime.configuration_error or runtime.tfa.needs_intervention:
                _http_respond(writer, "503 Service Unavailable", "application/json",
                              json.dumps({"healthy": False, "configuration_error": runtime.configuration_error,
                                          "needs_tfa_intervention": runtime.tfa.needs_intervention}))
            else:
                _http_respond(writer, "200 OK", "application/json", '{"healthy":true}')

        elif method == "GET" and path in ("/", ""):
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
                "tfa_required": runtime.tfa.required,
                "tfa_message": broker.message or None,
                "configuration_error": runtime.configuration_error,
                "stats": runtime.last_stats,
                "needs_tfa_intervention": runtime.tfa.needs_intervention,
                "reauth_failures": runtime.tfa.reauth_failures,
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
            if not re.fullmatch(r"\d{6,8}", code):
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


async def _start_web_server(
    host: str,
    port: int,
    runtime: "_Status",
    broker: "_TfaBroker",
) -> asyncio.Server:
    """Start the asyncio TCP server and bind the web handler."""
    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _web_handler(reader, writer, runtime, broker)

    server = await asyncio.start_server(_handle, host, port)
    addr = server.sockets[0].getsockname()
    print(f"Web dashboard listening on http://{addr[0]}:{addr[1]}", file=sys.stderr)
    return server
