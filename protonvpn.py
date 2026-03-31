"""
ProtonVPN integration: authentication, server list fetch, and TFA flow.

This module is the reference implementation of how a 2FA-requiring VPN
provider integrates with Gluetun's server model. It is designed as a
standalone importable building block — the companion container and future
community tooling can import it directly without pulling in the web layer,
storage, or process state.

ProtonVPN is the only Gluetun provider that mandates 2FA for normal
operation. Gluetun's FetchServers(ctx, minServers) interface has no
mechanism for an interactive auth flow — this module demonstrates the
pattern for how such providers should be handled.
"""
from __future__ import annotations

import asyncio
import sys
import time
from typing import TYPE_CHECKING

from proton.session import Session
from proton.session.exceptions import ProtonAPI2FANeeded, ProtonAPIAuthenticationNeeded  # noqa: F401 — re-exported for callers

if TYPE_CHECKING:
    from state import _Status, _TfaState

APP_VERSION = "linux-vpn-cli@4.15.2"
USER_AGENT = "ProtonVPN/4.15.2 (Linux)"
LOGICALS_ENDPOINT = "/vpn/v1/logicals?SecureCoreFilter=all&WithIpV6=1"


def _read_secret(name: str) -> str | None:
    """Read a Docker secret from /run/secrets/<name>, returning None if absent."""
    try:
        with open(f"/run/secrets/{name}", encoding="utf-8") as f:
            value = f.read().strip()
        return value or None
    except OSError:
        return None


class _TfaTimeoutError(Exception):
    """Raised when the 2FA code is not submitted within the allowed window."""


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


async def _authenticate(username: str, password: str) -> Session:
    """
    Create a Session and perform initial password authentication via SRP.

    The caller is responsible for calling session.async_logout() when done.
    Raises ProtonAPIAuthenticationNeeded on failure.
    """
    session = Session(appversion=APP_VERSION, user_agent=USER_AGENT)
    print("Authenticating...", file=sys.stderr)
    success = await session.async_authenticate(username, password)
    if not success:
        raise ProtonAPIAuthenticationNeeded("Authentication failed — check credentials.")
    return session


async def _fetch_server_list(
    session: Session,
    broker: _TfaBroker | None = None,
    status: "_Status | None" = None,
    stop_event: asyncio.Event | None = None,
    tfa_timeout: float = 900,  # seconds; 900 = 15 min (startup), caller passes 300 for re-auth
) -> dict:
    """
    Fetch the server list using an existing authenticated session.

    Handles a 2FA challenge the first time it is encountered (e.g. on the
    initial request after password-only authentication). Subsequent calls
    on the same session skip 2FA because the session token is already valid.

    IPv6 data is always requested from the API regardless of IP6 config;
    the ipv6_filter is applied during transformation to include, exclude, or
    restrict output to servers with IPv6 addresses.

    When a broker is provided, 2FA codes are collected via the web form.
    A tfa_timeout limits how long we wait for a code — on timeout, the
    partial session is logged out and _TfaTimeoutError is raised.

    Without a broker (dev/interactive use), a TTY stdin prompt is used.
    """
    print("Fetching server list...", file=sys.stderr)
    try:
        result = await session.async_api_request(LOGICALS_ENDPOINT)
        if status is not None and status.tfa.required is None:
            status.tfa.required = False
        return result
    except ProtonAPI2FANeeded:
        if status is not None:
            status.tfa.required = True
        # Proton 2FA.Enabled bitmask: 1 = TOTP, 2 = FIDO2.
        # If the account has 2FA but TOTP is not enabled, our web form (TOTP-
        # only) can never satisfy the challenge — fail fast rather than looping
        # forever. Access the private mangled attribute defensively so a future
        # library refactor degrades gracefully (we'd just fall through and let
        # submission attempts fail with "Invalid code").
        _tfa_info = getattr(session, "_Session__2FA", None) or {}
        _tfa_enabled_bits = _tfa_info.get("Enabled", 0)
        if _tfa_enabled_bits and not (_tfa_enabled_bits & 1):
            raise RuntimeError(
                "2FA is required but TOTP is not enabled on this account "
                "(FIDO2 / hardware-key only). Only TOTP codes are supported."
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
