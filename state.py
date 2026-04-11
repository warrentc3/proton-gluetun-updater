"""
Process overseer: runtime state shared across all modules.

_Status is cross-cutting by design — the inevitable single-process state
aggregator. It is a composition host, not a flat bag. _TfaState is extracted
as a named sub-object so TFA concerns are owned and readable independently.
"""
from __future__ import annotations

import asyncio
import dataclasses
import time
from pathlib import Path

from storage import _Config


@dataclasses.dataclass
class _TfaState:
    """
    TFA-specific runtime state, owned by the Proton auth lifecycle.

    Extracted from _Status as a composition sub-object so TFA concerns
    are co-located and readable without scanning the full status bag.
    """
    required: bool | None = None    # None=unknown, False=not needed, True=was required
    needs_intervention: bool = False  # True when re-auth requires 2FA and nobody is watching
    reauth_failures: int = 0          # consecutive re-auth failure count


@dataclasses.dataclass
class _Status:
    """
    Mutable runtime state surfaced on the web dashboard.

    Cross-cutting by design — imported by web, proton, and orchestration.
    Acts as a composition host: tfa sub-object owns TFA lifecycle state.
    """
    config: _Config = dataclasses.field(default_factory=_Config)
    start_time: float = dataclasses.field(default_factory=time.time)
    state: str = "starting"  # starting|authenticating|running|sleeping|idle|waiting_tfa|error|shutting_down
    last_run_time: float | None = None
    next_run_time: float | None = None
    last_server_count: int | None = None
    last_error: str | None = None
    run_count: int = 0
    last_stats: dict | None = None
    tfa: _TfaState = dataclasses.field(default_factory=_TfaState)
    configuration_error: bool = False
    cache_dir: Path | None = None  # set after STORAGE_FILEPATH is resolved
    force_fetch: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    ipv6_routable: bool | None = None
