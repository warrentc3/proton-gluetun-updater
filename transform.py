"""
Pure transformation layer: ProtonVPN API response → Gluetun server format.

This module has zero project dependencies and requires no network access or
authentication. It is the auditable core of the ProtonVPN→Gluetun mapping and
is fully unit-testable without mocking.
"""
import json
import re
import sys
import time
from pathlib import Path


# Feature bitmask (from proton.vpn.session.servers.types.ServerFeatureEnum)
SECURE_CORE = 1 << 0  # 1
TOR = 1 << 1          # 2
P2P = 1 << 2          # 4
STREAMING = 1 << 3    # 8
IPV6 = 1 << 4         # 16 — defined for documentation; IPv6 filtering uses EntryIPv6 field directly


def load_country_names() -> dict:
    """Load country code to name mapping from countries.json."""
    script_dir = Path(__file__).parent
    countries_file = script_dir / "countries.json"

    try:
        with open(countries_file, "r", encoding="utf-8") as f:
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


def transform(
    api_data: dict,
    ipv6_filter: str = "exclude",
    secure_core_filter: str = "include",
    tor_filter: str = "include",
    free_tier_filter: str = "include",
) -> tuple[dict, dict]:
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
        "skipped_disabled": 0,
        "skipped_duplicate": 0,
        "out_physical": 0,
    }

    for logical in logicals:
        features = logical.get("Features", 0)
        tier = logical.get("Tier", 1)

        # Decode feature flags
        is_secure_core = bool(features & SECURE_CORE)
        is_tor = bool(features & TOR)
        is_p2p = bool(features & P2P)
        is_streaming = bool(features & STREAMING)
        is_free = tier == 0

        # Parse country from server name (critical for secure_core routing)
        country = parse_country_from_name(logical["Name"], is_secure_core)

        for physical in logical["Servers"]:
            # Skip disabled servers
            if physical.get("Status") == 0:
                stats["skipped_disabled"] += 1
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
                    stats["skipped_duplicate"] += 1
                    continue
                seen_ips[entry_ip] = True

            # Track physical server output counts
            stats["out_physical"] += 1

            # Create OpenVPN entry (ordered by Server struct definition)
            # Only include feature flags when true
            ovpn_server: dict = {
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

            # Create WireGuard entry (if key present, ordered by Server struct definition)
            # Only include feature flags when true
            wg_key = physical.get("X25519PublicKey")
            if wg_key:
                wg_server: dict = {
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
        ("Physical servers",    total_physical,    stats["out_physical"]),
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
    if stats["skipped_disabled"]:
        print(f"\n  Note: {stats['skipped_disabled']} physical servers skipped (disabled)", file=sys.stderr)
    if stats["skipped_duplicate"]:
        print(f"  Note: {stats['skipped_duplicate']} physical servers skipped (duplicate IP)", file=sys.stderr)

    stats_payload = {
        "rows": [{"label": label, "total": total_val, "out": out_val} for label, total_val, out_val in rows],
        "skipped_disabled": stats["skipped_disabled"],
        "skipped_duplicate": stats["skipped_duplicate"],
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
