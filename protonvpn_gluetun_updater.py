#!/usr/bin/env python3
"""
Fetch the Proton VPN server list and export it in Gluetun custom
provider format (servers.json).

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
    MAX_SERVERS       Max number of servers to export, sorted by load (default: no limit)
    INCLUDE_IPV6      Include IPv6 addresses in server entries (1/true/yes or 0/false/no, default: false)
    SECURE_CORE       Filter secure_core servers: include (default), exclude, or only
    TOR               Filter TOR servers: include (default), exclude, or only
    DEBUG             Save raw API response to debug directory (1/true/yes or 0/false/no, default: false)
    DEBUG_DIR         Debug output directory (default: STORAGE_FILEPATH/debug when DEBUG=true and DEBUG_DIR is unset)
"""
import asyncio
import getpass
import json
import os
import re
import sys
import tarfile
import time
from pathlib import Path

from proton.session import Session
from proton.session.exceptions import ProtonAPI2FANeeded

APP_VERSION = "linux-vpn-cli@4.15.2"
USER_AGENT = "ProtonVPN/4.15.2 (Linux)"
LOGICALS_ENDPOINT_BASE = "/vpn/v1/logicals?SecureCoreFilter=all"

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
    Parse country code from server name.
    
    Critical for secure_core servers where ExitCountry indicates the exit point,
    but the actual server location is encoded in the name.
    
    Examples:
        Normal: "US-NY#1" -> "US" -> "United States"
        Secure Core: "IS-US#1" -> "US" -> "United States" (exit through US, hosted in Iceland)
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


async def fetch_server_list(username: str, password: str, include_ipv6: bool = False) -> dict:
    session = Session(appversion=APP_VERSION, user_agent=USER_AGENT)

    print("Authenticating...", file=sys.stderr)
    success = await session.async_authenticate(username, password)
    if not success:
        print("Error: authentication failed.", file=sys.stderr)
        sys.exit(1)

    # Build endpoint with conditional IPv6 parameter
    endpoint = LOGICALS_ENDPOINT_BASE
    if include_ipv6:
        endpoint += "&WithIpV6=1"

    try:
        print("Fetching server list...", file=sys.stderr)
        response = await session.async_api_request(endpoint)
    except ProtonAPI2FANeeded:
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
        response = await session.async_api_request(endpoint)

    await session.async_logout()
    return response


def transform(api_data: dict, max_load: int | None = None, max_servers: int | None = None, include_ipv6: bool = False, secure_core_filter: str = "include", tor_filter: str = "include") -> dict:
    """
    Transform ProtonVPN API data to Gluetun format.
    
    Improvements:
    - Parse country from server name (not ExitCountry)
    - Include all feature flags (free, secure_core, tor, stream, port_forward)
    - Only include feature flags when true
    - Fix Wireguard: no tcp/udp properties
    - Deduplicate physical servers for non-secure_core
    - Optional IPv6 address inclusion
    - Filtering by secure_core and TOR (include/exclude/only)
    """
    # Sort logical servers: secure_core first, then tor, then by country, city, and score
    logicals = sorted(
        api_data["LogicalServers"],
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

    if max_servers is not None:
        logicals = logicals[:max_servers]

    servers = []
    seen_ips = {}  # Track IPs for non-secure_core deduplication
    stats = {
        'skipped_disabled': 0,
        'skipped_duplicate': 0,
        'skipped_tor': 0,
        'skipped_secure_core': 0,
        'secure_core': 0,
        'tor': 0,
        'free_tier': 0,
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
            
            # Track statistics
            if is_secure_core:
                stats['secure_core'] += 1
            if is_tor:
                stats['tor'] += 1
            if is_free:
                stats['free_tier'] += 1
            
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

    # Print statistics
    print(f"\nTransformation statistics:", file=sys.stderr)
    print(f"  Skipped (disabled): {stats['skipped_disabled']}", file=sys.stderr)
    print(f"  Skipped (duplicate IPs): {stats['skipped_duplicate']}", file=sys.stderr)
    print(f"  Secure core servers: {stats['secure_core']}", file=sys.stderr)
    print(f"  TOR servers: {stats['tor']}", file=sys.stderr)
    print(f"  Free tier servers: {stats['free_tier']}", file=sys.stderr)

    return {
        "version": 1,
        "protonvpn": {
            "version": 4,
            "timestamp": int(time.time()),
            "servers": servers,
        },
    }


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

    api_data = await fetch_server_list(username, password, include_ipv6)
    
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
    
    total = len(api_data.get("LogicalServers", []))
    result = transform(api_data, max_load=max_load, max_servers=max_servers, include_ipv6=include_ipv6, secure_core_filter=secure_core_filter, tor_filter=tor_filter)

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
    filter_info = f" ({', '.join(filters)})" if filters else ""

    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        f.write(output)
    print(f"\n{count} servers written to {output_file} (from {total} logicals{filter_info})", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
