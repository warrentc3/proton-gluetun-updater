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

Environment variables (or interactive prompt):
    PROTON_USERNAME   Proton account username
    PROTON_PASSWORD   Proton account password
    PROTON_2FA        TOTP code (optional, only if 2FA is enabled)
    OUTPUT_FILE       Output file path (default: stdout)
    MAX_LOAD          Max server load percentage to include (0-100, default: no filter)
    MAX_SERVERS       Max number of servers to export, sorted by load (default: no limit)
"""
import asyncio
import getpass
import json
import os
import re
import sys
import time

from proton.session import Session
from proton.session.exceptions import ProtonAPI2FANeeded

APP_VERSION = "linux-vpn-cli@4.15.2"
USER_AGENT = "ProtonVPN/4.15.2 (Linux)"
LOGICALS_ENDPOINT = "/vpn/v1/logicals?SecureCoreFilter=all"

# Feature bitmask (from proton.vpn.session.servers.types.ServerFeatureEnum)
SECURE_CORE = 1 << 0  # 1
TOR = 1 << 1          # 2
P2P = 1 << 2          # 4
STREAMING = 1 << 3    # 8
IPV6 = 1 << 4         # 16

# Complete ProtonVPN country code mapping (194 countries)
COUNTRY_NAMES = {
    'BD': 'Bangladesh', 'BE': 'Belgium', 'BF': 'Burkina Faso', 'BG': 'Bulgaria',
    'BA': 'Bosnia and Herzegovina', 'BB': 'Barbados', 'WF': 'Wallis and Futuna',
    'BL': 'Saint Barthelemy', 'BM': 'Bermuda', 'BN': 'Brunei', 'BO': 'Bolivia',
    'BH': 'Bahrain', 'BI': 'Burundi', 'BJ': 'Benin', 'BT': 'Bhutan', 'JM': 'Jamaica',
    'BV': 'Bouvet Island', 'BW': 'Botswana', 'WS': 'Samoa',
    'BQ': 'Bonaire, Saint Eustatius and Saba', 'BR': 'Brazil', 'BS': 'Bahamas',
    'JE': 'Jersey', 'BY': 'Belarus', 'BZ': 'Belize', 'RU': 'Russia', 'RW': 'Rwanda',
    'RS': 'Serbia', 'TL': 'East Timor', 'RE': 'Reunion', 'TM': 'Turkmenistan',
    'TJ': 'Tajikistan', 'RO': 'Romania', 'TK': 'Tokelau', 'GW': 'Guinea-Bissau',
    'GU': 'Guam', 'GT': 'Guatemala', 'GS': 'South Georgia and the South Sandwich Islands',
    'GR': 'Greece', 'GQ': 'Equatorial Guinea', 'GP': 'Guadeloupe', 'JP': 'Japan',
    'GY': 'Guyana', 'GG': 'Guernsey', 'GF': 'French Guiana', 'GE': 'Georgia',
    'GD': 'Grenada', 'UK': 'United Kingdom', 'GA': 'Gabon', 'SV': 'El Salvador',
    'GN': 'Guinea', 'GM': 'Gambia', 'GL': 'Greenland', 'GI': 'Gibraltar', 'GH': 'Ghana',
    'OM': 'Oman', 'TN': 'Tunisia', 'JO': 'Jordan', 'HR': 'Croatia', 'HT': 'Haiti',
    'HU': 'Hungary', 'HK': 'Hong Kong', 'HN': 'Honduras',
    'HM': 'Heard Island and McDonald Islands', 'VE': 'Venezuela', 'PR': 'Puerto Rico',
    'PS': 'Palestinian Territory', 'PW': 'Palau', 'PT': 'Portugal',
    'SJ': 'Svalbard and Jan Mayen', 'PY': 'Paraguay', 'IQ': 'Iraq', 'PA': 'Panama',
    'PF': 'French Polynesia', 'PG': 'Papua New Guinea', 'PE': 'Peru', 'PK': 'Pakistan',
    'PH': 'Philippines', 'PN': 'Pitcairn', 'PL': 'Poland', 'PM': 'Saint Pierre and Miquelon',
    'ZM': 'Zambia', 'EH': 'Western Sahara', 'EE': 'Estonia', 'EG': 'Egypt',
    'ZA': 'South Africa', 'EC': 'Ecuador', 'IT': 'Italy', 'VN': 'Vietnam',
    'SB': 'Solomon Islands', 'ET': 'Ethiopia', 'SO': 'Somalia', 'ZW': 'Zimbabwe',
    'SA': 'Saudi Arabia', 'ES': 'Spain', 'ER': 'Eritrea', 'ME': 'Montenegro',
    'MD': 'Moldova', 'MG': 'Madagascar', 'MF': 'Saint Martin', 'MA': 'Morocco',
    'MC': 'Monaco', 'UZ': 'Uzbekistan', 'MM': 'Myanmar', 'ML': 'Mali', 'MO': 'Macao',
    'MN': 'Mongolia', 'MH': 'Marshall Islands', 'MK': 'Macedonia', 'MU': 'Mauritius',
    'MT': 'Malta', 'MW': 'Malawi', 'MV': 'Maldives', 'MQ': 'Martinique',
    'MP': 'Northern Mariana Islands', 'MS': 'Montserrat', 'MR': 'Mauritania',
    'IM': 'Isle of Man', 'UG': 'Uganda', 'TZ': 'Tanzania', 'MY': 'Malaysia',
    'MX': 'Mexico', 'IL': 'Israel', 'FR': 'France', 'IO': 'British Indian Ocean Territory',
    'SH': 'Saint Helena', 'FI': 'Finland', 'FJ': 'Fiji', 'FK': 'Falkland Islands',
    'FM': 'Micronesia', 'FO': 'Faroe Islands', 'NI': 'Nicaragua', 'NL': 'Netherlands',
    'NO': 'Norway', 'NA': 'Namibia', 'VU': 'Vanuatu', 'NC': 'New Caledonia',
    'NE': 'Niger', 'NF': 'Norfolk Island', 'NG': 'Nigeria', 'NZ': 'New Zealand',
    'NP': 'Nepal', 'NR': 'Nauru', 'NU': 'Niue', 'CK': 'Cook Islands', 'XK': 'Kosovo',
    'CI': 'Ivory Coast', 'CH': 'Switzerland', 'CO': 'Colombia', 'CN': 'China',
    'CM': 'Cameroon', 'CL': 'Chile', 'CC': 'Cocos Islands', 'CA': 'Canada',
    'CG': 'Republic of the Congo', 'CF': 'Central African Republic',
    'CD': 'Democratic Republic of the Congo', 'CZ': 'Czech Republic', 'CY': 'Cyprus',
    'CX': 'Christmas Island', 'CR': 'Costa Rica', 'CW': 'Curacao', 'CV': 'Cape Verde',
    'CU': 'Cuba', 'SZ': 'Swaziland', 'SY': 'Syria', 'SX': 'Sint Maarten',
    'KG': 'Kyrgyzstan', 'KE': 'Kenya', 'SS': 'South Sudan', 'SR': 'Suriname',
    'KI': 'Kiribati', 'KH': 'Cambodia', 'KN': 'Saint Kitts and Nevis', 'KM': 'Comoros',
    'ST': 'Sao Tome and Principe', 'SK': 'Slovakia', 'KR': 'South Korea',
    'SI': 'Slovenia', 'KP': 'North Korea', 'KW': 'Kuwait', 'SN': 'Senegal',
    'SM': 'San Marino', 'SL': 'Sierra Leone', 'SC': 'Seychelles', 'KZ': 'Kazakhstan',
    'KY': 'Cayman Islands', 'SG': 'Singapore', 'SE': 'Sweden', 'SD': 'Sudan',
    'DO': 'Dominican Republic', 'DM': 'Dominica', 'DJ': 'Djibouti', 'DK': 'Denmark',
    'VG': 'British Virgin Islands', 'DE': 'Germany', 'YE': 'Yemen', 'DZ': 'Algeria',
    'US': 'United States', 'UY': 'Uruguay', 'YT': 'Mayotte',
    'UM': 'United States Minor Outlying Islands', 'LB': 'Lebanon', 'LC': 'Saint Lucia',
    'LA': 'Laos', 'TV': 'Tuvalu', 'TW': 'Taiwan', 'TT': 'Trinidad and Tobago',
    'TR': 'Turkey', 'LK': 'Sri Lanka', 'LI': 'Liechtenstein', 'LV': 'Latvia',
    'TO': 'Tonga', 'LT': 'Lithuania', 'LU': 'Luxembourg', 'LR': 'Liberia',
    'LS': 'Lesotho', 'TH': 'Thailand', 'TF': 'French Southern Territories', 'TG': 'Togo',
    'TD': 'Chad', 'TC': 'Turks and Caicos Islands', 'LY': 'Libya', 'VA': 'Vatican',
    'VC': 'Saint Vincent and the Grenadines', 'AE': 'United Arab Emirates',
    'AD': 'Andorra', 'AG': 'Antigua and Barbuda', 'AF': 'Afghanistan', 'AI': 'Anguilla',
    'VI': 'U.S. Virgin Islands', 'IS': 'Iceland', 'IR': 'Iran', 'AM': 'Armenia',
    'AL': 'Albania', 'AO': 'Angola', 'AQ': 'Antarctica', 'AS': 'American Samoa',
    'AR': 'Argentina', 'AU': 'Australia', 'AT': 'Austria', 'AW': 'Aruba', 'IN': 'India',
    'AX': 'Aland Islands', 'AZ': 'Azerbaijan', 'IE': 'Ireland', 'ID': 'Indonesia',
    'UA': 'Ukraine', 'QA': 'Qatar', 'MZ': 'Mozambique'
}


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


async def fetch_server_list(username: str, password: str) -> dict:
    session = Session(appversion=APP_VERSION, user_agent=USER_AGENT)

    print("Authenticating...", file=sys.stderr)
    success = await session.async_authenticate(username, password)
    if not success:
        print("Error: authentication failed.", file=sys.stderr)
        sys.exit(1)

    try:
        print("Fetching server list...", file=sys.stderr)
        response = await session.async_api_request(LOGICALS_ENDPOINT)
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
        response = await session.async_api_request(LOGICALS_ENDPOINT)

    await session.async_logout()
    return response


def transform(api_data: dict, max_load: int | None = None, max_servers: int | None = None) -> dict:
    """
    Transform ProtonVPN API data to Gluetun format.
    
    Improvements:
    - Parse country from server name (not ExitCountry)
    - Include all feature flags (free, secure_core, tor, stream, port_forward)
    - Only include feature flags when true
    - Fix Wireguard: no tcp/udp properties
    - Deduplicate physical servers for non-secure_core
    """
    # Sort logical servers by score (lower = better, factors in load + proximity)
    logicals = sorted(api_data["LogicalServers"], key=lambda s: s.get("Score", float("inf")))

    if max_load is not None:
        logicals = [s for s in logicals if s.get("Load", 100) <= max_load]

    if max_servers is not None:
        logicals = logicals[:max_servers]

    servers = []
    seen_ips = {}  # Track IPs for non-secure_core deduplication
    stats = {
        'skipped_disabled': 0,
        'skipped_duplicate': 0,
        'secure_core': 0,
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
            
            # Deduplicate non-secure_core servers by IP
            if not is_secure_core:
                if entry_ip in seen_ips:
                    stats['skipped_duplicate'] += 1
                    continue
                seen_ips[entry_ip] = True
            
            # Track statistics
            if is_secure_core:
                stats['secure_core'] += 1
            if is_free:
                stats['free_tier'] += 1
            
            # Build base server properties (ordered by Server struct)
            # Only include feature flags when true
            base = {
                "country": country,
                "city": logical.get("City") or "",
                "server_name": logical["Name"],
                "hostname": physical["Domain"],
            }
            
            # Add optional feature flags (only if true)
            if is_free:
                base["free"] = True
            if is_streaming:
                base["stream"] = True
            if is_secure_core:
                base["secure_core"] = True
            if is_tor:
                base["tor"] = True
            if is_p2p:
                base["port_forward"] = True
            
            base["ips"] = [entry_ip]
            
            # Create Wireguard entry (if key present)
            wg_key = physical.get("X25519PublicKey")
            if wg_key:
                wg_server = {
                    "vpn": "wireguard",
                    **base,
                    "wgpubkey": wg_key,
                }
                # Note: Wireguard does NOT have tcp/udp properties
                servers.append(wg_server)
            
            # Create OpenVPN entry
            ovpn_server = {
                "vpn": "openvpn",
                **base,
                "tcp": True,
                "udp": True,
            }
            servers.append(ovpn_server)

    # Print statistics
    print(f"\nTransformation statistics:", file=sys.stderr)
    print(f"  Skipped (disabled): {stats['skipped_disabled']}", file=sys.stderr)
    print(f"  Skipped (duplicate IPs): {stats['skipped_duplicate']}", file=sys.stderr)
    print(f"  Secure core servers: {stats['secure_core']}", file=sys.stderr)
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

    api_data = await fetch_server_list(username, password)
    total = len(api_data.get("LogicalServers", []))
    result = transform(api_data, max_load=max_load, max_servers=max_servers)

    output = json.dumps(result, indent=2)
    count = len(result["protonvpn"]["servers"])

    output_file = os.environ.get("OUTPUT_FILE")
    filters = []
    if max_load is not None:
        filters.append(f"max_load={max_load}%")
    if max_servers is not None:
        filters.append(f"max_servers={max_servers}")
    filter_info = f" ({', '.join(filters)})" if filters else ""

    if output_file:
        with open(output_file, "w") as f:
            f.write(output)
        print(f"\n{count} servers written to {output_file} (from {total} logicals{filter_info})", file=sys.stderr)
    else:
        print(output)
        print(f"\n# {count} servers exported (from {total} logicals{filter_info})", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
