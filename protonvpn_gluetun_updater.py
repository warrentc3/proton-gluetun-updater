#!/usr/bin/env python3
"""
Fetch the Proton VPN server list and export it in Gluetun custom
provider format (servers.json).

Authenticates directly against the Proton API using SRP.

Environment variables (or interactive prompt):
    PROTON_USERNAME   Proton account username
    PROTON_PASSWORD   Proton account password
    PROTON_2FA        TOTP code (optional, only if 2FA is enabled)
    OUTPUT_FILE       Output file path (default: stdout)
"""
import asyncio
import getpass
import json
import os
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

COUNTRY_NAMES = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan",
    "AL": "Albania", "AM": "Armenia", "AR": "Argentina", "AT": "Austria",
    "AU": "Australia", "AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina",
    "BD": "Bangladesh", "BE": "Belgium", "BG": "Bulgaria", "BR": "Brazil",
    "CA": "Canada", "CH": "Switzerland", "CL": "Chile", "CM": "Cameroon",
    "CO": "Colombia", "CR": "Costa Rica", "CY": "Cyprus", "CZ": "Czech Republic",
    "DE": "Germany", "DK": "Denmark", "EC": "Ecuador", "EE": "Estonia",
    "EG": "Egypt", "ES": "Spain", "FI": "Finland", "FR": "France",
    "GE": "Georgia", "GH": "Ghana", "GR": "Greece", "HK": "Hong Kong",
    "HR": "Croatia", "HU": "Hungary", "ID": "Indonesia", "IE": "Ireland",
    "IL": "Israel", "IN": "India", "IS": "Iceland", "IT": "Italy",
    "JP": "Japan", "KE": "Kenya", "KH": "Cambodia", "KR": "South Korea",
    "KZ": "Kazakhstan", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia",
    "MA": "Morocco", "MD": "Moldova", "ME": "Montenegro", "MK": "North Macedonia",
    "MM": "Myanmar", "MN": "Mongolia", "MX": "Mexico", "MY": "Malaysia",
    "NG": "Nigeria", "NL": "Netherlands", "NO": "Norway", "NZ": "New Zealand",
    "PA": "Panama", "PE": "Peru", "PH": "Philippines", "PK": "Pakistan",
    "PL": "Poland", "PR": "Puerto Rico", "PT": "Portugal", "RO": "Romania",
    "RS": "Serbia", "RU": "Russia", "SE": "Sweden", "SG": "Singapore",
    "SI": "Slovenia", "SK": "Slovakia", "TH": "Thailand", "TN": "Tunisia",
    "TR": "Turkey", "TW": "Taiwan", "UA": "Ukraine", "UK": "United Kingdom",
    "US": "United States", "UY": "Uruguay", "VN": "Vietnam", "ZA": "South Africa",
}


def country_name(code: str) -> str:
    return COUNTRY_NAMES.get(code, code)


def get_credentials() -> tuple[str, str]:
    username = os.environ.get("PROTON_USERNAME")
    password = os.environ.get("PROTON_PASSWORD")

    if not username:
        username = input("Proton username: ")
    if not password:
        password = getpass.getpass("Proton password: ")

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
            totp_code = input("2FA code: ")

        success = await session.async_validate_2fa_code(totp_code)
        if not success:
            print("Error: invalid 2FA code.", file=sys.stderr)
            sys.exit(1)

        print("Fetching server list...", file=sys.stderr)
        response = await session.async_api_request(LOGICALS_ENDPOINT)

    await session.async_logout()
    return response


def transform(api_data: dict) -> dict:
    servers = []
    for logical in api_data["LogicalServers"]:
        features = logical.get("Features", 0)
        common = {
            "country": country_name(logical["ExitCountry"]),
            "city": logical.get("City") or "",
            "server_name": logical["Name"],
            "stream": bool(features & STREAMING),
            "port_forward": bool(features & P2P),
        }

        for physical in logical["Servers"]:
            ips = [physical["EntryIP"]]

            wg_key = physical.get("X25519PublicKey")
            if wg_key:
                servers.append({
                    **common,
                    "vpn": "wireguard",
                    "hostname": physical["Domain"],
                    "wgpubkey": wg_key,
                    "tcp": True,
                    "udp": True,
                    "ips": ips,
                })

            servers.append({
                **common,
                "vpn": "openvpn",
                "hostname": physical["Domain"],
                "tcp": True,
                "udp": True,
                "ips": ips,
            })

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
    api_data = await fetch_server_list(username, password)
    result = transform(api_data)

    output = json.dumps(result, indent=2)
    count = len(result["protonvpn"]["servers"])

    output_file = os.environ.get("OUTPUT_FILE")
    if output_file:
        with open(output_file, "w") as f:
            f.write(output)
        print(f"{count} servers written to {output_file}", file=sys.stderr)
    else:
        print(output)
        print(f"\n# {count} servers exported", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
