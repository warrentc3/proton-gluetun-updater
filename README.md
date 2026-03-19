# protonvpn-gluetun-updater

Fetch the Proton VPN server list and export it as a [Gluetun](https://github.com/qdm12/gluetun) custom provider `servers.json` file.

Authenticates directly against the Proton API (SRP) — no dependency on the Proton VPN desktop app.

## How it works

The script authenticates against the Proton API via SRP, then fetches the server list from the `/vpn/v1/logicals` endpoint.

The Proton API returns a list of **logical servers**, each containing one or more **physical servers** (nodes):

```json
{
  "LogicalServers": [
    {
      "Name": "CH#485",
      "ExitCountry": "CH",
      "City": "Zurich",
      "Domain": "node-ch-9999.protonvpn.net",
      "Features": 12,
      "Load": 23,
      "Score": 1.0234,
      "Status": 1,
      "Servers": [
        {
          "EntryIP": "146.70.226.194",
          "Domain": "node-ch-9999.protonvpn.net",
          "X25519PublicKey": "JuU8atNk6x75cZiCI8TuYnnDfFs4MUSZZomSWKKl1Rs="
        }
      ]
    }
  ]
}
```

The script iterates over each logical server and its physical servers, and produces two Gluetun entries per physical server:

- A **WireGuard** entry (if `X25519PublicKey` is present)
- An **OpenVPN** entry

The `Features` field is a bitmask decoded as follows:

| Bit | Value | Feature |
|---|---|---|
| 0 | 1 | Secure Core |
| 1 | 2 | TOR |
| 2 | 4 | P2P (`port_forward`) |
| 3 | 8 | Streaming (`stream`) |
| 4 | 16 | IPv6 |

For example, `"Features": 12` = P2P (4) + Streaming (8) → `"port_forward": true, "stream": true`.

The resulting Gluetun output for the example above:

```json
{
  "version": 1,
  "protonvpn": {
    "version": 4,
    "timestamp": 1721997873,
    "servers": [
      {
        "vpn": "wireguard",
        "country": "Switzerland",
        "city": "Zurich",
        "server_name": "CH#485",
        "hostname": "node-ch-9999.protonvpn.net",
        "wgpubkey": "JuU8atNk6x75cZiCI8TuYnnDfFs4MUSZZomSWKKl1Rs=",
        "tcp": true,
        "udp": true,
        "stream": true,
        "port_forward": true,
        "ips": ["146.70.226.194"]
      },
      {
        "vpn": "openvpn",
        "country": "Switzerland",
        "city": "Zurich",
        "server_name": "CH#485",
        "hostname": "node-ch-9999.protonvpn.net",
        "tcp": true,
        "udp": true,
        "stream": true,
        "port_forward": true,
        "ips": ["146.70.226.194"]
      }
    ]
  }
}
```

## Usage

### Python

```bash
pip install -r requirements.txt

# Interactive (prompts for credentials and 2FA code)
STORAGE_FILEPATH=/data/gluetun \
python protonvpn_gluetun_updater.py

# Via environment variables
PROTON_USERNAME=user \
PROTON_PASSWORD=pass \
PROTON_2FA=123456 \
STORAGE_FILEPATH=/data/gluetun \
python protonvpn_gluetun_updater.py

# Include IPv6 addresses
PROTON_USERNAME=user \
PROTON_PASSWORD=pass \
INCLUDE_IPV6=true \
STORAGE_FILEPATH=/data/gluetun \
python protonvpn_gluetun_updater.py

# Enable debug mode (saves to STORAGE_FILEPATH/debug)
PROTON_USERNAME=user \
PROTON_PASSWORD=pass \
DEBUG=true \
STORAGE_FILEPATH=/data/gluetun \
python protonvpn_gluetun_updater.py

# Debug mode with custom directory
PROTON_USERNAME=user \
PROTON_PASSWORD=pass \
DEBUG=true \
DEBUG_DIR=/tmp/protonvpn-debug \
STORAGE_FILEPATH=/data/gluetun \
python protonvpn_gluetun_updater.py

# Combined: IPv6 enabled + debug mode + filtering
PROTON_USERNAME=user \
PROTON_PASSWORD=pass \
INCLUDE_IPV6=true \
DEBUG=true \
MAX_LOAD=75 \
STORAGE_FILEPATH=/data/gluetun \
python protonvpn_gluetun_updater.py
```

### Docker

Pull the latest image from GitHub Container Registry:

```bash
docker pull ghcr.io/warrentc3/proton-gluetun-updater:latest
```

Or build from source:

```bash
docker build -t protonvpn-gluetun-updater .
```

Run with the GHCR image:

```bash
docker run --rm \
  -e PROTON_USERNAME=user \
  -e PROTON_PASSWORD=pass \
  -e PROTON_2FA=123456 \
  -e STORAGE_FILEPATH=/gluetun \
  -v /path/to/gluetun:/gluetun \
  ghcr.io/warrentc3/proton-gluetun-updater:latest

# Only servers with load <= 50% and keep the 100 best
docker run --rm \
  -e PROTON_USERNAME=user \
  -e PROTON_PASSWORD=pass \
  -e PROTON_2FA=123456 \
  -e MAX_LOAD=50 \
  -e MAX_SERVERS=100 \
  -e STORAGE_FILEPATH=/gluetun \
  -v /path/to/gluetun:/gluetun \
  ghcr.io/warrentc3/proton-gluetun-updater:latest

# Include IPv6 addresses
docker run --rm \
  -e PROTON_USERNAME=user \
  -e PROTON_PASSWORD=pass \
  -e INCLUDE_IPV6=true \
  -e STORAGE_FILEPATH=/gluetun \
  -v /path/to/gluetun:/gluetun \
  ghcr.io/warrentc3/proton-gluetun-updater:latest

# Enable debug mode (saves to /gluetun by default)
docker run --rm \
  -e PROTON_USERNAME=user \
  -e PROTON_PASSWORD=pass \
  -e DEBUG=true \
  -e STORAGE_FILEPATH=/gluetun \
  -v /path/to/gluetun:/gluetun \
  ghcr.io/warrentc3/proton-gluetun-updater:latest

# Debug with custom directory
docker run --rm \
  -e PROTON_USERNAME=user \
  -e PROTON_PASSWORD=pass \
  -e DEBUG=true \
  -e DEBUG_DIR=/debug \
  -e STORAGE_FILEPATH=/gluetun \
  -v /path/to/gluetun:/gluetun \
  -v /path/to/debug:/debug \
  ghcr.io/warrentc3/proton-gluetun-updater:latest

# Full example: filtering + IPv6 + debug
docker run --rm \
  -e PROTON_USERNAME=user \
  -e PROTON_PASSWORD=pass \
  -e MAX_LOAD=50 \
  -e MAX_SERVERS=100 \
  -e INCLUDE_IPV6=true \
  -e DEBUG=true \
  -e STORAGE_FILEPATH=/gluetun \
  -v /path/to/gluetun:/gluetun \
  ghcr.io/warrentc3/proton-gluetun-updater:latest
```

> **Note:** When using Docker, the `PROTON_2FA` environment variable is required if your account has 2FA enabled (interactive prompt is not available).

### Filtering and scoring

Each logical server returned by the Proton API includes two fields used for ranking:

- **`Load`** (0–100) — current usage percentage of the server
- **`Score`** (float, lower = better) — internal Proton metric that combines server load and geographic proximity to the user

The filtering pipeline works as follows:

1. **Sort** all logical servers by `Score` (ascending — best servers first)
2. **Filter by load** — if `MAX_LOAD` is set, discard any server where `Load > MAX_LOAD`
3. **Truncate** — if `MAX_SERVERS` is set, keep only the first N servers from the sorted list

Both filters are optional and can be combined. For example, `MAX_LOAD=50 MAX_SERVERS=100` first removes all servers above 50% load, then keeps the 100 best-scored among the remaining ones.

Without any filter, all servers are exported (sorted by score).

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PROTON_USERNAME` | Yes | Proton account username |
| `PROTON_PASSWORD` | Yes | Proton account password |
| `PROTON_2FA` | No | TOTP code (required if 2FA is enabled on the account) |
| `STORAGE_FILEPATH` | Yes | Storage directory path (output file: `servers-proton.json`) |
| `MAX_LOAD` | No | Only include servers with load <= this value (0-100) |
| `MAX_SERVERS` | No | Limit to the N best servers, sorted by score |
| `INCLUDE_IPV6` | No | Include IPv6 addresses in server entries (`1`/`true`/`yes` or `0`/`false`/`no`, default: `false`) |
| `DEBUG` | No | Save raw API response to debug directory (`1`/`true`/`yes` or `0`/`false`/`no`, default: `false`) |
| `DEBUG_DIR` | No | Debug output directory (default: `STORAGE_FILEPATH/debug` when `DEBUG=true` and `DEBUG_DIR` is unset) |

## Debug Mode

When `DEBUG=true`, the script saves the raw API response from ProtonVPN before transformation. This is useful for:
- Troubleshooting transformation issues
- Analyzing changes in the ProtonVPN API response
- Preserving historical server data

The debug output is saved as `serverlist.{EPOCHTIME}.tar.gz` in the debug directory. The uncompressed JSON is automatically removed after compression to save space.

Example:
```bash
# Save debug output to default location (STORAGE_FILEPATH/debug)
PROTON_USERNAME=user \
PROTON_PASSWORD=pass \
STORAGE_FILEPATH=/data/gluetun \
DEBUG=true \
python protonvpn_gluetun_updater.py

# With storage directory, debug files go to STORAGE_FILEPATH/debug subdirectory
STORAGE_FILEPATH=/data/gluetun \
DEBUG=true \
python protonvpn_gluetun_updater.py

# Save debug output to custom location
DEBUG=true DEBUG_DIR=/data/debug python protonvpn_gluetun_updater.py > servers.json
```

## Country Mapping

The script uses `countries.json` to map 194 country codes to full country names. This file must be present in the same directory as the script. The mapping is loaded at runtime and provides fallback warnings for unknown country codes.

## License

MIT
