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
python protonvpn_gluetun_updater.py > servers.json

# Via environment variables
PROTON_USERNAME=user \
PROTON_PASSWORD=pass \
PROTON_2FA=123456 \
python protonvpn_gluetun_updater.py > servers.json
```

### Docker

```bash
docker build -t protonvpn-gluetun-updater .

docker run --rm \
  -e PROTON_USERNAME=user \
  -e PROTON_PASSWORD=pass \
  -e PROTON_2FA=123456 \
  -e OUTPUT_FILE=/out/servers.json \
  -v /path/to/output:/out \
  protonvpn-gluetun-updater
```

> **Note:** When using Docker, the `PROTON_2FA` environment variable is required if your account has 2FA enabled (interactive prompt is not available).

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PROTON_USERNAME` | Yes | Proton account username |
| `PROTON_PASSWORD` | Yes | Proton account password |
| `PROTON_2FA` | No | TOTP code (required if 2FA is enabled on the account) |
| `OUTPUT_FILE` | No | Output file path (defaults to stdout) |

## License

MIT
