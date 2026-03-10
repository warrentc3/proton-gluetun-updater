# protonvpn-gluetun-updater

Fetch the Proton VPN server list and export it as a [Gluetun](https://github.com/qdm12/gluetun) custom provider `servers.json` file.

Authenticates directly against the Proton API (SRP) — no dependency on the Proton VPN desktop app.

## Output format

The generated JSON follows the [Gluetun custom provider](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/custom.md) format and includes both **WireGuard** and **OpenVPN** server entries.

## Usage

### Python

```bash
pip install -r requirements.txt

# Interactive (prompts for credentials)
python protonvpn_gluetun_updater.py > servers.json

# Via environment variables
PROTON_USERNAME=user PROTON_PASSWORD=pass python protonvpn_gluetun_updater.py > servers.json

# Write directly to a file
OUTPUT_FILE=/gluetun/servers.json PROTON_USERNAME=user PROTON_PASSWORD=pass python protonvpn_gluetun_updater.py
```

### Docker

```bash
docker build -t protonvpn-gluetun-updater .

# Output to stdout
docker run --rm \
  -e PROTON_USERNAME=user \
  -e PROTON_PASSWORD=pass \
  protonvpn-gluetun-updater > servers.json

# Write to a mounted volume (e.g. Gluetun data directory)
docker run --rm \
  -e PROTON_USERNAME=user \
  -e PROTON_PASSWORD=pass \
  -e OUTPUT_FILE=/gluetun/servers.json \
  -v /path/to/gluetun:/gluetun \
  protonvpn-gluetun-updater
```

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PROTON_USERNAME` | Yes | Proton account username |
| `PROTON_PASSWORD` | Yes | Proton account password |
| `PROTON_2FA` | No | TOTP code (if 2FA is enabled) |
| `OUTPUT_FILE` | No | Output file path (defaults to stdout) |

## License

MIT
