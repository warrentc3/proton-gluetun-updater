# protonvpn-gluetun-updater

Fetch the Proton VPN server list and export it as a [Gluetun](https://github.com/qdm12/gluetun) custom provider `servers.json` file.

Authenticates directly against the Proton API (SRP) — no dependency on the Proton VPN desktop app.

## Output format

The generated JSON follows the [Gluetun custom provider](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/custom.md) format and includes both **WireGuard** and **OpenVPN** server entries.

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
