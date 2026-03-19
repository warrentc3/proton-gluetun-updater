# protonvpn-gluetun-updater

Fetch the Proton VPN server list and export it as a [Gluetun](https://github.com/qdm12/gluetun) custom provider configuration file.
Authenticates directly against the Proton API (SRP) — no dependency on the Proton VPN desktop app.

## Usage

### Docker Run
```bash
docker run -d \
  -e PROTON_USERNAME=user \
  -e PROTON_PASSWORD=pass \
  -e STORAGE_FILEPATH=/gluetun \
  -v /path/to/gluetun:/gluetun \
  -p 8080:8080 \
  ghcr.io/warrentc3/proton-gluetun-updater:latest
```

### Docker Compose
Use the included [`docker-compose.yml`](docker-compose.yml):

```bash
docker compose up
```

Edit the compose file to set your credentials and paths.

## Environment variables

| Variable           | Required | Description                                                                                           |
| ------------------ | -------- | ----------------------------------------------------------------------------------------------------- |
| `PROTON_USERNAME`  | Yes      | Proton account username                                                                               |
| `PROTON_PASSWORD`  | Yes      | Proton account password                                                                               |
| `STORAGE_FILEPATH` | Yes      | Storage directory path (output file: `servers-proton.json`)                                           |
| `MAX_LOAD`         | No       | Only include servers with load <= this value (0-100)                                                  |
| `MAX_SERVERS`      | No       | Limit to the N best servers after sorting and filtering                                               |
| `SECURE_CORE`      | No       | Filter Secure Core servers: `include` (default), `exclude`, or `only`                                 |
| `TOR`              | No       | Filter TOR servers: `include` (default), `exclude`, or `only`                                         |
| `FREE_TIER`        | No       | Filter free tier servers: `include` (default), `exclude`, or `only`                                   |
| `REPLACE_GLUETUN_SERVERS_JSON` | No | Replace `servers.json` with `servers-proton.json` (`1`/`true`/`yes` or `0`/`false`/`no`, default: `false`) |
| `WEB_PORT`         | No       | Port for the web dashboard (default: `8080`)                                                          |
| `INCLUDE_IPV6`     | No       | Retain IPv6 addresses in server entries (`1`/`true`/`yes` or `0`/`false`/`no`, default: `false`). IPv6 data is always fetched from the API but stripped from output when `false`. |
| `DEBUG`            | No       | Save raw API response to debug directory (`1`/`true`/`yes` or `0`/`false`/`no`, default: `false`)     |
| `DEBUG_DIR`        | No       | Debug output directory (default: `STORAGE_FILEPATH/debug` when `DEBUG=true` and `DEBUG_DIR` is unset) |

## Web Dashboard

A lightweight web dashboard is always available on `WEB_PORT` (default `8080`). No extra dependencies are required — it uses Python's built-in `asyncio`.

**Endpoints:**
- `GET /` — status page with live stats
- `GET /status` — JSON status (polled every 10 s by the page)
- `POST /2fa` — submit a TOTP code when 2FA is required

**Stats shown:** current state (starting / authenticating / running / sleeping / waiting 2FA / error), uptime, total run count, last run time, next run time, servers written, and last error. After each successful run a **Last Run Statistics** table is shown with total vs in-output counts across 8 categories (physical servers, logical servers, IPv6, TOR, secure core, free, P2P, streaming).

**2FA:** The 2FA input card is always visible. When a TOTP code is required it activates with an orange border; otherwise it is shown in a muted/disabled state. Invalid codes display an inline error and allow retry without restarting the container.

**Theme:** A light/dark mode toggle is available in the top-right corner. The preference is saved to `localStorage` and defaults to dark mode.

> **Note:** the dashboard has no authentication. Do not expose it publicly — control access via Docker port binding or a reverse proxy.

## Debug Mode

When `DEBUG=true`, the script saves the raw API response from ProtonVPN before transformation. This is useful for:
- Troubleshooting transformation issues
- Analyzing changes in the ProtonVPN API response
- Preserving historical server data

The debug output is saved as `serverlist.{EPOCHTIME}.tar.gz` in the debug directory. The uncompressed JSON is automatically removed after compression to save space.

### Filtering and scoring

Each logical server returned by the Proton API includes two fields used for ranking:

- **`Load`** (0–100) — current usage percentage of the server
- **`Score`** (float, lower = better) — internal Proton metric that combines server load and geographic proximity to the user

The filtering pipeline works as follows:

1. **Sort** all logical servers by priority: secure_core servers first, then TOR servers, then alphabetically by country, city, and score (ascending)
2. **Filter by load** — if `MAX_LOAD` is set, discard any server where `Load > MAX_LOAD`
3. **Filter by server type** — apply `SECURE_CORE`, `TOR`, and `FREE_TIER` filters:
   - `include` (default): include these servers in the output
   - `exclude`: exclude these servers from the output
   - `only`: only include these servers (exclude all others)
4. **Truncate** — if `MAX_SERVERS` is set, keep only the first N servers from the sorted list

All filters are optional and can be combined. For example:
- `MAX_LOAD=50 MAX_SERVERS=100` — removes servers above 50% load, keeps 100 best
- `SECURE_CORE=only TOR=exclude` — only secure_core servers, excluding any with TOR
- `TOR=only` — only TOR servers
- `FREE_TIER=exclude` — exclude all free tier servers
- `FREE_TIER=only` — only free tier servers

Without any filter, all servers are exported (sorted by secure_core, TOR, country, city, score).

## License

MIT
