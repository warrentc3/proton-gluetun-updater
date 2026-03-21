Companion container for [Gluetun](https://github.com/qdm12/gluetun) to fetch the Proton VPN server list. Authenticates directly against the Proton API (SRP) — no dependency on the Proton VPN desktop app.

`servers-proton.json` is always written to `STORAGE_FILEPATH`. Use `GLUETUN_SERVERS_JSON=update` to merge ProtonVPN servers into the existing `servers.json` while preserving all other providers, or `GLUETUN_SERVERS_JSON=replace` to overwrite `servers.json` entirely with ProtonVPN-only content.


## Environment variables
| Variable           | Required | Description                                                                                           |
| ------------------ | -------- | ----------------------------------------------------------------------------------------------------- |
| `PROTON_USERNAME`  | Yes*     | Proton account username. Can be omitted if the Docker secret `proton_username` is used instead.       |
| `PROTON_PASSWORD`  | Yes*     | Proton account password. Can be omitted if the Docker secret `proton_password` is used instead.       |
| `STORAGE_FILEPATH` | Yes      | Storage directory path                                          |
| `WEB_HOST`         | No       | Web dashboard bind address (default: `127.0.0.1` for localhost-only access; use `0.0.0.0` to expose publicly) |
| `WEB_PORT`         | No       | Port for the web dashboard (default: `8080`)                                                          |
| `GLUETUN_SERVERS_JSON` | No  | How to update Gluetun's `servers.json`: `none` (default, don't touch it), `replace` (overwrite entirely with ProtonVPN-only content), or `update` (merge ProtonVPN servers into the existing file, preserving all other providers) |
| `REPLACE_GLUETUN_SERVERS_JSON` | No | **Deprecated.** Use `GLUETUN_SERVERS_JSON=replace` instead. Still accepted for backward compatibility. |
| `FREE_TIER`        | No       | Filter free tier servers: `include` (default), `exclude`, or `only`                                   |
| `SECURE_CORE`      | No       | Filter Secure Core servers: `include` (default), `exclude`, or `only`                                 |
| `TOR`              | No       | Filter TOR servers: `include` (default), `exclude`, or `only`                                         |
| `IP6`              | No       | IPv6 address behavior: `include` (add IPv6 IPs to server entries when available), `exclude` (default, strip IPv6 from output), or `only` (filter to servers with IPv6 and include their IPs). IPv6 data is always fetched from the API. |


### Docker secrets (optional)

As an alternative to environment variables, credentials can be supplied via [Docker secrets](https://docs.docker.com/compose/how-tos/use-secrets/), which keeps them out of `docker inspect` output and compose files:

```yaml
secrets:
  proton_username:
    file: ./secrets/proton_username.txt
  proton_password:
    file: ./secrets/proton_password.txt

services:
  gtupdate:
    secrets:
      - proton_username
      - proton_password
    # PROTON_USERNAME / PROTON_PASSWORD env vars can be omitted when secrets are used
```

Secret files should contain only the value — no surrounding quotes or extra whitespace. The lookup order is: environment variable → Docker secret → interactive prompt.

### Filtering and sorting
Servers are sorted by: secure_core first, then TOR, then alphabetically by country and city, then by **load ascending** (lower load = better).
The filtering pipeline works as follows:

1. **Sort** all logical servers by priority: secure_core first, then TOR, then alphabetically by country, city, and load (ascending)
2. **Filter by server type** — apply `SECURE_CORE`, `TOR`, `FREE_TIER`, and `IP6` filters:
   - `include` (default): include these servers in the output
   - `exclude`: exclude these servers from the output
   - `only`: only include these servers (exclude all others)

Without any filter, all servers are exported (sorted by secure_core, TOR, country, city, load).

## Web Dashboard
![Example](https://github.com/user-attachments/assets/ef592d4b-df6a-4c63-83b9-b122469b5993)

A lightweight web dashboard is always available on `WEB_PORT` (default `8080`). No extra dependencies are required — it uses Python's built-in `asyncio`.

**Endpoints:**
- `GET /` — status page with live stats
- `GET /status` — JSON status (polled every 10 s by the page)
- `POST /2fa` — submit a TOTP code when 2FA is required

**Stats shown:** current state (starting / authenticating / running / sleeping / waiting 2FA / error), uptime, total run count, last run time, next run time, servers written, and last error. After each successful run a **Last Run Statistics** table is shown with total vs in-output counts across 8 categories (physical servers, logical servers, IPv6, TOR, secure core, free, P2P, streaming).

**2FA:** The 2FA input card is always visible. When a TOTP code is required it activates with an orange border; otherwise it is shown in a muted/disabled state. Invalid codes display an inline error and allow retry without restarting the container.

**Theme:** A light/dark mode toggle is available in the top-right corner. The preference is saved to `localStorage` and defaults to dark mode.

> **Security Note:** The dashboard has no authentication and includes a 2FA submission endpoint. By default it binds to `127.0.0.1` (localhost-only) for safety. To expose it in a Docker container, set `WEB_HOST=0.0.0.0` and control access via Docker port binding (`-p 127.0.0.1:8080:8080`) or a reverse proxy with authentication.

## License

MIT
