# ProtonVPN Gluetun Updater

A companion container for [Gluetun](https://github.com/qdm12/gluetun) that automatically fetches and transforms the ProtonVPN server list into the format used by Gluetun. Authenticates directly against the Proton API using SRP — no dependency on the ProtonVPN desktop app.

![Web dashboard](https://github.com/user-attachments/assets/ef592d4b-df6a-4c63-83b9-b122469b5993)

## Features

- Authenticates with the Proton API (SRP) with full 2FA (TOTP) support
- Exports a `servers-proton.json` file in Gluetun custom-provider format
- Optionally merges or replaces Gluetun's `servers.json` to keep it in sync
- Filters servers by type: Secure Core, TOR, free tier, IPv6
- Live web dashboard with manual controls and run statistics
- Filter settings persist across restarts in `config.yaml` and can be changed at runtime without restarting
- Caches raw API responses locally — avoids unnecessary requests on restart
- Supports Docker secrets for credential storage
- Single Python file, no extra runtime dependencies beyond `PyYAML` and the Proton library

---

## Quick start

```yaml
# docker-compose.yml
services:
  gtupdate:
    image: ghcr.io/warrentc3/proton-gluetun-updater:latest
    container_name: protonvpn-gluetun-updater
    volumes:
      - /path/to/gluetun:/gluetun
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      PROTON_USERNAME: your@email.com
      PROTON_PASSWORD: yourpassword
      STORAGE_FILEPATH: /gluetun
      GLUETUN_SERVERS_JSON: update   # merge ProtonVPN servers into servers.json
      WEB_HOST: 0.0.0.0
```

Set `STORAGE_FILEPATH` to Gluetun's data directory — or directly to `servers.json` inside it (e.g. `/gluetun/servers.json`). When a file path is given, the parent directory is inferred automatically. The updater writes `servers-proton.json` there and, when `GLUETUN_SERVERS_JSON` is not `none`, also updates `servers.json`.

---

## Environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PROTON_USERNAME` | Yes* | — | Proton account username. Can be omitted when the `proton_username` Docker secret is used. |
| `PROTON_PASSWORD` | Yes* | — | Proton account password. Can be omitted when the `proton_password` Docker secret is used. |
| `STORAGE_FILEPATH` | Yes | — | Intentionally used the same variable name as the Gluetun container, which maps to `/gluetun/servers.json`. |
| `WEB_HOST` | No | `127.0.0.1` | Dashboard bind address. Set to `0.0.0.0` to expose inside Docker (control access via port binding or a reverse proxy). |
| `WEB_PORT` | No | `8080` | Dashboard port. |

These filter variables are only applied **when `config.yaml` does not yet exist**. Once the file is created (first run), the dashboard controls or direct edits to `config.yaml` take precedence.
| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `GLUETUN_SERVERS_JSON` | No | `none` | How to handle Gluetun's `servers.json`: `none` (don't touch it), `replace` (overwrite entirely with ProtonVPN-only content), or `update` (merge ProtonVPN servers in, preserving all other providers). |
| `IP6` | No | `exclude` | IPv6 behavior: `include` (add IPv6 IPs to each server entry), `exclude` (strip IPv6 from output), or `only` (only output servers that have an IPv6 address). IPv6 data is always fetched from the API regardless of this setting. |
| `SECURE_CORE` | No | `include` | Filter for Secure Core servers: `include`, `exclude`, or `only`. |
| `TOR` | No | `include` | Filter for TOR servers: `include`, `exclude`, or `only`. |
| `FREE_TIER` | No | `include` | Filter for free-tier servers: `include`, `exclude`, or `only`. |



---

## Docker secrets

Credentials can be supplied via [Docker secrets](https://docs.docker.com/compose/how-tos/use-secrets/) instead of environment variables, keeping them out of `docker inspect` output and compose files:

```yaml
secrets:
  proton_username:
    file: ./secrets/proton_username.txt
  proton_password:
    file: ./secrets/proton_password.txt

services:
  gtupdate:
    image: ghcr.io/warrentc3/proton-gluetun-updater:latest
    secrets:
      - proton_username
      - proton_password
    environment:
      STORAGE_FILEPATH: /gluetun
    volumes:
      - /path/to/gluetun:/gluetun
```

Secret files must contain only the value with no surrounding quotes or extra whitespace. Credential lookup order: environment variable → Docker secret → interactive prompt (TTY only).

---

## Output files

| File | Description |
| --- | --- |
| `$STORAGE_FILEPATH/servers-proton.json` | Always written. ProtonVPN servers in Gluetun custom-provider format. |
| `$STORAGE_FILEPATH/servers.json` | Written only when `GLUETUN_SERVERS_JSON` is `replace` or `update`. |
| `$STORAGE_FILEPATH/proton/serverlist.<timestamp>.json` | Raw API cache (up to 3 files kept). Reused on restart if under 12 hours old. |
| `$STORAGE_FILEPATH/proton/config.yaml` | Persistent filter configuration. Edited via the dashboard or directly. |

---

## Filtering

Each filter accepts three values:

| Value | Behaviour |
| --- | --- |
| `include` | Include these servers in the output (default for all filters) |
| `exclude` | Remove these servers from the output |
| `only` | Output only these servers, removing all others |

Filters can be combined freely. For example, `SECURE_CORE=only` + `TOR=exclude` outputs only Secure Core servers that are not also TOR exit nodes.

### Sort order

Servers are sorted before filtering:

1. Secure Core first
2. TOR servers next
3. Alphabetically by country, then city
4. Load ascending (lowest load first)

### Physical server deduplication

For non-Secure Core servers, physical servers with duplicate IP addresses are deduplicated — each unique IP appears only once in the output.

---

## Web dashboard

A lightweight dashboard is served on `WEB_PORT` (default `8080`) with no extra dependencies. It auto-refreshes every 10 seconds.

### Status card

Shows the current state badge (starting / authenticating / running / sleeping / waiting for 2FA / error), uptime, last run time, next scheduled run, and server count.

**Fetch Now** — bypasses the cache and immediately pulls a fresh server list from the Proton API, then transforms and writes the output files.

### Filter Configuration

A collapsible panel with dropdowns for all five filter settings. Three buttons are available:

- **Apply** — saves the current dropdown selections to `config.yaml`. Does not re-transform; use Reprocess after applying to regenerate output files immediately.
- **Reprocess** — re-runs the transform using the most recent cached server list and the current filter config, then writes output files. Use this after changing filters without wanting to fetch fresh data.
- **Fetch Now** — fetches a fresh server list from the Proton API regardless of cache age, then transforms and writes output files.

### Last Run Statistics

Shown after each successful run. Displays a table of total vs. in-output counts for: physical servers, logical servers, IPv6 servers, TOR, Secure Core, free, P2P, and streaming. Filtered-out categories show 0 in the "In Output" column.

### 2FA

The 2FA card is always visible. When a TOTP code is required during authentication it activates (orange border); otherwise it appears muted and disabled. Invalid codes show an inline error and allow retry without restarting the container. Only TOTP (6–8 digit codes) is supported — FIDO2/hardware keys are not.

### Theme

A light/dark toggle is fixed to the top-right corner. The preference is saved to `localStorage` and defaults to dark mode.

> **Security note:** The dashboard has no authentication. By default it binds to `127.0.0.1` (localhost only). To expose it inside a Docker container, set `WEB_HOST=0.0.0.0` and restrict access via Docker port binding (e.g. `-p 127.0.0.1:8080:8080`) or a reverse proxy with authentication.

---

## API endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | HTML dashboard |
| `GET` | `/status` | JSON status payload (polled every 10 s by the dashboard) |
| `POST` | `/config` | Save filter settings (form-encoded). Does not reprocess. |
| `POST` | `/reprocess` | Re-transform from cached data and write output files. Returns 404 if no cache exists. |
| `POST` | `/refresh` | Force-fetch fresh data from the Proton API, then transform and write. Returns 409 if a run is already in progress. |
| `POST` | `/2fa` | Submit a TOTP code. Returns 400 if not currently waiting or if the code format is invalid. |

---

## Update schedule

After each successful fetch, the updater sleeps until the cached data reaches 12 hours of age, plus a random jitter of 0–4 hours (to spread load). On restart, if a cache file under 12 hours old is found, the initial fetch is skipped and the updater goes straight to sleep until the cache expires. Use **Fetch Now** to pull a fresh list at any time.

---

## License

MIT
