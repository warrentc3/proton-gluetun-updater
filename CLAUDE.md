## Project

protonvpn-gluetun-updater — single-file Python app that authenticates against the Proton VPN API via SRP, fetches the server list, and exports it in Gluetun custom provider format. Runs as a Docker container with a web dashboard for status/2FA handling.

## Build & Test (Docker only)

All local development uses Docker. Do not attempt native Python execution.

### Build

```bash
docker build -t protonvpn-gluetun-updater c:/git/protonvpn-gluetun-updater
```

### Run (local compose)

```bash
cd c:/git/protonvpn-gluetun-updater
docker compose -f docker-compose.local.yml up --build
```

For 2FA testing, edit `docker-compose.local.yml` secret paths from `protonvpn/` to `protonvpn-2fa/`.

`docker-compose.local.yml` is gitignored — it contains local paths and is not shipped.

### Credentials

The app requires `PROTON_USERNAME` and `PROTON_PASSWORD`. Two credential sets exist at `c:\git-cred\` for testing:

- `protonvpn/` — standard account (proton_username.txt, proton_password.txt)
- `protonvpn-2fa/` — 2FA-enabled account (proton_username.txt, proton_password.txt)

Claude does not have access to read these files. They are mounted into the container as Docker secrets. Never prompt for, generate, or hardcode credentials.

### Persistent Storage

Output files (servers-proton.json, config.yaml) write to `c:/git/appdata/gluetun` mounted as `/gluetun` in the container. This directory is shared across the local dev environment and is not project-local.

## Stack

- Python 3.12 (in container, based on python:3.12-slim)
- Single entry point: `protonvpn_gluetun_updater.py`
- Key dependency: `proton-core` (git install from ProtonVPN/python-proton-core)
- Docker for all build/run

## Coding Standards

- Type hints on all functions
- Google-style docstrings
- Environment variables for all configuration (no CLI args)
- Docker secrets as credential fallback

## Architecture Principle

**All future decisions, architecture, plumbing, and refactoring must be in the spirit of modularization.**

The project is structured as distinct modules with clean boundaries:
- `transform.py` — pure core, zero project imports, fully unit-testable
- `storage.py` — persistence: `_Config` (YAML shape), cache, config load/save
- `state.py` — process overseer: `_Status` (cross-cutting runtime state), `_TfaState`
- `protonvpn.py` — ProtonVPN integration: auth, fetch, TFA flow. Standalone importable. Named `protonvpn.py` (not `proton.py`) to avoid shadowing the `proton-core` library's `proton` namespace package.
- `web.py` — HTTP dashboard and control API
- `protonvpn_gluetun_updater.py` — orchestration entry point only

Every new feature goes into the correct module. The entry point never grows beyond orchestration.
`proton.py` is designed as a reference implementation and standalone building block — the companion
container and future community tooling will import it directly.

## History

This project originated as a fork of Neonox31's work, then Warren's first solo project — built entirely with GitHub Copilot before switching to Claude. The single-file architecture was the Copilot-era starting point, not a deliberate standard — the module split (Proton-39k) establishes the correct foundation.

## Git

- Stealth mode (no git ops from Claude)
- Current working branch: check with `git branch --show-current`

## Versioning

- Semver with annotated tags (`git tag -a v1.x.x`)
- **Tag after merge to main** — tag the merge commit, not the feature branch. Keeps tags on the mainline history where `git describe` and changelog tools expect them.
- CI triggers on `v*` tags — pushes multi-arch images to GHCR with semver tags (1.3.0, 1.3, 1, latest)
- PR number in commit messages for traceability (e.g., "Resolves #7")
