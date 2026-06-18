# Sub2API Self-Use Deploy

This folder contains a small Docker-based deployment bundle for running `Sub2API` on your own machine.

## What this setup does

- Runs `Sub2API`, `PostgreSQL`, and `Redis` with `docker compose`
- Defaults to `RUN_MODE=simple`
- Persists data in this folder for easier backup and migration
- Exposes the service to your LAN on port `8080`

## Quick start

From PowerShell:

```powershell
cd C:\Users\11045\Documents\飞书文档解答\sub2api-selfuse-deploy
powershell -ExecutionPolicy Bypass -File .\start-sub2api.ps1
```

Stop:

```powershell
powershell -ExecutionPolicy Bypass -File .\stop-sub2api.ps1
```

## Access addresses

Local machine:

- [http://127.0.0.1:8080](http://127.0.0.1:8080)

LAN devices on the same network:

- `http://<your-lan-ip>:8080`

## Useful commands

View logs:

```powershell
docker compose logs -f sub2api
```

Restart:

```powershell
docker compose down
docker compose up -d
```

## Important notes

- The `.env` file contains sensitive credentials and should not be committed.
- Run `.\init-secrets.ps1` first to generate local passwords and secrets.
- If your router changes this PC's LAN IP, the LAN access address will change too.
- If you later expose this beyond your own LAN, add HTTPS, authentication hardening, and tighter network controls first.
