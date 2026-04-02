# AGENTS.md — Coding Agent Context for auth-viewer

## Overview

Entra OAuth Explorer — an interactive teaching tool that visualizes OAuth 2.0 / Entra ID
token flows. Three FastAPI services (client app, middle-tier API A, downstream API B) plus
an Entra ID tenant with 5 app registrations.

## Quick Start (Full Setup)

```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Register core Entra apps (creates .env automatically)
.\scripts\register_apps.ps1

# 3. (Optional) Set up Agent Identity for Agent ID flows
.\scripts\setup-agent-id.ps1

# 4. Run all services
.\scripts\run_all.ps1
```

Open http://localhost:8000 in a browser.

## Prerequisites

- Python 3.11+
- Azure CLI (`az`) — logged in with permission to create app registrations
- An Entra ID (Azure AD) tenant
- PowerShell 7+ (for setup scripts)

## Project Structure

```
auth-viewer/
├── app/                          # Main FastAPI web app (:8000)
│   ├── main.py                   # Routes, session, OAuth callback
│   ├── config.py                 # Settings from .env (pydantic-settings)
│   ├── diagrams.py               # Mermaid sequence diagrams per flow
│   ├── auth/
│   │   ├── flows.py              # Raw REST OAuth flow implementations
│   │   └── token_utils.py        # JWT decode + formatting
│   ├── templates/
│   │   ├── base.html             # Layout + mermaid.js CDN
│   │   └── index.html            # Main UI (flow picker, step visualizer)
│   └── static/
│       ├── app.js                # Frontend logic (diagrams, step-through)
│       └── style.css             # Dark theme
├── resource_api_a/               # Middle-tier API (:8001) — does OBO
│   └── main.py
├── resource_api_b/               # Downstream API (:8002) — protected resource
│   └── main.py
├── scripts/
│   ├── register_apps.ps1         # Creates 3 Entra apps + .env
│   ├── setup-agent-id.ps1        # Creates Blueprint + Agent Identity + .env update
│   └── run_all.ps1               # Starts all 3 services
├── test_all_flows.py             # Full E2E test suite (65 tests)
├── test_flows.py                 # Quick non-interactive smoke tests
├── .env.template                 # Template — copy to .env and fill in
├── requirements.txt              # Python dependencies
└── .gitignore
```

## Environment Variables (.env)

All secrets come from `.env` (never hardcoded). The `.env.template` shows the shape.
`register_apps.ps1` auto-generates `.env` with real values.

Key variables:
- `TENANT_ID` — Your Entra tenant
- `CLIENT_ID` / `CLIENT_SECRET` — Confidential client app
- `API_A_APP_ID` / `API_A_CLIENT_SECRET` / `API_A_SCOPE` — Middle-tier API
- `API_B_APP_ID` / `API_B_SCOPE` — Downstream API
- `AGENT_BLUEPRINT_APP_ID` / `AGENT_BLUEPRINT_SECRET` — Blueprint for Agent ID flows
- `AGENT_IDENTITY_ID` / `AGENT_IDENTITY_TENANT_ID` — Agent Identity for Agent ID flows
- `SESSION_SECRET` — Cookie signing key

## Entra App Registrations

The project uses 5 app registrations (created by the two scripts):

| App | Script | Purpose |
|-----|--------|---------|
| auth-viewer-client | register_apps.ps1 | Confidential client, redirect URI `http://localhost:8000/auth/callback` |
| auth-viewer-api-a | register_apps.ps1 | Middle-tier API, exposes `access_as_user` scope, does OBO to API B |
| auth-viewer-api-b | register_apps.ps1 | Downstream API, exposes `read` scope |
| auth-viewer-blueprint | setup-agent-id.ps1 | Agent Identity Blueprint, exposes `access_as_user` scope |
| auth-viewer-agent-identity | setup-agent-id.ps1 | Workload identity with WIF federated credential |

### Permission Chain

```
Client → API A (delegated: access_as_user)
Client → API B (delegated: read)
Client → Graph (delegated: User.Read)
Client → Blueprint (delegated: access_as_user)
API A → API B (delegated: read, for OBO chain)
Agent Identity → Graph (delegated: User.Read, via oauth2PermissionGrant)
```

### Pre-authorizations

- Client is pre-authorized on API A (skip consent prompt)
- API A is pre-authorized on API B (skip consent prompt)
- Client is pre-authorized on Blueprint (skip consent prompt)

## Supported OAuth Flows

| Flow | Type | Key Concepts |
|------|------|-------------|
| Authorization Code | Delegated | Standard web sign-in |
| Client Credentials | App-only | Service-to-service, no user context |
| On-Behalf-Of (OBO) | Delegated | Client → API A → API B chain |
| Agent ID Autonomous | App-only | Blueprint parent token → agent exchange |
| Agent ID OBO | Delegated | User sign-in → Blueprint → agent OBO exchange |

## Build / Run Commands

```powershell
# Install dependencies
pip install -r requirements.txt

# Run all 3 services (client + API A + API B)
.\scripts\run_all.ps1

# Run just the client app
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Run tests (requires all 3 services running)
$env:PYTHONIOENCODING="utf-8"; python test_all_flows.py --no-pause
```

## Testing

The E2E test suite (`test_all_flows.py`) has 65 tests across two phases:
- **Phase 1**: Non-interactive (client credentials, agent ID autonomous)
- **Phase 2**: Interactive (opens browser for sign-in, validates results)

Run with `--no-pause` for CI/automated mode (auto-continues between tests).

## Code Style

- Python: no venv, standard library + packages from requirements.txt
- No type stubs or mypy — uses type hints for clarity, not enforcement
- Vanilla JavaScript (no framework), dark theme CSS
- FastAPI with Jinja2 templates, Starlette session middleware

## Boundaries

- This is a **teaching/demo tool** — not production-ready
- JWT tokens are decoded without signature verification (for display purposes)
- Session state uses signed cookies (itsdangerous) — suitable for localhost
- No database — all state is in-memory dicts and session cookies

## Recommended Skills

For coding agents working on this project, these skills are helpful:

- `entra-agent-id` — Entra Agent Identity Blueprint/Principal provisioning via Graph API
- `entra-agent-id-runtime` — Runtime token exchange patterns (autonomous + OBO)
- `entra-app-registration` — Entra app registration, OAuth 2.0, MSAL
