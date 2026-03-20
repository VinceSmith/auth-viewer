# Entra OAuth Explorer

An interactive teaching tool that visualizes OAuth 2.0 / Entra ID token flows. Execute real flows against your own tenant and see the raw HTTP requests, decoded JWT tokens, and live Mermaid sequence diagrams for each step.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-async-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Supported Flows

| Flow | Type | Description |
|------|------|-------------|
| Authorization Code | Delegated | Standard web app sign-in |
| Auth Code + PKCE | Delegated | Public client variant (SPA/mobile) |
| Client Credentials | App-only | Service-to-service, no user |
| On-Behalf-Of (OBO) | Delegated | Chain: Client → API A → API B |
| Device Code | Delegated | Headless/CLI authentication |
| Refresh Token | Delegated | Token lifecycle renewal |
| Agent ID — Autonomous | App-only | Two-step: parent token → exchange |
| Agent ID — OBO | Delegated | Two-step: parent token → OBO exchange |

## Architecture

```
┌─────────────┐     ┌──────────┐     ┌──────────┐
│ Client App  │────▶│  API A   │────▶│  API B   │
│ :8000       │     │  :8001   │     │  :8002   │
└──────┬──────┘     └────┬─────┘     └──────────┘
       │                 │
       └────────┬────────┘
                ▼
         ┌──────────┐
         │ Entra ID │
         └──────────┘
```

## Prerequisites

- **Python 3.11+**
- **Azure CLI** (`az`) — logged in with permission to create app registrations
- **An Entra ID (Azure AD) tenant** — a [free M365 developer tenant](https://developer.microsoft.com/microsoft-365/dev-program) works
- **PowerShell 7+** — for setup scripts (Windows ships with this)

## Setup

### 1. Clone & install dependencies

```bash
git clone https://github.com/VinceSmith/auth-viewer.git
cd auth-viewer
pip install -r requirements.txt
```

### 2. Register Entra app registrations

```powershell
.\scripts\register_apps.ps1
```

This creates **three** app registrations in your tenant (Client, API A, API B), configures permissions/pre-authorizations, grants admin consent, and writes a `.env` file with all IDs and secrets.

### 3. (Optional) Set up Agent Identity for Agent ID flows

```powershell
.\scripts\setup-agent-id.ps1
```

This creates an **Agent Identity Blueprint** and **Agent Identity** (workload identity), configures Workload Identity Federation, grants Graph User.Read, and updates `.env` with the `AGENT_*` values.

> **Note:** Steps 2-3 require Azure CLI logged in as an admin who can create app registrations and grant admin consent. If you don't have that access, copy `.env.template` to `.env` and fill in values from manually created registrations.

### 4. Run

```powershell
.\scripts\run_all.ps1
```

Open http://localhost:8000 in your browser.

### Coding Agent Setup

If you're using a coding agent (GitHub Copilot, Cursor, etc.), the project includes an [AGENTS.md](AGENTS.md) file with full context. The agent can read that file and run the setup scripts for you.

**Recommended skills** (install in `~/.agents/skills/`):
- [`entra-agent-id`](https://github.com/VinceSmith/dotfiles/tree/main/skills/entra-agent-id) — Agent Identity provisioning via Graph
- [`entra-agent-id-runtime`](https://github.com/VinceSmith/dotfiles/tree/main/skills/entra-agent-id-runtime) — Token exchange patterns
- [`entra-app-registration`](https://github.com/VinceSmith/dotfiles/tree/main/skills/entra-app-registration) — App registration & OAuth 2.0

## Usage

1. **Select a flow type** from the radio buttons on the left
2. **Choose a scope/resource** from the dropdown (or enter a custom scope)
3. **Click Execute** — for Auth Code flows this redirects you to Entra; for others it runs inline
4. **View results** on the right panel:
   - **Access Token** tab: decoded header, payload, and raw token
   - **ID Token** tab: decoded header, payload, and raw token
   - **Raw Request** tab: the exact HTTP request sent to Entra
   - **Raw Response** tab: the full HTTP response from Entra
5. **Flow diagram** updates in the lower-left to show the sequence

## Project Structure

```
auth-viewer/
├── app/
│   ├── main.py              # FastAPI routes, session, OAuth callback
│   ├── config.py            # Settings from .env (pydantic-settings)
│   ├── diagrams.py          # Mermaid sequence diagrams per flow
│   ├── auth/
│   │   ├── flows.py         # Raw REST OAuth flow implementations
│   │   └── token_utils.py   # JWT decode + formatting
│   ├── templates/
│   │   ├── base.html        # Layout + mermaid.js CDN
│   │   └── index.html       # Main UI (flow picker, step visualizer)
│   └── static/
│       ├── app.js            # Frontend logic (diagrams, step-through)
│       └── style.css         # Dark theme
├── resource_api_a/
│   └── main.py              # Middle-tier API (performs OBO exchange)
├── resource_api_b/
│   └── main.py              # Downstream API (protected resource)
├── scripts/
│   ├── register_apps.ps1    # Creates 3 Entra apps + .env
│   ├── setup-agent-id.ps1   # Creates Blueprint + Agent Identity
│   └── run_all.ps1          # Starts all 3 services
├── test_all_flows.py        # Full E2E test suite (65 tests)
├── test_flows.py            # Quick non-interactive smoke tests
├── .env.template            # Copy to .env and fill in
├── AGENTS.md                # Coding agent context file
└── requirements.txt
```

## Testing

```powershell
# Start all services first
.\scripts\run_all.ps1

# In another terminal — run the full E2E suite (opens browser for interactive flows)
$env:PYTHONIOENCODING="utf-8"
python test_all_flows.py --no-pause
```

65 tests across two phases:
- **Phase 1** — Non-interactive: Client Credentials, Agent ID Autonomous, Device Code start
- **Phase 2** — Interactive: Auth Code, PKCE, OBO chain, Agent ID OBO (opens browser)

## How It Works

This is a **teaching tool** — every flow is implemented as raw HTTP requests (no MSAL),
so you can see exactly what goes over the wire. JWT tokens are decoded (without signature
verification) to show claims. Mermaid diagrams update to show the sequence for each flow.

## Future

- [ ] Multi-tenant support
- [ ] Animated Mermaid diagrams (highlight current step)
- [ ] ROPC flow (educational "don't do this" demo)
- [ ] Token cache visualization (show cache hits vs. fresh)
- [ ] Export flow as curl commands

## License

MIT
