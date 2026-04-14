"""Mermaid sequence diagrams for each OAuth flow.

Each step is wrapped in a rect block with a distinct fill color.
The frontend scans the SVG for these rects to make them clickable
and to highlight the active step.
"""

# Single source of truth for step highlight colours.
# JS reads this via the `step_fills` template variable injected by main.py —
# there is NO hardcoded copy in app.js.
# Step 0 = deep blue, 1 = deep green, 2 = deep red, 3 = deep teal,
# 4 = deep purple, 5 = olive, 6 = slate blue, 7 = sienna
STEP_FILLS: list[tuple[int, int, int]] = [
    (25, 35, 65),
    (25, 60, 35),
    (65, 30, 25),
    (30, 55, 55),
    (55, 30, 55),
    (55, 55, 25),
    (45, 45, 60),
    (60, 40, 30),
]


def _rgb(idx: int) -> str:
    r, g, b = STEP_FILLS[idx]
    return f"rgb({r},{g},{b})"


_S0 = _rgb(0)
_S1 = _rgb(1)
_S2 = _rgb(2)
_S3 = _rgb(3)
_S4 = _rgb(4)
_S5 = _rgb(5)
_S6 = _rgb(6)
_S7 = _rgb(7)

DIAGRAMS = {
    "auth_code": f"""sequenceDiagram
    participant U as User / Browser
    participant C as Client App<br/>(auth-viewer)
    participant E as Entra ID
    participant R as Resource API

    rect {_S0}
    Note right of C: Step 1 — Authorize
    U->>C: Click "Sign In"
    C->>U: Redirect to /authorize
    U->>E: GET /authorize<br/>(client_id, scope, redirect_uri, state)
    E->>U: Login prompt + consent
    U->>E: Credentials + consent
    E->>U: Redirect to callback<br/>(code, state)
    U->>C: GET /auth/callback?code=...&state=...
    end
    rect {_S1}
    Note right of C: Step 2 — Token Exchange
    C->>E: POST /token<br/>(grant_type=authorization_code,<br/>code, client_secret)
    E->>C: {{ access_token, id_token,<br/>refresh_token }}
    end
    rect {_S2}
    Note right of C: Step 3 — Call Resource
    C->>R: GET /endpoint<br/>Authorization: Bearer {{access_token}}
    R->>C: {{ response }}
    end""",

    "client_credentials": f"""sequenceDiagram
    participant C as Client App<br/>(auth-viewer)
    participant E as Entra ID
    participant R as Resource API

    rect {_S0}
    Note right of C: Step 1 — Client Credentials
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id, client_secret,<br/>scope=api://.../.default)
    E->>C: {{ access_token }}<br/>(app-only, no user context)
    end
    rect {_S1}
    Note right of C: Step 2 — Call Resource
    C->>R: GET /endpoint<br/>Authorization: Bearer {{access_token}}
    R->>C: {{ response }}
    end""",

    "client_credentials_chain": f"""sequenceDiagram
    participant C as Client App<br/>(auth-viewer)
    participant E as Entra ID
    participant A as API A<br/>(middle tier)
    participant B as API B<br/>(downstream)

    Note over C: Client Credentials Chain — app-only
    rect {_S0}
    Note right of C: Step 1 — Client Credentials for API A
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id, client_secret,<br/>scope=api://api-a/.default)
    E->>C: {{ access_token }}<br/>(app-only for API A)
    end
    rect {_S1}
    Note right of C: Step 2 — Call API A
    C->>A: POST /chain<br/>Authorization: Bearer {{access_token}}
    Note over A: API A validates token
    end
    rect {_S2}
    Note right of A: Step 3 — API A → Client Credentials for API B
    A->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=api_a_id,<br/>client_secret=api_a_secret,<br/>scope=api://api-b/.default)
    E->>A: {{ access_token }}<br/>(app-only for API B)
    end
    rect {_S3}
    Note right of A: Step 4 — API A → Call API B
    A->>B: GET /data<br/>Authorization: Bearer {{api_a_token}}
    B->>A: {{ data }}
    Note over A: API B sees API A as caller<br/>(not the original client)
    end""",

    "client_credentials_chain_graph": f"""sequenceDiagram
    participant C as Client App<br/>(auth-viewer)
    participant E as Entra ID
    participant A as API A<br/>(middle tier)
    participant G as Microsoft Graph

    Note over C: Client Credentials Chain — app-only
    rect {_S0}
    Note right of C: Step 1 — Client Credentials for API A
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id, client_secret,<br/>scope=api://api-a/.default)
    E->>C: {{ access_token }}<br/>(app-only for API A)
    end
    rect {_S1}
    Note right of C: Step 2 — Call API A
    C->>A: POST /chain<br/>Authorization: Bearer {{access_token}}
    Note over A: API A validates token
    end
    rect {_S2}
    Note right of A: Step 3 — API A → Client Credentials for Graph
    A->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=api_a_id,<br/>client_secret=api_a_secret,<br/>scope=https://graph.microsoft.com/.default)
    E->>A: {{ access_token }}<br/>(app-only for Graph)
    end
    rect {_S3}
    Note right of A: Step 4 — API A → Call Graph
    A->>G: GET /v1.0/organization<br/>Authorization: Bearer {{api_a_token}}
    G->>A: {{ organization data }}
    Note over A: Graph sees API A as caller<br/>(not the original client)
    end""",

    "obo": f"""sequenceDiagram
    participant U as User / Browser
    participant C as Client App<br/>(auth-viewer)
    participant A as API A<br/>(middle tier)
    participant E as Entra ID
    participant B as API B<br/>(downstream)

    Note over C: On-Behalf-Of (OBO) — full chain
    rect {_S0}
    Note right of C: Step 1 — Authorize
    U->>C: Click "Execute OBO"
    C->>U: Redirect to /authorize<br/>(scope = API A)
    U->>E: GET /authorize
    E->>U: Login + consent
    U->>E: Credentials
    E->>U: Redirect with code
    U->>C: GET /callback?code=...
    end
    rect {_S1}
    Note right of C: Step 2 — Token Exchange
    C->>E: POST /token<br/>(grant_type=authorization_code,<br/>code, client_secret,<br/>scope=api://api-a/access_as_user)
    E->>C: {{ access_token for API A,<br/>id_token, refresh_token }}
    end
    rect {_S2}
    Note right of C: Step 3 — Call API A
    C->>A: GET /me<br/>Authorization: Bearer {{token_A}}
    A->>C: {{ claims }}
    end
    rect {_S3}
    Note right of C: Step 4 — OBO Exchange
    C->>E: POST /token<br/>(grant_type=jwt-bearer,<br/>assertion={{token_A}},<br/>client_id=api_a_app_id,<br/>scope=api://api-b/.default)
    E->>C: {{ access_token for API B }}
    end
    rect {_S4}
    Note right of C: Step 5 — Call API B
    C->>B: GET /data<br/>Authorization: Bearer {{token_B}}
    B->>C: {{ data }}
    end""",

    "agent_id_autonomous": f"""sequenceDiagram
    participant C as Client App
    participant E as Entra ID
    participant R as Resource API

    Note over C: Agent ID — Autonomous (app-only)
    rect {_S0}
    Note right of C: Step 1 — Parent Token
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=blueprint_app_id,<br/>client_secret=blueprint_secret,<br/>scope=api://AzureADTokenExchange/.default,<br/>fmi_path=agent_identity_id)
    E->>C: {{ parent_token }}<br/>(aud: api://AzureADTokenExchange)
    end
    rect {_S1}
    Note right of C: Step 2 \u2014 FMI Exchange
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=agent_identity_id,<br/>client_assertion=parent_token,<br/>scope=resource/.default)
    E->>C: {{ access_token }}<br/>(sub: agent_identity)
    end
    rect {_S2}
    Note right of C: Step 3 — Call Resource
    C->>R: GET /endpoint<br/>Authorization: Bearer {{access_token}}
    R->>C: {{ response }}
    end""",

    "agent_id_autonomous_chain": f"""sequenceDiagram
    participant C as Client App
    participant E as Entra ID
    participant A as API A<br/>(middle tier)
    participant B as API B<br/>(downstream)

    Note over C: Agent ID Autonomous Chain — app-only
    rect {_S0}
    Note right of C: Step 1 — Parent Token
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=blueprint_app_id,<br/>client_secret=blueprint_secret,<br/>scope=api://AzureADTokenExchange/.default,<br/>fmi_path=agent_identity_id)
    E->>C: {{ parent_token }}<br/>(aud: api://AzureADTokenExchange)
    end
    rect {_S1}
    Note right of C: Step 2 — FMI Exchange for API A
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=agent_identity_id,<br/>client_assertion=parent_token,<br/>scope=api://api-a/.default)
    E->>C: {{ access_token }}<br/>(sub: agent_identity)
    end
    rect {_S2}
    Note right of C: Step 3 — Call API A
    C->>A: POST /chain<br/>Authorization: Bearer {{agent_token}}
    Note over A: API A validates token<br/>(sees Agent Identity as caller)
    end
    rect {_S3}
    Note right of A: Step 4 — API A → Client Credentials for API B
    A->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=api_a_id,<br/>client_secret=api_a_secret,<br/>scope=api://api-b/.default)
    E->>A: {{ access_token }}<br/>(app-only for API B)
    end
    rect {_S4}
    Note right of A: Step 5 — API A → Call API B
    A->>B: GET /data<br/>Authorization: Bearer {{api_a_token}}
    B->>A: {{ data }}
    Note over A: API B sees API A as caller<br/>(not the Agent Identity)
    end""",

    "agent_id_autonomous_chain_graph": f"""sequenceDiagram
    participant C as Client App
    participant E as Entra ID
    participant A as API A<br/>(middle tier)
    participant G as Microsoft Graph

    Note over C: Agent ID Autonomous Chain — app-only
    rect {_S0}
    Note right of C: Step 1 — Parent Token
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=blueprint_app_id,<br/>client_secret=blueprint_secret,<br/>scope=api://AzureADTokenExchange/.default,<br/>fmi_path=agent_identity_id)
    E->>C: {{ parent_token }}<br/>(aud: api://AzureADTokenExchange)
    end
    rect {_S1}
    Note right of C: Step 2 — FMI Exchange for API A
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=agent_identity_id,<br/>client_assertion=parent_token,<br/>scope=api://api-a/.default)
    E->>C: {{ access_token }}<br/>(sub: agent_identity)
    end
    rect {_S2}
    Note right of C: Step 3 — Call API A
    C->>A: POST /chain<br/>Authorization: Bearer {{agent_token}}
    Note over A: API A validates token<br/>(sees Agent Identity as caller)
    end
    rect {_S3}
    Note right of A: Step 4 — API A → Client Credentials for Graph
    A->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=api_a_id,<br/>client_secret=api_a_secret,<br/>scope=https://graph.microsoft.com/.default)
    E->>A: {{ access_token }}<br/>(app-only for Graph)
    end
    rect {_S4}
    Note right of A: Step 5 — API A → Call Graph
    A->>G: GET /v1.0/organization<br/>Authorization: Bearer {{api_a_token}}
    G->>A: {{ organization data }}
    Note over A: Graph sees API A as caller<br/>(not the Agent Identity)
    end""",

    "agent_id_obo": f"""sequenceDiagram
    participant U as User / Browser
    participant C as Client App
    participant A as API A<br/>(middle tier)
    participant E as Entra ID
    participant B as API B<br/>(downstream)

    Note over C: Agent ID — OBO (delegated)
    rect {_S0}
    Note right of C: Step 1 — Authorize
    U->>C: Click "Execute Agent ID OBO"
    C->>U: Redirect to /authorize<br/>(scope = Blueprint API)
    U->>E: GET /authorize
    E->>U: Login + consent
    U->>E: Credentials
    E->>U: Redirect with code
    U->>C: GET /callback?code=...
    end
    rect {_S1}
    Note right of C: Step 2 — Token Exchange
    C->>E: POST /token<br/>(grant_type=authorization_code,<br/>code, client_secret,<br/>scope=api://blueprint/access_as_user)
    E->>C: {{ user_token }}<br/>(aud: api://blueprint)
    end
    rect {_S2}
    Note right of C: Step 3 — Parent Token
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=blueprint_app_id,<br/>client_secret=blueprint_secret,<br/>scope=api://AzureADTokenExchange/.default,<br/>fmi_path=agent_identity_id)
    E->>C: {{ parent_token }}
    end
    rect {_S3}
    Note right of C: Step 4 — Agent OBO Exchange
    C->>E: POST /token<br/>(grant_type=jwt-bearer,<br/>client_id=agent_identity_id,<br/>client_assertion=parent_token,<br/>assertion=user_token,<br/>scope=api://api-a/access_as_user)
    E->>C: {{ agent_token_A }}<br/>(sub: agent, upn: user, aud: API A)
    end
    rect {_S4}
    Note right of C: Step 5 — Call API A
    C->>A: GET /me<br/>Authorization: Bearer {{agent_token_A}}
    A->>C: {{ claims }}
    end
    rect {_S5}
    Note right of C: Step 6 — OBO Exchange (API A → API B)
    C->>E: POST /token<br/>(grant_type=jwt-bearer,<br/>assertion={{agent_token_A}},<br/>client_id=api_a_app_id,<br/>scope=api://api-b/.default)
    E->>C: {{ token_B }}
    end
    rect {_S6}
    Note right of C: Step 7 — Call API B
    C->>B: GET /data<br/>Authorization: Bearer {{token_B}}
    B->>C: {{ data }}
    end""",

    "profile_login": f"""sequenceDiagram
    participant U as User / Browser
    participant C as Client App<br/>(auth-viewer)
    participant E as Entra ID

    Note over C: Session Bootstrap — OpenID Connect Sign-In
    rect {_S0}
    Note right of C: Step 1 — Authorize
    U->>C: Open app
    C->>U: Redirect to /authorize
    U->>E: GET /authorize<br/>(scope=openid profile)
    E->>U: Login prompt
    U->>E: Credentials
    E->>U: Redirect to callback<br/>(code, state)
    U->>C: GET /auth/callback?code=...&state=...
    end
    rect {_S1}
    Note right of C: Step 2 — Token Exchange
    C->>E: POST /token<br/>(grant_type=authorization_code,<br/>code, client_secret)
    E->>C: {{{{ id_token }}}}
    end""",
}


def get_diagram(flow_type: str) -> str:
    """Return the Mermaid diagram for a flow type, or a fallback."""
    return DIAGRAMS.get(flow_type, f"sequenceDiagram\n    Note over Client: Unknown flow: {flow_type}")
