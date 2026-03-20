"""Mermaid sequence diagrams for each OAuth flow.

Each step is wrapped in a rect block with a distinct fill color.
The frontend scans the SVG for these rects to make them clickable
and to highlight the active step.
"""

# Step colours — keep in sync with STEP_FILLS in app.js
# Step 0 = deep blue, 1 = deep green, 2 = deep red, 3 = deep teal, 4 = deep purple
_S0 = "rgb(25,35,65)"
_S1 = "rgb(25,60,35)"
_S2 = "rgb(65,30,25)"
_S3 = "rgb(30,55,55)"
_S4 = "rgb(55,30,55)"
_S5 = "rgb(55,55,25)"

DIAGRAMS = {
    "auth_code": f"""sequenceDiagram
    participant U as User / Browser
    participant C as Client App<br/>(auth-viewer)
    participant E as Entra ID

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
    C->>U: Display tokens
    end""",

    "auth_code_pkce": f"""sequenceDiagram
    participant U as User / Browser
    participant C as Client App<br/>(public client)
    participant E as Entra ID

    rect {_S0}
    Note right of C: Step 1 — Authorize (PKCE)
    C->>C: Generate code_verifier<br/>+ code_challenge (S256)
    U->>C: Click "Sign In"
    C->>U: Redirect to /authorize
    U->>E: GET /authorize<br/>(client_id, scope, code_challenge,<br/>code_challenge_method=S256)
    E->>U: Login prompt + consent
    U->>E: Credentials + consent
    E->>U: Redirect to callback<br/>(code, state)
    U->>C: GET /auth/callback?code=...
    end
    rect {_S1}
    Note right of C: Step 2 — Token Exchange
    C->>E: POST /token<br/>(grant_type=authorization_code,<br/>code, code_verifier)<br/>No client_secret
    E->>C: {{ access_token, id_token,<br/>refresh_token }}
    C->>U: Display tokens
    end""",

    "client_credentials": f"""sequenceDiagram
    participant C as Client App<br/>(auth-viewer)
    participant E as Entra ID

    rect {_S0}
    Note right of C: Client Credentials
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id, client_secret,<br/>scope=api://.../.default)
    E->>C: {{ access_token }}<br/>(app-only, no user context)
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
    Note over C,E: Step 5 — Exchanged token<br/>aud switched: API A → API B
    end
    rect {_S5}
    Note right of C: Step 6 — Call API B
    C->>B: GET /data<br/>Authorization: Bearer {{token_B}}
    B->>C: {{ data }}
    end""",

    "device_code": f"""sequenceDiagram
    participant U as User / Browser
    participant C as Client App
    participant D as Other Device<br/>(phone/laptop)
    participant E as Entra ID

    rect {_S0}
    Note right of C: Step 1 — Request Device Code
    C->>E: POST /devicecode<br/>(client_id, scope)
    E->>C: {{ user_code, device_code,<br/>verification_uri }}
    C->>U: Display: "Go to<br/>microsoft.com/devicelogin<br/>and enter code: ABCD-EFGH"
    end
    rect {_S1}
    Note right of C: Step 2 — Poll for Token
    D->>E: User navigates to<br/>verification_uri
    D->>E: Enters user_code
    D->>E: Authenticates + consents
    loop Poll every 5s
        C->>E: POST /token<br/>(grant_type=device_code,<br/>device_code)
        E->>C: authorization_pending
    end
    C->>E: POST /token<br/>(grant_type=device_code)
    E->>C: {{ access_token, id_token,<br/>refresh_token }}
    C->>U: Display tokens
    end""",

    "refresh_token": f"""sequenceDiagram
    participant C as Client App<br/>(auth-viewer)
    participant E as Entra ID

    rect {_S0}
    Note over C: Has refresh_token<br/>from prior auth
    C->>E: POST /token<br/>(grant_type=refresh_token,<br/>refresh_token, client_secret,<br/>scope)
    E->>C: {{ new access_token,<br/>new id_token,<br/>new refresh_token }}
    end""",

    "agent_id_autonomous": f"""sequenceDiagram
    participant C as Client App
    participant E as Entra ID
    participant G as Target Resource<br/>(e.g. Graph)

    Note over C: Agent ID — Autonomous (app-only)
    rect {_S0}
    Note right of C: Step 1 — Parent Token
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=blueprint_app_id,<br/>client_secret=blueprint_secret,<br/>scope=api://AzureADTokenExchange/.default,<br/>fmi_path=agent_identity_id)
    E->>C: {{ parent_token }}<br/>(aud: api://AzureADTokenExchange)
    end
    rect {_S1}
    Note right of C: Step 2 — Token Exchange
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=agent_identity_id,<br/>client_assertion=parent_token,<br/>scope=https://graph.microsoft.com/.default)
    E->>C: {{ access_token }}<br/>(sub: agent_identity)
    end
    C->>G: API call with access_token""",

    "agent_id_obo": f"""sequenceDiagram
    participant U as User / Browser
    participant C as Client App
    participant E as Entra ID
    participant G as Target Resource<br/>(e.g. Graph)

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
    Note right of C: Step 4 — OBO Exchange
    C->>E: POST /token<br/>(grant_type=jwt-bearer,<br/>client_id=agent_identity_id,<br/>client_assertion=parent_token,<br/>assertion=user_token,<br/>requested_token_use=on_behalf_of,<br/>scope=https://graph.microsoft.com/.default)
    E->>C: {{ access_token }}<br/>(sub: agent_identity, upn: user)
    end
    C->>G: API call on behalf of user""",

    # ── Shortened diagrams for "reuse stored token" mode ──

    "obo_reuse": f"""sequenceDiagram
    participant C as Client App<br/>(auth-viewer)
    participant A as API A<br/>(middle tier)
    participant E as Entra ID
    participant B as API B<br/>(downstream)

    Note over C: OBO — Using stored token
    rect {_S0}
    Note right of C: Step 1 — Stored User Token
    Note over C: Access token from<br/>prior sign-in (session)
    end
    rect {_S1}
    Note right of C: Step 2 — Call API A
    C->>A: GET /me<br/>Authorization: Bearer {{token_A}}
    A->>C: {{ claims }}
    end
    rect {_S2}
    Note right of C: Step 3 — OBO Exchange
    C->>E: POST /token<br/>(grant_type=jwt-bearer,<br/>assertion={{token_A}},<br/>client_id=api_a_app_id,<br/>scope=api://api-b/.default)
    E->>C: {{ access_token for API B }}
    end
    rect {_S3}
    Note over C,E: Step 4 — Exchanged token<br/>aud switched: API A → API B
    end
    rect {_S4}
    Note right of C: Step 5 — Call API B
    C->>B: GET /data<br/>Authorization: Bearer {{token_B}}
    B->>C: {{ data }}
    end""",

    "agent_id_obo_reuse": f"""sequenceDiagram
    participant C as Client App
    participant E as Entra ID
    participant G as Target Resource<br/>(e.g. Graph)

    Note over C: Agent ID OBO — Using stored token
    rect {_S0}
    Note right of C: Step 1 — Stored User Token
    Note over C: User token from<br/>prior sign-in (session)
    end
    rect {_S1}
    Note right of C: Step 2 — Parent Token
    C->>E: POST /token<br/>(grant_type=client_credentials,<br/>client_id=blueprint_app_id,<br/>client_secret=blueprint_secret,<br/>scope=api://AzureADTokenExchange/.default,<br/>fmi_path=agent_identity_id)
    E->>C: {{ parent_token }}
    end
    rect {_S2}
    Note right of C: Step 3 — OBO Exchange
    C->>E: POST /token<br/>(grant_type=jwt-bearer,<br/>client_id=agent_identity_id,<br/>client_assertion=parent_token,<br/>assertion=user_token,<br/>scope=https://graph.microsoft.com/.default)
    E->>C: {{ access_token }}<br/>(sub: agent_identity, upn: user)
    end
    C->>G: API call on behalf of user""",
}


def get_diagram(flow_type: str) -> str:
    """Return the Mermaid diagram for a flow type, or a fallback."""
    return DIAGRAMS.get(flow_type, f"sequenceDiagram\n    Note over Client: Unknown flow: {flow_type}")
