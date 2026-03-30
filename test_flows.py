"""Quick test script to exercise all non-interactive flows and verify results."""
import os
from pathlib import Path
from dotenv import load_dotenv
import httpx
import json

load_dotenv(Path(__file__).parent / ".env")

BASE = "http://localhost:8000"
API_A_APP_ID = os.environ.get("API_A_APP_ID", "")
API_B_APP_ID = os.environ.get("API_B_APP_ID", "")


def test_flow(name, payload):
    print(f"=== {name} ===")
    resp = httpx.post(f"{BASE}/api/execute", json=payload, timeout=30)
    data = resp.json()

    if "error" in data:
        print(f"  ERROR: {data['error']}")
        print()
        return data

    result = data["result"]
    steps = result.get("steps", [])
    print(f"  Steps: {len(steps)}")
    for i, s in enumerate(steps):
        print(f"    [{i}] {s['label']}")
        tokens = s.get("tokens", {})
        for tname, tdata in tokens.items():
            payload_data = tdata.get("payload", {})
            header_data = tdata.get("header", {})
            if payload_data:
                print(f"        {tname}:")
                print(f"          aud: {payload_data.get('aud')}")
                print(f"          sub: {payload_data.get('sub', 'N/A')}")
                print(f"          iss: {payload_data.get('iss')}")
                print(f"          ver: {payload_data.get('ver')}")
                print(f"          scp: {payload_data.get('scp', 'N/A')}")
                print(f"          roles: {payload_data.get('roles', 'N/A')}")
                print(f"          idtyp: {payload_data.get('idtyp', 'N/A')}")
                print(f"          appid/azp: {payload_data.get('appid') or payload_data.get('azp', 'N/A')}")
            elif tdata.get("note"):
                print(f"        {tname}: {tdata['note']}")
        resp_data = s.get("response", {})
        status = resp_data.get("status", "N/A")
        body = resp_data.get("body", {})
        if isinstance(body, dict) and "error" in body:
            print(f"        response: {status} ERROR: {body['error']}: {body.get('error_description', '')[:100]}")
        else:
            print(f"        response: {status}")
    print()
    return data


# 1. Client Credentials → API A
test_flow("Client Credentials — API A .default", {
    "flow_type": "client_credentials",
    "scope": f"api://{API_A_APP_ID}/.default",
})

# 2. Client Credentials → Graph
test_flow("Client Credentials — Graph .default", {
    "flow_type": "client_credentials",
    "scope": "https://graph.microsoft.com/.default",
})

# 3. Client Credentials → API B
test_flow("Client Credentials — API B .default", {
    "flow_type": "client_credentials",
    "scope": f"api://{API_B_APP_ID}/.default",
})

# 4. Client Credentials Chain → API A → API B
test_flow("Client Credentials Chain — API A → API B", {
    "flow_type": "client_credentials_chain",
    "scope": f"api://{API_B_APP_ID}/.default",
})

# 5. Client Credentials Chain → API A → Graph
test_flow("Client Credentials Chain — API A → Graph", {
    "flow_type": "client_credentials_chain",
    "scope": "https://graph.microsoft.com/.default",
})

# 6. Agent ID Autonomous → Graph
test_flow("Agent ID Autonomous — Graph .default", {
    "flow_type": "agent_id_autonomous",
    "scope": "https://graph.microsoft.com/.default",
})

# 5. OBO (will fail if no session)
test_flow("OBO (no session)", {
    "flow_type": "obo",
    "scope": f"api://{API_B_APP_ID}/.default",
})

# 6. Agent ID OBO (will fail if no session)
test_flow("Agent ID OBO (no session)", {
    "flow_type": "agent_id_obo",
    "scope": "https://graph.microsoft.com/.default",
})
