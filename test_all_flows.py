"""End-to-end test suite for auth-viewer OAuth flows.

Requires all three servers running:
  - Main app on :8000
  - API A on :8001
  - API B on :8002

Phase 1: Non-interactive (Client Credentials, Agent ID Autonomous, Device Code start)
Phase 2: Interactive — opens browser for sign-in, then verifies results
         (Auth Code, PKCE, OBO chain, Agent ID OBO chain, OBO via API, Refresh)
"""

import os
import sys
import time
import json

import urllib.parse

import argparse

import httpx
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

BASE = "http://localhost:8000"
TENANT_ID = os.environ["TENANT_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
API_A_APP_ID = os.environ["API_A_APP_ID"]
API_A_SCOPE = os.environ["API_A_SCOPE"]
API_B_APP_ID = os.environ["API_B_APP_ID"]
AGENT_BLUEPRINT_APP_ID = os.environ.get("AGENT_BLUEPRINT_APP_ID", "")
AGENT_IDENTITY_ID = os.environ.get("AGENT_IDENTITY_ID", "")

# ── Output helpers ──

_pass = 0
_fail = 0


def section(name: str):
    print(f"\n{'═' * 60}")
    print(f"  {name}")
    print(f"{'═' * 60}")


def check(name: str, condition: bool, detail: str = ""):
    global _pass, _fail
    if condition:
        _pass += 1
        print(f"  ✓ {name}" + (f"  ({detail})" if detail else ""))
    else:
        _fail += 1
        print(f"  ✗ {name}" + (f"  — {detail}" if detail else ""))


def execute(payload: dict) -> dict:
    """Call /api/execute and return the result dict."""
    resp = httpx.post(f"{BASE}/api/execute", json=payload, timeout=30)
    return resp.json()


def get_latest_callback() -> dict | None:
    """Poll /api/test/latest for the most recent redirect callback result."""
    resp = httpx.get(f"{BASE}/api/test/latest", timeout=10)
    if resp.status_code == 200:
        return resp.json()
    return None


def open_browser(url: str):
    """Open a URL in the default browser (Windows).

    Uses os.startfile() instead of cmd /c start because cmd interprets '&'
    in URLs as a command separator, stripping query params after the first '&'.
    """
    try:
        os.startfile(url)
    except Exception:
        print(f"  ⚠ Could not open browser automatically.")
    print(f"  🔗 {url}")


def wait_for_new_callback(old_flow_type: str | None, timeout: int = 120) -> dict:
    """Wait until a NEW callback result appears (counter-based detection)."""
    old = get_latest_callback()
    old_counter = old.get("counter", 0) if old else 0

    print("  ⏳ Waiting for sign-in to complete...", end="", flush=True)
    start = time.time()
    dots = 0
    while time.time() - start < timeout:
        time.sleep(2)
        dots += 1
        if dots % 5 == 0:
            elapsed = int(time.time() - start)
            print(f" {elapsed}s", end="", flush=True)
        else:
            print(".", end="", flush=True)
        latest = get_latest_callback()
        if latest is None:
            continue
        new_counter = latest.get("counter", 0)
        if new_counter > old_counter:
            print("  ✓")
            return latest
    print("\n  ✗ Timeout waiting for callback")
    sys.exit(1)


def get_token_payload(result: dict, step_index: int, token_key: str = "access_token") -> dict:
    """Extract a decoded token payload from a step."""
    steps = result.get("steps", [])
    if step_index >= len(steps):
        return {}
    tokens = steps[step_index].get("tokens", {})
    tok = tokens.get(token_key, {})
    return tok.get("payload", {})


def get_step_response(result: dict, step_index: int) -> dict:
    """Extract the response body from a step."""
    steps = result.get("steps", [])
    if step_index >= len(steps):
        return {}
    return steps[step_index].get("response", {}).get("body", {})


def get_step_request(result: dict, step_index: int) -> dict:
    """Extract the request body from a step."""
    steps = result.get("steps", [])
    if step_index >= len(steps):
        return {}
    return steps[step_index].get("request", {}).get("body", {})


# ══════════════════════════════════════════════════════════════
# Phase 1: Non-interactive flows
# ══════════════════════════════════════════════════════════════

def test_client_credentials():
    section("Client Credentials")

    # API A
    data = execute({"flow_type": "client_credentials", "scope": f"api://{API_A_APP_ID}/.default"})
    result = data.get("result", {})
    steps = result.get("steps", [])
    check("API A — has 1 step", len(steps) == 1)
    if steps:
        p = get_token_payload(result, 0)
        check("API A — aud correct", p.get("aud") == API_A_APP_ID, f"aud={p.get('aud')}")
        check("API A — v2.0 token", p.get("ver") == "2.0", f"ver={p.get('ver')}")
        check("API A — no error", "error" not in get_step_response(result, 0))

    # Graph
    data = execute({"flow_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"})
    result = data.get("result", {})
    steps = result.get("steps", [])
    if steps:
        p = get_token_payload(result, 0)
        check("Graph — aud correct", p.get("aud") == "https://graph.microsoft.com", f"aud={p.get('aud')}")
        check("Graph — v1.0 token", p.get("ver") == "1.0", f"ver={p.get('ver')}")

    # API B
    data = execute({"flow_type": "client_credentials", "scope": f"api://{API_B_APP_ID}/.default"})
    result = data.get("result", {})
    steps = result.get("steps", [])
    if steps:
        p = get_token_payload(result, 0)
        check("API B — aud correct", p.get("aud") == API_B_APP_ID, f"aud={p.get('aud')}")
        check("API B — v2.0 token", p.get("ver") == "2.0", f"ver={p.get('ver')}")


def test_agent_id_autonomous():
    section("Agent ID Autonomous")
    if not AGENT_BLUEPRINT_APP_ID:
        print("  ⊘ Skipped (Agent ID not configured)")
        return

    data = execute({"flow_type": "agent_id_autonomous", "scope": "https://graph.microsoft.com/.default"})
    result = data.get("result", {})
    steps = result.get("steps", [])
    check("Has 2 steps", len(steps) == 2, f"got {len(steps)}")

    if len(steps) >= 1:
        p0 = get_token_payload(result, 0)
        # AzureADTokenExchange first-party app ID
        check("Step 1 — parent token aud", p0.get("aud") == "fb60f99c-7a34-4190-8149-302f77469936",
              f"aud={p0.get('aud')}")
        check("Step 1 — azp is Blueprint", p0.get("azp") == AGENT_BLUEPRINT_APP_ID,
              f"azp={p0.get('azp')}")

    if len(steps) >= 2:
        p1 = get_token_payload(result, 1)
        check("Step 2 — aud is Graph", p1.get("aud") == "https://graph.microsoft.com",
              f"aud={p1.get('aud')}")
        check("Step 2 — sub is Agent Identity",
              p1.get("sub") == AGENT_IDENTITY_ID,
              f"sub={p1.get('sub')}")
        app_id = p1.get("appid") or p1.get("azp")
        check("Step 2 — appid is Agent Identity", app_id == AGENT_IDENTITY_ID,
              f"appid={app_id}")


def test_device_code_start():
    section("Device Code (start only)")
    data = execute({"flow_type": "device_code_start", "scope": "openid profile"})
    result = data.get("result", {})
    body = result.get("response", {}).get("body", {})
    check("Has user_code", bool(body.get("user_code")), f"user_code={body.get('user_code', 'N/A')}")
    check("Has verification_uri", bool(body.get("verification_uri")))
    check("Has device_code", bool(body.get("device_code")))


# ══════════════════════════════════════════════════════════════
# Phase 2: Interactive flows (browser sign-in)
# ══════════════════════════════════════════════════════════════

def test_auth_code():
    """Auth Code with API A scope — THE flow that had the bug."""
    section("Auth Code — API A scope (sign-in required)")
    scope = f"openid profile offline_access {API_A_SCOPE}"
    url = f"{BASE}/auth/login?scope={urllib.parse.quote(scope)}"
    print(f"  → Opening browser: Auth Code + API A")
    open_browser(url)

    latest = wait_for_new_callback(None)
    result = latest.get("result", {})
    if not result:
        check("Callback succeeded", False, latest.get("error", "empty result"))
        return {}
    flow = latest["flow_type"]
    raw_tokens = latest.get("raw_tokens", {})

    check("Flow type is auth_code", flow == "auth_code", f"got {flow}")
    steps = result.get("steps", [])
    check("Has 2 steps", len(steps) == 2, f"got {len(steps)}")

    # Step 1 (Token Exchange) should have the access token
    if len(steps) >= 2:
        p = get_token_payload(result, 1)
        check("Access token aud is API A (not Graph!)",
              p.get("aud") == API_A_APP_ID,
              f"aud={p.get('aud')}")
        check("Access token ver is 2.0", p.get("ver") == "2.0", f"ver={p.get('ver')}")
        check("Access token has scp with access_as_user",
              "access_as_user" in (p.get("scp") or ""),
              f"scp={p.get('scp')}")
        check("Issuer is v2.0 endpoint",
              "/v2.0" in (p.get("iss") or ""),
              f"iss={p.get('iss')}")

    # Check for ID token
    if len(steps) >= 2:
        id_tok = steps[1].get("tokens", {}).get("id_token", {})
        check("ID token present", bool(id_tok.get("payload")))

    # Check raw tokens for subsequent tests
    check("Raw access_token stored", bool(raw_tokens.get("access_token")))
    check("Raw refresh_token stored", bool(raw_tokens.get("refresh_token")))

    return raw_tokens


def test_obo_via_api(user_token: str):
    """Test OBO via /api/execute with an explicit user token."""
    section("OBO via API (using Auth Code token)")
    data = execute({
        "flow_type": "obo",
        "scope": f"api://{API_B_APP_ID}/.default",
        "user_token": user_token,
    })

    if "error" in data:
        check("No error", False, data["error"])
        return

    result = data.get("result", {})
    steps = result.get("steps", [])
    check("Has 5 steps", len(steps) == 5, f"got {len(steps)}: {[s.get('label','?') for s in steps]}")

    if len(steps) >= 1:
        check("Step 1 — User Token (Input)", steps[0].get("label") == "User Token (Input)")

    if len(steps) >= 2:
        resp = get_step_response(result, 1)
        check("Step 2 — Call API A", steps[1].get("label") == "Call API A")
        api_a_status = steps[1].get("response", {}).get("status", 0)
        check("Step 2 — API A responds 200", api_a_status == 200, f"status={api_a_status}")

    if len(steps) >= 3:
        check("Step 3 — OBO Token Exchange", steps[2].get("label") == "OBO Token Exchange")
        resp = get_step_response(result, 2)
        check("Step 3 — no error", "error" not in resp, f"error={resp.get('error')}")

    if len(steps) >= 4:
        p = get_token_payload(result, 3)
        check("Step 4 — aud switched to API B",
              p.get("aud") == API_B_APP_ID,
              f"aud={p.get('aud')}")

    if len(steps) >= 5:
        api_b_status = steps[4].get("response", {}).get("status", 0)
        check("Step 5 — API B responds 200", api_b_status == 200, f"status={api_b_status}")


def test_refresh(refresh_token: str):
    """Test Refresh Token via /api/execute."""
    section("Refresh Token (using stored refresh_token)")
    data = execute({
        "flow_type": "refresh_token",
        "scope": f"openid profile {API_A_SCOPE}",
        "refresh_token": refresh_token,
    })

    if "error" in data:
        check("No error", False, data["error"])
        return

    result = data.get("result", {})
    steps = result.get("steps", [])
    check("Has 1 step", len(steps) == 1, f"got {len(steps)}")

    if steps:
        resp = get_step_response(result, 0)
        check("Response has access_token", "access_token" in resp)
        check("Response has refresh_token", "refresh_token" in resp)
        p = get_token_payload(result, 0)
        check("Refreshed token aud is API A",
              p.get("aud") == API_A_APP_ID,
              f"aud={p.get('aud')}")


def test_auth_code_pkce():
    """Auth Code + PKCE — verifies public client flow works."""
    section("Auth Code + PKCE — API A scope (sign-in required)")
    scope = f"openid profile {API_A_SCOPE}"
    url = f"{BASE}/auth/login?scope={urllib.parse.quote(scope)}&use_pkce=true"
    print(f"  → Opening browser: Auth Code + PKCE")
    open_browser(url)

    latest = wait_for_new_callback("auth_code_pkce")
    result = latest.get("result", {})
    if not result:
        check("Callback succeeded", False, latest.get("error", "empty result"))
        return
    flow = latest["flow_type"]

    check("Flow type is auth_code_pkce", flow == "auth_code_pkce", f"got {flow}")
    steps = result.get("steps", [])
    check("Has 2 steps", len(steps) == 2, f"got {len(steps)}")

    if len(steps) >= 2:
        # Verify PKCE code_verifier in the request
        req_body = get_step_request(result, 1)
        check("Request has code_verifier", "code_verifier" in req_body)
        check("Request has client_secret (confidential + PKCE)", "client_secret" in req_body)

        # Check response for errors
        resp = get_step_response(result, 1)
        if "error" in resp:
            print(f"  ⚠ Token exchange error: {resp.get('error')}: {resp.get('error_description', '')[:150]}")

        p = get_token_payload(result, 1)
        check("Access token aud is API A",
              p.get("aud") == API_A_APP_ID,
              f"aud={p.get('aud')}")
        check("Access token ver is 2.0", p.get("ver") == "2.0", f"ver={p.get('ver')}")


def test_obo_redirect():
    """Self-contained OBO flow via browser redirect — full 6-step chain."""
    section("OBO Chain (self-contained, sign-in required)")
    scope = f"api://{API_B_APP_ID}/.default"
    url = f"{BASE}/auth/login?flow_type=obo&target_scope={urllib.parse.quote(scope)}"
    print(f"  → Opening browser: OBO chain")
    open_browser(url)

    latest = wait_for_new_callback("obo")
    result = latest.get("result", {})
    if not result:
        check("Callback succeeded", False, latest.get("error", "empty result"))
        return
    flow = latest["flow_type"]

    check("Flow type is obo", flow == "obo", f"got {flow}")
    steps = result.get("steps", [])
    check("Has 6 steps", len(steps) == 6, f"got {len(steps)}: {[s.get('label','?') for s in steps]}")

    if len(steps) >= 1:
        check("Step 1 — Authorize Redirect", "Authorize" in steps[0].get("label", ""))

    if len(steps) >= 2:
        check("Step 2 — Token Exchange", "Token Exchange" in steps[1].get("label", ""))
        p = get_token_payload(result, 1)
        check("Step 2 — aud is API A", p.get("aud") == API_A_APP_ID, f"aud={p.get('aud')}")

    if len(steps) >= 3:
        check("Step 3 — Call API A", "Call API A" in steps[2].get("label", ""))
        api_a_status = steps[2].get("response", {}).get("status", 0)
        check("Step 3 — API A 200", api_a_status == 200, f"status={api_a_status}")

    if len(steps) >= 4:
        check("Step 4 — OBO Token Exchange", "OBO" in steps[3].get("label", ""))
        resp = get_step_response(result, 3)
        check("Step 4 — no error", "error" not in resp)

    if len(steps) >= 5:
        p = get_token_payload(result, 4)
        check("Step 5 — aud switched to API B", p.get("aud") == API_B_APP_ID, f"aud={p.get('aud')}")

    if len(steps) >= 6:
        api_b_status = steps[5].get("response", {}).get("status", 0)
        check("Step 6 — API B 200", api_b_status == 200, f"status={api_b_status}")


def test_agent_id_obo_redirect():
    """Self-contained Agent ID OBO flow via browser redirect — 4-step chain."""
    section("Agent ID OBO (self-contained, sign-in required)")
    if not AGENT_BLUEPRINT_APP_ID:
        print("  ⊘ Skipped (Agent ID not configured)")
        return

    scope = "https://graph.microsoft.com/.default"
    url = f"{BASE}/auth/login?flow_type=agent_id_obo&target_scope={urllib.parse.quote(scope)}"
    print(f"  → Opening browser: Agent ID OBO")
    open_browser(url)

    latest = wait_for_new_callback("agent_id_obo")
    result = latest.get("result", {})
    if not result:
        check("Callback succeeded", False, latest.get("error", "empty result"))
        return
    flow = latest["flow_type"]

    check("Flow type is agent_id_obo", flow == "agent_id_obo", f"got {flow}")
    steps = result.get("steps", [])
    check("Has 4 steps", len(steps) == 4, f"got {len(steps)}: {[s.get('label','?') for s in steps]}")

    if len(steps) >= 1:
        check("Step 1 — Authorize Redirect", "Authorize" in steps[0].get("label", ""))

    if len(steps) >= 2:
        check("Step 2 — Token Exchange", "Token Exchange" in steps[1].get("label", ""))
        p = get_token_payload(result, 1)
        check("Step 2 — aud is Blueprint",
              p.get("aud") == AGENT_BLUEPRINT_APP_ID,
              f"aud={p.get('aud')}")

    if len(steps) >= 3:
        check("Step 3 — Parent Token (Blueprint)", "Parent" in steps[2].get("label", ""))
        p = get_token_payload(result, 2)
        check("Step 3 — parent aud is AzureADTokenExchange",
              p.get("aud") == "fb60f99c-7a34-4190-8149-302f77469936",
              f"aud={p.get('aud')}")

    if len(steps) >= 4:
        check("Step 4 — OBO Exchange (Agent)", "OBO" in steps[3].get("label", ""))
        resp = get_step_response(result, 3)
        if "error" in resp:
            print(f"  ⚠ OBO error: {resp.get('error')}: {resp.get('error_description', '')[:200]}")
        check("Step 4 — no error", "error" not in resp, f"error={resp.get('error', 'N/A')}")
        p = get_token_payload(result, 3)
        if p:
            check("Step 4 — aud is Graph",
                  p.get("aud") == "https://graph.microsoft.com",
                  f"aud={p.get('aud')}")


def test_agent_id_obo_via_api(user_token: str):
    """Test Agent ID OBO via /api/execute with an explicit user token."""
    section("Agent ID OBO via API (using stored token)")
    if not AGENT_BLUEPRINT_APP_ID:
        print("  ⊘ Skipped (Agent ID not configured)")
        return

    data = execute({
        "flow_type": "agent_id_obo",
        "scope": "https://graph.microsoft.com/.default",
        "user_token": user_token,
    })

    if "error" in data:
        check("No error", False, data["error"])
        return

    result = data.get("result", {})
    steps = result.get("steps", [])
    check("Has 3 steps", len(steps) == 3, f"got {len(steps)}: {[s.get('label','?') for s in steps]}")

    if len(steps) >= 2:
        p = get_token_payload(result, 1)
        check("Parent token aud is AzureADTokenExchange",
              p.get("aud") == "fb60f99c-7a34-4190-8149-302f77469936",
              f"aud={p.get('aud')}")

    if len(steps) >= 3:
        resp = get_step_response(result, 2)
        check("OBO exchange — no error", "error" not in resp, f"error={resp.get('error', 'N/A')}")


# ══════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════

def main():
    global _pass, _fail
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-pause", action="store_true",
                        help="Skip interactive Enter prompts between tests")
    args = parser.parse_args()

    def pause(msg: str):
        if args.no_pause:
            print(f"\n  {msg} (auto-continuing)")
            time.sleep(1)  # brief pause for SSO to propagate
        else:
            input(f"\n  {msg}")

    print("╔══════════════════════════════════════════════════════════╗")
    print("║        auth-viewer — End-to-End Flow Test Suite         ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # Verify servers
    print("\nChecking servers...")
    for name, url in [("Main :8000", f"{BASE}/"), ("API A :8001", "http://localhost:8001/health"), ("API B :8002", "http://localhost:8002/health")]:
        try:
            r = httpx.get(url, timeout=5)
            print(f"  ✓ {name} — {r.status_code}")
        except Exception as e:
            print(f"  ✗ {name} — {e}")
            print("\nPlease start all servers first (scripts/run_all.ps1)")
            sys.exit(1)

    # Phase 1
    test_client_credentials()
    test_agent_id_autonomous()
    test_device_code_start()

    p1_pass, p1_fail = _pass, _fail
    print(f"\n  Phase 1 complete: {p1_pass} passed, {p1_fail} failed")

    # Phase 2 — interactive
    print("\n" + "─" * 60)
    print("  Phase 2: Interactive flows — browser sign-in(s) required")
    print("  Your browser will open. Complete sign-in when prompted.")
    print("  (Entra SSO may auto-complete after the first one.)")
    print("─" * 60)
    pause("Press Enter to start interactive tests...")

    # Auth Code → verify the original bug is fixed
    raw_tokens = test_auth_code()
    user_token = raw_tokens.get("access_token", "")
    refresh_token = raw_tokens.get("refresh_token", "")

    # OBO using the Auth Code token (tests backend OBO logic)
    if user_token:
        test_obo_via_api(user_token)
    else:
        section("OBO via API")
        check("Skipped — no user token from Auth Code", False)

    # Refresh token
    if refresh_token:
        test_refresh(refresh_token)
    else:
        section("Refresh Token")
        check("Skipped — no refresh token from Auth Code", False)

    # Auth Code PKCE
    pause("Press Enter to test Auth Code + PKCE...")
    test_auth_code_pkce()

    # Self-contained OBO chain (browser redirect)
    pause("Press Enter to test OBO redirect chain...")
    test_obo_redirect()

    # Self-contained Agent ID OBO chain (browser redirect)
    pause("Press Enter to test Agent ID OBO redirect chain...")
    test_agent_id_obo_redirect()

    # Summary
    print(f"\n{'═' * 60}")
    print(f"  RESULTS: {_pass} passed, {_fail} failed  ({_pass + _fail} total)")
    print(f"{'═' * 60}")

    if _fail:
        print("\n  ⚠ Some tests failed. Review output above.")
        sys.exit(1)
    else:
        print("\n  All tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
