"""Unit tests for token-path diagram shift logic.

When a delegated flow skips the interactive authorize → code → token path
because a token was already available (either cached or silently acquired),
the sequence diagram should reflect what actually happened:

  "Silent Token Acquisition"  → _silent diagram (Token Exchange via refresh_token)
  "Token Cache Hit"           → _cached diagram (starts at first real flow step)

_apply_token_diagram_shift() implements this by:
  1. Detecting "Silent Token Acquisition" or "Token Cache Hit" in the steps
  2. Shifting diagram_index values so the first real step → 0
  3. Returning the variant suffix ("_silent" or "_cached") or "" if no change

These tests must fail before implementation and pass after.
"""

import pytest


# ---------------------------------------------------------------------------
# Import the function under test
# ---------------------------------------------------------------------------

from app.main import _apply_token_diagram_shift
from app.diagrams import DIAGRAMS


# ---------------------------------------------------------------------------
# _apply_token_diagram_shift — unit tests
# ---------------------------------------------------------------------------

class TestApplyTokenDiagramShift:
    """The helper that rewrites diagram_index values for non-interactive paths."""

    def _make_step(self, label: str, diagram_index: int) -> dict:
        return {"label": label, "diagram_index": diagram_index, "description": "", "tokens": {}, "highlights": {}}

    # --- No-op cases ---

    def test_returns_empty_string_when_no_special_step(self):
        steps = [
            self._make_step("Parent Token", 2),
            self._make_step("OBO Exchange", 3),
        ]
        assert _apply_token_diagram_shift(steps) == ""

    def test_returns_empty_string_for_empty_steps(self):
        assert _apply_token_diagram_shift([]) == ""

    def test_does_not_mutate_steps_when_no_special_step(self):
        steps = [self._make_step("Parent Token", 2)]
        _apply_token_diagram_shift(steps)
        assert steps[0]["diagram_index"] == 2

    # --- Silent Token Acquisition path ---

    def test_silent_returns_silent_suffix(self):
        steps = [
            self._make_step("Silent Token Acquisition", -1),
            self._make_step("Parent Token", 2),
        ]
        assert _apply_token_diagram_shift(steps) == "_silent"

    def test_silent_step_becomes_diagram_index_0(self):
        steps = [
            self._make_step("Silent Token Acquisition", -1),
            self._make_step("Parent Token", 2),
        ]
        _apply_token_diagram_shift(steps)
        assert steps[0]["diagram_index"] == 0

    def test_silent_downstream_steps_shift_by_min_minus_1(self):
        """With silent: min_positive=2 → shift=1, so Parent Token goes 2→1."""
        steps = [
            self._make_step("Silent Token Acquisition", -1),
            self._make_step("Parent Token", 2),
            self._make_step("OBO Exchange", 3),
            self._make_step("Call API A", 4),
        ]
        _apply_token_diagram_shift(steps)
        assert steps[1]["diagram_index"] == 1
        assert steps[2]["diagram_index"] == 2
        assert steps[3]["diagram_index"] == 3

    def test_silent_other_minus_1_steps_unchanged(self):
        steps = [
            self._make_step("OIDC Discovery", -1),
            self._make_step("Silent Token Acquisition", -1),
            self._make_step("Token Cache Hit", -1),
            self._make_step("Parent Token", 2),
        ]
        _apply_token_diagram_shift(steps)
        assert steps[0]["diagram_index"] == -1
        assert steps[2]["diagram_index"] == -1

    # --- Token Cache Hit path ---

    def test_cache_hit_returns_cached_suffix(self):
        steps = [
            self._make_step("Token Cache Hit", -1),
            self._make_step("Parent Token", 2),
        ]
        assert _apply_token_diagram_shift(steps) == "_cached"

    def test_cache_hit_stays_at_minus_1(self):
        """Token Cache Hit is display-only; has no corresponding diagram rect."""
        steps = [
            self._make_step("Token Cache Hit", -1),
            self._make_step("Parent Token", 2),
        ]
        _apply_token_diagram_shift(steps)
        assert steps[0]["diagram_index"] == -1

    def test_cache_hit_downstream_steps_shift_to_start_at_0(self):
        """With cache hit: min_positive=2 → shift=2, Parent Token goes 2→0."""
        steps = [
            self._make_step("Token Cache Hit", -1),
            self._make_step("Parent Token", 2),
            self._make_step("OBO Exchange (Agent → API A)", 3),
            self._make_step("Call API A", 4),
            self._make_step("OBO Token Exchange", 5),
            self._make_step("Call API B", 6),
        ]
        _apply_token_diagram_shift(steps)
        assert steps[1]["diagram_index"] == 0
        assert steps[2]["diagram_index"] == 1
        assert steps[3]["diagram_index"] == 2
        assert steps[4]["diagram_index"] == 3
        assert steps[5]["diagram_index"] == 4

    def test_cache_hit_obo_flow_shift(self):
        """obo cache hit: Call API A=2, OBO Exchange=3, Call API B=4 → 0,1,2."""
        steps = [
            self._make_step("Token Cache Hit", -1),
            self._make_step("Call API A", 2),
            self._make_step("OBO Exchange", 3),
            self._make_step("Call API B", 4),
        ]
        _apply_token_diagram_shift(steps)
        assert steps[1]["diagram_index"] == 0
        assert steps[2]["diagram_index"] == 1
        assert steps[3]["diagram_index"] == 2

    def test_cache_hit_auth_code_flow_shift(self):
        """auth_code cache hit: Call Resource=2 → 0."""
        steps = [
            self._make_step("Token Cache Hit", -1),
            self._make_step("Call Resource", 2),
        ]
        _apply_token_diagram_shift(steps)
        assert steps[1]["diagram_index"] == 0

    def test_cache_hit_audience_mismatch_plus_silent_uses_silent(self):
        """Mismatch + Silent Token Acquisition → should use _silent, not _cached."""
        steps = [
            self._make_step("Token Audience Mismatch", -1),
            self._make_step("Silent Token Acquisition", -1),
            self._make_step("Parent Token", 2),
        ]
        result = _apply_token_diagram_shift(steps)
        assert result == "_silent"
        assert steps[1]["diagram_index"] == 0
        assert steps[2]["diagram_index"] == 1

    def test_steps_without_diagram_index_not_crashed(self):
        steps = [
            {"label": "Token Cache Hit", "description": "", "tokens": {}, "highlights": {}},
            {"label": "Parent Token", "diagram_index": 2, "description": "", "tokens": {}, "highlights": {}},
        ]
        result = _apply_token_diagram_shift(steps)
        assert result == "_cached"
        assert steps[1]["diagram_index"] == 0


# ---------------------------------------------------------------------------
# Cached diagram content
# ---------------------------------------------------------------------------

class TestCachedDiagramContent:
    """Cached diagram variants must exist and show only post-auth steps."""

    @pytest.mark.parametrize("key", ["auth_code_cached", "obo_cached", "agent_id_obo_cached"])
    def test_cached_diagram_exists(self, key):
        assert key in DIAGRAMS, f"DIAGRAMS missing '{key}'"

    @pytest.mark.parametrize("key", ["auth_code_cached", "obo_cached", "agent_id_obo_cached"])
    def test_cached_diagram_no_authorize(self, key):
        diag = DIAGRAMS[key]
        assert "GET /authorize" not in diag
        assert "Redirect to /authorize" not in diag

    @pytest.mark.parametrize("key", ["auth_code_cached", "obo_cached", "agent_id_obo_cached"])
    def test_cached_diagram_no_authorization_code_grant(self, key):
        diag = DIAGRAMS[key]
        assert "authorization_code" not in diag

    @pytest.mark.parametrize("key", ["auth_code_cached", "obo_cached", "agent_id_obo_cached"])
    def test_cached_diagram_no_refresh_token_grant(self, key):
        """Cached diagrams don't show a refresh_token exchange (that's the _silent variant)."""
        diag = DIAGRAMS[key]
        assert "refresh_token" not in diag

    def test_auth_code_cached_step_count(self):
        """auth_code_cached: just Call Resource — 1 step."""
        assert DIAGRAMS["auth_code_cached"].count("Note right of") == 1

    def test_obo_cached_step_count(self):
        """obo_cached: Call API A, OBO Exchange, Call API B — 3 steps."""
        assert DIAGRAMS["obo_cached"].count("Note right of") == 3

    def test_agent_id_obo_cached_step_count(self):
        """agent_id_obo_cached: Parent Token, Agent OBO, Call API A,
        OBO Exchange (API A→API B), Call API B — 5 steps."""
        assert DIAGRAMS["agent_id_obo_cached"].count("Note right of") == 5

    def test_cached_diagrams_first_rect_uses_s0_color(self):
        from app.diagrams import _rgb
        s0 = _rgb(0)
        for key in ["auth_code_cached", "obo_cached", "agent_id_obo_cached"]:
            diag = DIAGRAMS[key]
            first_rect = diag.index("rect ")
            assert s0 in diag[first_rect:first_rect + 80], f"{key}: first rect should use S0"


# ---------------------------------------------------------------------------
# Silent diagram content (retained from old test file, updated naming)
# ---------------------------------------------------------------------------

class TestSilentDiagramContent:
    """Silent diagram variants must exist and show refresh_token."""

    @pytest.mark.parametrize("key", ["auth_code_silent", "obo_silent", "agent_id_obo_silent"])
    def test_silent_diagram_exists(self, key):
        assert key in DIAGRAMS

    @pytest.mark.parametrize("key", ["auth_code_silent", "obo_silent", "agent_id_obo_silent"])
    def test_silent_diagram_has_refresh_token(self, key):
        assert "refresh_token" in DIAGRAMS[key]

    @pytest.mark.parametrize("key", ["auth_code_silent", "obo_silent", "agent_id_obo_silent"])
    def test_silent_diagram_no_authorize(self, key):
        assert "GET /authorize" not in DIAGRAMS[key]

    def test_auth_code_silent_step_count(self):
        assert DIAGRAMS["auth_code_silent"].count("Note right of") == 2

    def test_obo_silent_step_count(self):
        assert DIAGRAMS["obo_silent"].count("Note right of") == 4

    def test_agent_id_obo_silent_step_count(self):
        assert DIAGRAMS["agent_id_obo_silent"].count("Note right of") == 6
