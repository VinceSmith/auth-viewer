"""Unit tests for silent-token diagram shift logic.

When a delegated flow uses silent token acquisition (refresh_token grant)
instead of the interactive authorize → code → token path, the sequence
diagram should:
  - Show "Token Exchange (refresh_token)" as the first step (not /authorize)
  - NOT show the /authorize redirect
  - Have the Silent Token Acquisition pill aligned to diagram step 0

_apply_silent_diagram_shift() implements this by:
  1. Finding the "Silent Token Acquisition" step
  2. Setting its diagram_index to 0 (was -1)
  3. Decrementing all other diagram_index >= 0 values by 1
  4. Returning True if the shift was applied

These tests must fail before implementation and pass after.
"""

import pytest


# ---------------------------------------------------------------------------
# Import the function under test (will fail until implemented)
# ---------------------------------------------------------------------------

from app.main import _apply_silent_diagram_shift
from app.diagrams import DIAGRAMS


# ---------------------------------------------------------------------------
# _apply_silent_diagram_shift — unit tests
# ---------------------------------------------------------------------------

class TestApplySilentDiagramShift:
    """The helper that rewrites diagram_index values for the silent path."""

    def _make_step(self, label: str, diagram_index: int) -> dict:
        return {"label": label, "diagram_index": diagram_index, "description": "", "tokens": {}, "highlights": {}}

    def test_returns_false_when_no_silent_step(self):
        steps = [
            self._make_step("Token Cache Hit", -1),
            self._make_step("Parent Token", 2),
        ]
        result = _apply_silent_diagram_shift(steps)
        assert result is False

    def test_returns_true_when_silent_step_present(self):
        steps = [
            self._make_step("Silent Token Acquisition", -1),
            self._make_step("Parent Token", 2),
        ]
        assert _apply_silent_diagram_shift(steps) is True

    def test_silent_step_diagram_index_becomes_0(self):
        steps = [
            self._make_step("Silent Token Acquisition", -1),
            self._make_step("Parent Token", 2),
        ]
        _apply_silent_diagram_shift(steps)
        assert steps[0]["diagram_index"] == 0

    def test_positive_diagram_indexes_shift_down_by_1(self):
        steps = [
            self._make_step("Silent Token Acquisition", -1),
            self._make_step("Parent Token", 2),
            self._make_step("OBO Exchange", 3),
            self._make_step("Call API A", 4),
            self._make_step("OBO Exchange (API A)", 5),
            self._make_step("Call API B", 6),
        ]
        _apply_silent_diagram_shift(steps)
        assert steps[1]["diagram_index"] == 1
        assert steps[2]["diagram_index"] == 2
        assert steps[3]["diagram_index"] == 3
        assert steps[4]["diagram_index"] == 4
        assert steps[5]["diagram_index"] == 5

    def test_other_negative_1_steps_stay_at_minus_1(self):
        """Token Cache Hit, OIDC Discovery etc. should not be affected."""
        steps = [
            self._make_step("OIDC Discovery", -1),
            self._make_step("Silent Token Acquisition", -1),
            self._make_step("Token Cache Hit", -1),
            self._make_step("Parent Token", 2),
        ]
        _apply_silent_diagram_shift(steps)
        assert steps[0]["diagram_index"] == -1  # OIDC Discovery: unchanged
        assert steps[2]["diagram_index"] == -1  # Token Cache Hit: unchanged

    def test_steps_without_diagram_index_are_ignored(self):
        """Steps that never received diagram_index should not crash."""
        steps = [
            {"label": "Silent Token Acquisition", "description": "", "tokens": {}, "highlights": {}},
            {"label": "Parent Token", "diagram_index": 2, "description": "", "tokens": {}, "highlights": {}},
        ]
        # Should not raise
        result = _apply_silent_diagram_shift(steps)
        assert result is True
        assert steps[1]["diagram_index"] == 1

    def test_empty_steps_returns_false(self):
        assert _apply_silent_diagram_shift([]) is False

    def test_only_silent_step_no_downstream(self):
        """Single-step silent path — no downstream to shift."""
        steps = [self._make_step("Silent Token Acquisition", -1)]
        result = _apply_silent_diagram_shift(steps)
        assert result is True
        assert steps[0]["diagram_index"] == 0


# ---------------------------------------------------------------------------
# Silent diagram content — the diagram variants must exist and be correct
# ---------------------------------------------------------------------------

class TestSilentDiagramContent:
    """The _silent diagram variants must exist in DIAGRAMS and show refresh_token."""

    @pytest.mark.parametrize("key", ["auth_code_silent", "obo_silent", "agent_id_obo_silent"])
    def test_silent_diagram_exists(self, key):
        assert key in DIAGRAMS, f"DIAGRAMS missing '{key}'"

    @pytest.mark.parametrize("key", ["auth_code_silent", "obo_silent", "agent_id_obo_silent"])
    def test_silent_diagram_mentions_refresh_token(self, key):
        assert "refresh_token" in DIAGRAMS[key], f"'{key}' diagram should show refresh_token grant"

    @pytest.mark.parametrize("key", ["auth_code_silent", "obo_silent", "agent_id_obo_silent"])
    def test_silent_diagram_has_no_authorize_redirect(self, key):
        diag = DIAGRAMS[key]
        assert "GET /authorize" not in diag, f"'{key}' should not show GET /authorize"
        assert "Redirect to /authorize" not in diag, f"'{key}' should not show /authorize redirect"

    def test_auth_code_silent_step_count(self):
        """auth_code_silent: Token Exchange (refresh), Call Resource — 2 steps."""
        diag = DIAGRAMS["auth_code_silent"]
        assert diag.count("Note right of") == 2

    def test_obo_silent_step_count(self):
        """obo_silent: Token Exchange (refresh), Call API A, OBO Exchange, Call API B — 4 steps."""
        diag = DIAGRAMS["obo_silent"]
        assert diag.count("Note right of") == 4

    def test_agent_id_obo_silent_step_count(self):
        """agent_id_obo_silent: Token Exchange (refresh), Parent Token, Agent OBO,
        Call API A, OBO Exchange, Call API B — 6 steps."""
        diag = DIAGRAMS["agent_id_obo_silent"]
        assert diag.count("Note right of") == 6

    def test_obo_silent_first_rect_is_step_0_color(self):
        """The first rect in the silent diagram should use the S0 color (step 0)."""
        from app.diagrams import _rgb
        s0 = _rgb(0)
        diag = DIAGRAMS["obo_silent"]
        # The first `rect` in the diagram should use _S0 fill
        first_rect_idx = diag.index("rect ")
        assert s0 in diag[first_rect_idx:first_rect_idx + 80]

    def test_agent_id_obo_silent_first_rect_is_step_0_color(self):
        from app.diagrams import _rgb
        s0 = _rgb(0)
        diag = DIAGRAMS["agent_id_obo_silent"]
        first_rect_idx = diag.index("rect ")
        assert s0 in diag[first_rect_idx:first_rect_idx + 80]
