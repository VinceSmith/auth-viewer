"""Shared TypedDicts for the step-through visualizer data contract.

These types define the exact shape exchanged between flows.py / token_utils.py
and the frontend JavaScript.  Annotating return types with these lets a type
checker (pyright, mypy) catch key-name regressions at dev time instead of at
runtime.
"""
from __future__ import annotations

from typing import NotRequired, TypedDict


class RequestInfo(TypedDict):
    method: str
    url: str
    headers: dict
    body: dict | str


class ResponseInfo(TypedDict):
    status: int
    headers: dict
    body: dict


class TokenInfo(TypedDict):
    raw: str
    header: NotRequired[dict]
    payload: NotRequired[dict]
    note: NotRequired[str]


class StepDict(TypedDict):
    """A single step in the step-through visualizer.

    Every step returned by flows.py must conform to this shape.
    The frontend app.js accesses *all* of these keys by name.
    """
    label: str
    description: str
    request: NotRequired[RequestInfo | None]
    response: NotRequired[ResponseInfo | None]
    tokens: dict  # str → TokenInfo
    highlights: dict  # guid → {"label": str, "role": str}
    authorize_url: NotRequired[str]


class TokenResponse(TypedDict):
    """Return shape of format_token_response() and _post_token_endpoint()."""
    request: RequestInfo
    response: ResponseInfo
    tokens: dict  # str → TokenInfo


class JwtDecoded(TypedDict):
    """Return shape of decode_jwt()."""
    header: dict
    payload: dict
    error: NotRequired[str]
