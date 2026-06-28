"""Rough token-cost estimation for the per-lead / per-run cost printouts.

Prices are public list prices in USD per 1M tokens and are ESTIMATES — they drift over
time and don't reflect any negotiated/discounted rate. Edit `_RATES` if they're stale. The
cost line is labelled `~$` to signal it's an estimate, not a billed amount.

Usage dict shape (filled by the backend): input_tokens, output_tokens, cache_read,
cache_write. Cache writes bill at 1.25x input, cache reads at 0.1x input (Anthropic).
"""
from __future__ import annotations

# model-family substring -> (input, output, cache_write, cache_read) USD per 1M tokens.
_RATES = {
    "opus":   (15.0, 75.0, 18.75, 1.50),
    "haiku":  (1.0,  5.0,  1.25,  0.10),
    "sonnet": (3.0,  15.0, 3.75,  0.30),
}
_DEFAULT = _RATES["sonnet"]

_KEYS = ("input_tokens", "output_tokens", "cache_read", "cache_write")


def _rate(model: str):
    m = (model or "").lower()
    for fam, rate in _RATES.items():
        if fam in m:
            return rate
    return _DEFAULT


def blank() -> dict:
    return {k: 0 for k in _KEYS}


def accumulate(into: dict, u: dict | None) -> dict:
    """Add one call's usage into a running total (in place); tolerates empty/partial dicts."""
    for k in _KEYS:
        into[k] = into.get(k, 0) + ((u or {}).get(k, 0) or 0)
    return into


def cost(model: str, u: dict) -> float:
    i, o, cw, cr = _rate(model)
    return (u.get("input_tokens", 0) * i + u.get("output_tokens", 0) * o
            + u.get("cache_write", 0) * cw + u.get("cache_read", 0) * cr) / 1_000_000


def _money(c: float) -> str:
    return f"${c:.2f}" if c >= 1 else f"${c:.4f}"


def summary(model: str, u: dict) -> str:
    """One-line tokens + estimated cost, e.g.
    '3,450 in / 1,200 out · cache 18,900 r / 2,100 w · ~$0.0123'."""
    return (f"{u.get('input_tokens', 0):,} in / {u.get('output_tokens', 0):,} out · "
            f"cache {u.get('cache_read', 0):,} r / {u.get('cache_write', 0):,} w · "
            f"~{_money(cost(model, u))}")
