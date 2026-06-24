"""LLMClient: routes each role to its configured provider + model.

Backends are imported lazily, so users only need the SDK for the provider(s) they
actually use (anthropic / openai / google-genai).
"""
from __future__ import annotations

from .base import LLMResponse


def _make_backend(provider: str):
    p = provider.lower()
    if p == "anthropic":
        from .backends.anthropic_backend import AnthropicBackend
        return AnthropicBackend()
    if p == "openai":
        from .backends.openai_backend import OpenAIBackend
        return OpenAIBackend()
    if p in ("gemini", "google"):
        from .backends.gemini_backend import GeminiBackend
        return GeminiBackend()
    raise ValueError(f"unknown LLM provider: {provider!r} (use anthropic | openai | gemini)")


def _normalize_roles(models: dict) -> dict:
    """Accept either {role: {provider, model}} or {role: 'model-id'} (assumes anthropic)."""
    out = {}
    for role, spec in models.items():
        if isinstance(spec, dict):
            out[role] = {"provider": spec.get("provider", "anthropic"),
                         "model": spec["model"], "effort": spec.get("effort")}
        else:
            out[role] = {"provider": "anthropic", "model": spec, "effort": None}
    return out


class LLMClient:
    def __init__(self, models: dict, effort: str = "high", max_tokens: int = 16000):
        self._roles = _normalize_roles(models)
        self._effort = effort
        self._max_tokens = max_tokens
        self._backends: dict[str, object] = {}

    def _backend(self, provider: str):
        if provider not in self._backends:
            self._backends[provider] = _make_backend(provider)
        return self._backends[provider]

    def model_for(self, role: str) -> str:
        return self._roles[role]["model"]

    def provider_for(self, role: str) -> str:
        return self._roles[role]["provider"]

    def complete(self, role: str, system: str, messages: list, tools: list | None = None) -> LLMResponse:
        spec = self._roles[role]
        backend = self._backend(spec["provider"])
        effort = spec.get("effort") or self._effort
        return backend.complete(spec["model"], system, messages, tools, effort, self._max_tokens)
