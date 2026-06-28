"""Provider-neutral LLM types.

The agent loop speaks one neutral shape; each backend converts to/from its own wire
format. Because a given role uses one provider for its whole conversation, a backend
only ever sees its own native assistant turns plus neutral user turns — so we never
have to translate one provider's assistant turn into another's.

Neutral history element shapes:
- native assistant turn: whatever a backend returned as `assistant_turn` (opaque to
  the loop; the same backend consumes it next round).
- neutral user turn: {"_neutral": True, "role": "user", "content": <str | [blocks]>}
  where a block is {"type": "text", "text": ...} or
  {"type": "tool_result", "tool_use_id": ..., "content": str, "is_error": bool}.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[ToolCall]
    assistant_turn: object          # native turn to append to history (opaque)
    stop_reason: str                # "tool_use" | "end_turn"
    # Token usage for this one call (for per-lead / per-run cost printouts). Keys:
    # input_tokens, output_tokens, cache_read, cache_write. Empty if the backend can't report.
    usage: dict = field(default_factory=dict)


def neutral_user(content) -> dict:
    """Wrap a user turn (a string, or a list of neutral blocks) for the history."""
    return {"_neutral": True, "role": "user", "content": content}


def is_neutral(turn) -> bool:
    return isinstance(turn, dict) and turn.get("_neutral") is True
